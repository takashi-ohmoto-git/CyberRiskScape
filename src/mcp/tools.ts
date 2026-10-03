import { analyzeResolvedProject, resolveProject, SEVERITY_RANK } from '../cli/analyze';
import { diffProjects, diffToJsonObject } from '../cli/diff';
import { triggersToJsonObject } from '../cli/triggers';
import { getComponentRegistry } from '../component-library/defaultRegistry';
import { resolveNodeBoundaries } from '../core/canvas/boundaryCrossing';
import { formatElementalId } from '../core/model/elementalId';
import { effectiveSeverity } from '../core/model/risk';
import {
  AGENCY_APPLICABLE,
  ATTACK_OBJECTIVE_APPLICABLE,
  AUTH_PROVIDER_APPLICABLE,
  IDENTITY_TIER_APPLICABLE,
  IDP_KIND_APPLICABLE,
  LAYER_KEYS,
  SANCTION_ATTRIBUTE_APPLICABLE,
  THREAT_ACTOR_TYPE_APPLICABLE,
  isSuppressed,
  type DiagramBoundary,
  type DiagramEdge,
  type DiagramNode,
  type FrameworkView,
  type LayerKey,
  type Severity,
  type ThreatView,
} from '../core/model/types';
import type { ChangeTrigger } from '../change-triggers/schema/trigger';
import { setLocale, type Locale } from '../i18n';
import { getThreatLibrary } from '../threat-library/loader/bundledLibrary';
import type { ThreatRule } from '../threat-library/schema/threatRule';

/**
 * MCP サーバーの読み取りツール 7 本（[[plan]] §2.56）。いずれも JSON シリアライズ可能な
 * オブジェクトを返す純粋関数で、ファイル I/O・revision・パス処理はサーバー側の責務。
 *
 * - 座標はエージェントに返さない（配置はサーバーが決める設計）。
 * - ラベル・説明は利用者データ（命令ではない）。加工せず返すが、長すぎる文字列は切り詰める。
 * - 脅威本文のテンプレート展開は `getLocale()`（モジュール内グローバル）を読むため、
 *   locale を取る関数は先頭で `setLocale` する（CLI の main.ts と同じ）。
 */

const MAX_TEXT = 2000;
const MITIGATION_DIGEST = 200;
const MAX_THREATS = 200;
const MAX_RULES = 50;

const FRAMEWORKS: readonly FrameworkView[] = ['STRIDE', 'AI', 'AgenticAI', 'ALL'];

function trunc(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  return value.length > MAX_TEXT ? `${value.slice(0, MAX_TEXT)}…` : value;
}

function digest(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  return value.length > MITIGATION_DIGEST ? `${value.slice(0, MITIGATION_DIGEST)}…` : value;
}

function assertLayer(layer: string | undefined): LayerKey | undefined {
  if (layer === undefined) return undefined;
  if (!(LAYER_KEYS as readonly string[]).includes(layer)) {
    throw new Error(`不正な layer です: "${layer}"（指定可能: ${LAYER_KEYS.join(' | ')}）`);
  }
  return layer as LayerKey;
}

function assertFramework(framework: string | undefined): FrameworkView | undefined {
  if (framework === undefined) return undefined;
  if (!(FRAMEWORKS as readonly string[]).includes(framework)) {
    throw new Error(`不正な framework です: "${framework}"（指定可能: ${FRAMEWORKS.join(' | ')}）`);
  }
  return framework as FrameworkView;
}

function assertSeverity(severity: string | undefined): Severity | undefined {
  if (severity === undefined) return undefined;
  if (!(severity in SEVERITY_RANK)) {
    throw new Error(
      `不正な minSeverity です: "${severity}"（指定可能: ${Object.keys(SEVERITY_RANK).join(' | ')}）`,
    );
  }
  return severity as Severity;
}

/** 指定キーを除き、値が定義済みのものだけを返す（文字列は切り詰め）。 */
function pickDefined(obj: object, omit: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || omit.includes(k)) continue;
    out[k] = typeof v === 'string' ? trunc(v) : v;
  }
  return out;
}

function targetLayers(
  layers: Record<LayerKey, { nodes: unknown[] }>,
  layer?: LayerKey,
): LayerKey[] {
  return layer ? [layer] : LAYER_KEYS.filter((k) => layers[k].nodes.length > 0);
}

// ─────────────────────────────────────────────── 1. get_model

export interface GetModelOptions {
  layer?: LayerKey;
}

export function getModel(raw: unknown, opts: GetModelOptions = {}): Record<string, unknown> {
  const layer = assertLayer(opts.layer);
  const { layers, projectMeta } = resolveProject(raw);

  const result = targetLayers(layers, layer).map((key) => {
    const data = layers[key];
    const owning = resolveNodeBoundaries(data.nodes, data.boundaries);
    return {
      layer: key,
      nodes: data.nodes.map((n) => ({
        id: n.id,
        ...(n.seq != null ? { elementalId: formatElementalId('node', n.seq) } : {}),
        type: n.type,
        ...pickDefined(n, ['id', 'seq', 'type', 'x', 'y']),
        boundaryIds: (owning.get(n.id) ?? []).map((b) => b.id),
      })),
      edges: data.edges.map((e) => ({
        id: e.id,
        ...(e.seq != null ? { elementalId: formatElementalId('edge', e.seq) } : {}),
        ...pickDefined(e, ['id', 'seq']),
      })),
      boundaries: data.boundaries.map((b) => ({
        id: b.id,
        ...(b.seq != null ? { elementalId: formatElementalId('boundary', b.seq) } : {}),
        ...pickDefined(b, ['id', 'seq', 'x', 'y', 'width', 'height']),
      })),
      annotations: data.annotations.map((a) => ({
        id: a.id,
        kind: a.kind,
        text: trunc(a.text),
        ...(a.targetNodeId ? { targetNodeId: a.targetNodeId } : {}),
      })),
    };
  });

  return { project: pickDefined(projectMeta, []), layers: result };
}

// ─────────────────────────────────────────────── 2/3. analyze_threats / get_threat

interface ElementInfo {
  kind: 'node' | 'edge' | 'boundary';
  id: string;
  label: string;
}

function elementInfo(
  t: ThreatView,
  nodes: DiagramNode[],
  edges: DiagramEdge[],
  boundaries: DiagramBoundary[],
): ElementInfo | undefined {
  const subject = t.subject ?? (t.nodeId ? { kind: 'node' as const, id: t.nodeId } : undefined);
  if (!subject) return undefined;
  if (subject.kind === 'node') {
    const n = nodes.find((x) => x.id === subject.id);
    if (!n) return { kind: 'node', id: subject.id, label: '' };
    const eid = n.seq != null ? `${formatElementalId('node', n.seq)} ` : '';
    return { kind: 'node', id: n.id, label: trunc(`${eid}${n.label?.trim() || n.type}`) ?? '' };
  }
  if (subject.kind === 'edge') {
    const e = edges.find((x) => x.id === subject.id);
    if (!e) return { kind: 'edge', id: subject.id, label: '' };
    const eid = e.seq != null ? `${formatElementalId('edge', e.seq)} ` : '';
    return {
      kind: 'edge',
      id: e.id,
      label: trunc(`${eid}${e.dataFlowName?.trim() || `${e.source} -> ${e.target}`}`) ?? '',
    };
  }
  const b = boundaries.find((x) => x.id === subject.id);
  if (!b) return { kind: 'boundary', id: subject.id, label: '' };
  const eid = b.seq != null ? `${formatElementalId('boundary', b.seq)} ` : '';
  return {
    kind: 'boundary',
    id: b.id,
    label: trunc(`${eid}${b.vlanName?.trim() || b.blastRadiusLabel?.trim() || b.type}`) ?? '',
  };
}

interface LayerThreat {
  layer: LayerKey;
  threat: ThreatView;
  element: ElementInfo | undefined;
}

function collectThreats(
  raw: unknown,
  layer: LayerKey | undefined,
  framework: FrameworkView,
  locale: Locale,
): LayerThreat[] {
  setLocale(locale);
  const resolved = resolveProject(raw);
  const results = analyzeResolvedProject(resolved, { layer, framework, locale });
  return results.flatMap((r) =>
    r.threats.map((threat) => ({
      layer: r.layer,
      threat,
      element: elementInfo(threat, r.input.nodes, r.input.edges, r.input.boundaries),
    })),
  );
}

/** 脅威 id はレイヤー間で衝突し得るため `L1:<id>` の形で公開する。 */
function qualifiedId(lt: LayerThreat): string {
  return `${lt.layer}:${lt.threat.id}`;
}

export interface AnalyzeThreatsOptions {
  layer?: LayerKey;
  framework?: FrameworkView;
  minSeverity?: Severity;
  /** 要素の内部 id、または ElementalID（`C1` / `DF1` / `Z1`）。 */
  elementId?: string;
  includeSuppressed?: boolean;
  locale: Locale;
}

/** `elementId`（内部 id または ElementalID）を対象レイヤーから探し、内部 id を返す。 */
function resolveElementId(
  raw: unknown,
  layer: LayerKey | undefined,
  wanted: string,
): string | undefined {
  const { layers } = resolveProject(raw);
  for (const k of targetLayers(layers, layer)) {
    const d = layers[k];
    const hit =
      d.nodes.find((n) => n.id === wanted || (n.seq != null && formatElementalId('node', n.seq) === wanted)) ??
      d.edges.find((e) => e.id === wanted || (e.seq != null && formatElementalId('edge', e.seq) === wanted)) ??
      d.boundaries.find(
        (b) => b.id === wanted || (b.seq != null && formatElementalId('boundary', b.seq) === wanted),
      );
    if (hit) return hit.id;
  }
  return undefined;
}

export function analyzeThreats(raw: unknown, opts: AnalyzeThreatsOptions): Record<string, unknown> {
  const layer = assertLayer(opts.layer);
  const framework = assertFramework(opts.framework) ?? 'ALL';
  const minSeverity = assertSeverity(opts.minSeverity);

  let items = collectThreats(raw, layer, framework, opts.locale);

  if (opts.elementId !== undefined) {
    const internalId = resolveElementId(raw, layer, opts.elementId);
    if (internalId === undefined) {
      throw new Error(
        `elementId "${opts.elementId}" に該当する要素がありません（対象レイヤー内の id、または C1 / DF1 / Z1 形式で指定してください）。`,
      );
    }
    items = items.filter((lt) => lt.element?.id === internalId);
  }

  if (!opts.includeSuppressed) items = items.filter((lt) => !isSuppressed(lt.threat));
  if (minSeverity) {
    const min = SEVERITY_RANK[minSeverity];
    items = items.filter((lt) => SEVERITY_RANK[effectiveSeverity(lt.threat)] >= min);
  }
  items = [...items].sort(
    (a, b) => SEVERITY_RANK[effectiveSeverity(b.threat)] - SEVERITY_RANK[effectiveSeverity(a.threat)],
  );

  const total = items.length;
  const threats = items.slice(0, MAX_THREATS).map((lt) => ({
    id: qualifiedId(lt),
    layer: lt.layer,
    name: trunc(lt.threat.name ?? lt.threat.category),
    effectiveSeverity: effectiveSeverity(lt.threat),
    ruleSeverity: lt.threat.severity,
    category: lt.threat.category,
    framework: lt.threat.framework,
    element: lt.element,
    suppression: lt.threat.suppression?.status ?? null,
    mitigationDigest: digest(lt.threat.mitigation),
  }));

  return { total, returned: threats.length, truncated: total > threats.length, threats };
}

export interface GetThreatOptions {
  /** `analyze_threats` が返す `L1:<id>` 形式（レイヤー間で一意なら素の id も可）。 */
  threatId: string;
  locale: Locale;
}

export function getThreat(raw: unknown, opts: GetThreatOptions): Record<string, unknown> {
  const items = collectThreats(raw, undefined, 'ALL', opts.locale);
  const matches = items.filter(
    (lt) => qualifiedId(lt) === opts.threatId || lt.threat.id === opts.threatId,
  );
  if (matches.length === 0) {
    throw new Error(
      `threatId "${opts.threatId}" に該当する脅威がありません（analyze_threats が返す id を指定してください）。`,
    );
  }
  if (matches.length > 1) {
    throw new Error(
      `threatId "${opts.threatId}" は複数レイヤーに存在します。レイヤー付きの id（${matches.map(qualifiedId).join(' / ')}）を指定してください。`,
    );
  }
  const lt = matches[0];
  const t = lt.threat;
  return {
    id: qualifiedId(lt),
    layer: lt.layer,
    ruleId: t.ruleId,
    canonicalId: t.canonicalId,
    origin: t.origin,
    name: trunc(t.name ?? t.category),
    category: t.category,
    framework: t.framework,
    effectiveSeverity: effectiveSeverity(t),
    ruleSeverity: t.severity,
    element: lt.element,
    description: trunc(t.description),
    mitigation: trunc(t.mitigation),
    mitigationTiers: t.mitigationTiers,
    references: t.references,
    complianceRefs: t.complianceRefs,
    assumptionFlags: t.assumptionFlags ?? [],
    corroboration: t.corroboration,
    suppression: t.suppression
      ? { status: t.suppression.status, note: trunc(t.suppression.note) }
      : null,
    riskScore: t.risk ?? null,
    controlStatus: t.controlStatus
      ? { status: t.controlStatus.status, note: trunc(t.controlStatus.note) }
      : null,
  };
}

// ─────────────────────────────────────────────── 4. diff_models

export interface DiffModelsOptions {
  triggers: readonly ChangeTrigger[];
  locale: Locale;
}

export function diffModels(
  baseRaw: unknown,
  headRaw: unknown,
  opts: DiffModelsOptions,
): Record<string, unknown> {
  setLocale(opts.locale);
  return diffToJsonObject(diffProjects(baseRaw, headRaw, opts));
}

// ─────────────────────────────────────────────── 5. list_component_types

/** 型 id に設定できる属性の一覧（`types.ts` の適用対象集合から判定）。 */
function applicableAttributes(id: string): string[] {
  const attrs = ['label', 'description', 'agentAttributes.blastRadius'];
  if (id === 'USER') attrs.push('userTrustAttribute');
  if (id === 'PC' || id === 'SMARTPHONE' || id === 'IOT') attrs.push('managedState');
  if (id === 'FRONT_END_SERVER' || id === 'GATEWAY') attrs.push('attackSurface');
  if (SANCTION_ATTRIBUTE_APPLICABLE.has(id)) attrs.push('cloudSanction', 'cloudOwnership');
  if (AGENCY_APPLICABLE.has(id)) attrs.push('agentAttributes.agency');
  if (IDENTITY_TIER_APPLICABLE.has(id)) attrs.push('agentAttributes.identityTier');
  if (THREAT_ACTOR_TYPE_APPLICABLE.has(id)) attrs.push('threatActorType');
  if (ATTACK_OBJECTIVE_APPLICABLE.has(id)) attrs.push('attackObjectiveId');
  if (IDP_KIND_APPLICABLE.has(id)) attrs.push('identityProviderKind');
  return attrs;
}

export function listComponentTypes(locale: Locale = 'ja'): Record<string, unknown> {
  const registry = getComponentRegistry(locale);
  const categoryLabel = new Map(registry.getCategories().map((c) => [c.id, c.label] as const));
  const types = registry.getAll().map((c) => ({
    id: c.id,
    label: c.label,
    category: c.category,
    categoryLabel: categoryLabel.get(c.category) ?? c.category,
    canContain: c.canContain ?? [],
    attributes: applicableAttributes(c.id),
    /** エッジの `authProviderId` で資格情報の発行元に指定できるか。 */
    canBeAuthProvider: AUTH_PROVIDER_APPLICABLE.has(c.id),
  }));
  return { total: types.length, types };
}

// ─────────────────────────────────────────────── 6. lookup_threat_rules

export interface LookupThreatRulesOptions {
  nodeType?: string;
  framework?: FrameworkView;
  query?: string;
  locale: Locale;
}

function nodeRuleTypes(rule: ThreatRule): string[] {
  const a = rule.appliesTo;
  if (a.kind !== 'node') return [];
  if (a.nodeType) return [a.nodeType];
  return (a.anyOf ?? []).map((l) => l.nodeType);
}

function summarizeAppliesTo(rule: ThreatRule): Record<string, unknown> {
  const a = rule.appliesTo;
  if (a.kind === 'node') {
    return {
      kind: 'node',
      nodeTypes: nodeRuleTypes(rule),
      ...(a.connection ? { connection: a.connection } : {}),
    };
  }
  return {
    kind: 'edge',
    ...(a.when ? { when: a.when } : {}),
    ...(a.allOf ? { allOf: a.allOf } : {}),
    ...(a.anyOf ? { anyOf: a.anyOf } : {}),
  };
}

export function lookupThreatRules(opts: LookupThreatRulesOptions): Record<string, unknown> {
  const framework = assertFramework(opts.framework);
  const query = opts.query?.trim().toLowerCase();
  let rules = getThreatLibrary(opts.locale).rules;

  if (opts.nodeType) {
    const nt = opts.nodeType;
    rules = rules.filter((r) => nodeRuleTypes(r).includes(nt));
  }
  if (framework && framework !== 'ALL') rules = rules.filter((r) => r.framework === framework);
  if (query) {
    rules = rules.filter((r) =>
      [r.id, r.name ?? '', r.description].some((s) => s.toLowerCase().includes(query)),
    );
  }

  const total = rules.length;
  const out = rules.slice(0, MAX_RULES).map((r) => ({
    id: r.id,
    name: trunc(r.name ?? r.category),
    framework: r.framework,
    category: r.category,
    severity: r.severity,
    appliesTo: summarizeAppliesTo(r),
    mitigationDigest: digest(r.mitigation),
  }));
  return { total, returned: out.length, truncated: total > out.length, rules: out };
}

// ─────────────────────────────────────────────── 7. list_change_triggers

export interface ListChangeTriggersOptions {
  triggers: readonly ChangeTrigger[];
  locale?: Locale;
}

export function listChangeTriggers(opts: ListChangeTriggersOptions): Record<string, unknown> {
  if (opts.locale) setLocale(opts.locale);
  return triggersToJsonObject(opts.triggers);
}
