import { componentRegistry } from '../../component-library/defaultRegistry';
import {
  ATTACK_SURFACE_APPLICABLE,
  ATTACK_SURFACE_KEYS_BY_TYPE,
  type AttackSurfaceKey,
  type ComponentTypeId,
  type LayerKey,
  type PostureEnumKey,
} from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';
import { resourceLabel, type NormalizedProwlerFinding, type ProwlerResource } from './parseProwlerOcsf';
import {
  attackSurfaceKeyOf,
  betterValue,
  findProwlerMapping,
  worseValue,
  type FieldValue,
  type ProwlerMapping,
} from './prowlerMap';

/**
 * Prowler の検査結果を図のノードに載せる純粋関数（ファイル I/O なし）。
 *
 *   値の決定  : 1 つの資源の中では検査どうしで最も良い値、ノードでは資源どうしで最も悪い値（順序は prowlerMap.ts）
 *   上書きなし : ノードに既に値があり Prowler の値と違えば適用せず「食い違い」。未入力のときだけ埋める
 *   適用できない: ノードの型が持たない項目は適用せず報告
 *   突き合わせ : FAIL の検査の canonicalId を、検出済みの脅威と照合する
 */

/** 取り込み対象のノード 1 件分（プロジェクトの全レイヤーから集める）。 */
export interface ImportNodeRef {
  id: string;
  layer: LayerKey;
  seq?: number;
  type: ComponentTypeId;
  label?: string;
  posture?: object;
  attackSurface?: object;
}

/** 突き合わせ用の検出済み脅威 1 件分。 */
export interface ThreatRef {
  canonicalId: string;
  name: string;
  severity: string;
  /** 脅威の対象になっているノード id（エッジの脅威は両端）。 */
  nodeIds: string[];
}

export interface ApplyProwlerInput {
  nodes: readonly ImportNodeRef[];
  findings: readonly NormalizedProwlerFinding[];
  map: readonly ProwlerMapping[];
  /** `--map`：資源の uid または名前 → ノード ID（または C 番号）。 */
  nodeMap?: Readonly<Record<string, string>>;
  threats: readonly ThreatRef[];
}

/** 値の根拠 1 資源分。 */
export interface BasisEntry {
  resource: string;
  /** その資源で値を決めた検査（検査ごとの値）。 */
  checks: { checkId: string; value: FieldValue }[];
  /** その資源の値（検査どうしで最も良い値）。 */
  value: FieldValue;
}

interface FieldChange {
  nodeId: string;
  layer: LayerKey;
  node: string;
  field: string;
  basis: BasisEntry[];
}

export interface AppliedValue extends FieldChange {
  value: FieldValue;
}
export interface UnchangedValue extends FieldChange {
  value: FieldValue;
}
export interface ConflictValue extends FieldChange {
  current: FieldValue;
  prowler: FieldValue;
}
export interface NotApplicableValue extends FieldChange {
  type: ComponentTypeId;
  prowler: FieldValue;
}

export interface UnmatchedResource {
  resource: string;
  type?: string;
  service?: string;
  region?: string;
  /** none＝タグも対応表も無い／unknownNode＝指定されたノード ID が図に無い／ambiguous＝C 番号が複数レイヤーに該当。 */
  reason: 'none' | 'unknownNode' | 'ambiguous';
  /** 指定されたノード ID（reason が none 以外のとき）。 */
  ref?: string;
  checks: string[];
}

export interface CrossCheckHit {
  resource: string;
  node?: string;
  checkId: string;
}
export interface ConfirmedEntry {
  canonicalId: string;
  hits: CrossCheckHit[];
  threats: ThreatRef[];
}
export interface NotInModelEntry {
  canonicalId: string;
  hits: CrossCheckHit[];
}
export interface UnmappedCheck {
  checkId: string;
  severity?: string;
  title?: string;
  count: number;
}

export interface ProwlerImportResult {
  summary: {
    findings: number;
    mappedChecks: number;
    unknownChecks: number;
    manual: number;
    applied: number;
    unchanged: number;
    conflicts: number;
    notApplicable: number;
    unmatchedResources: number;
  };
  applied: AppliedValue[];
  unchanged: UnchangedValue[];
  conflicts: ConflictValue[];
  notApplicable: NotApplicableValue[];
  unmatchedResources: UnmatchedResource[];
  confirmed: ConfirmedEntry[];
  notInModel: NotInModelEntry[];
  /** FAIL だが canonicalId の対応が無い検査。 */
  unmappedChecks: UnmappedCheck[];
}

type NodeLookup = { kind: 'found'; node: ImportNodeRef } | { kind: 'unknown' } | { kind: 'ambiguous' };

function lookupNode(nodes: readonly ImportNodeRef[], ref: string): NodeLookup {
  const byId = nodes.find((n) => n.id === ref);
  if (byId) return { kind: 'found', node: byId };
  const m = /^C(\d+)$/.exec(ref);
  if (m) {
    const hits = nodes.filter((n) => n.seq === Number(m[1]));
    if (hits.length === 1) return { kind: 'found', node: hits[0] };
    if (hits.length > 1) return { kind: 'ambiguous' };
  }
  return { kind: 'unknown' };
}

function nodeLabel(n: ImportNodeRef): string {
  return `${n.seq != null ? formatElementalId('node', n.seq) : n.id} ${n.label?.trim() || n.type}`;
}

/** ノードの型がこの項目を持つか。運用状況は型の posture 宣言、攻撃面は適用型と型ごとの項目で決まる。 */
export function acceptsField(type: ComponentTypeId, field: string): boolean {
  const key = attackSurfaceKeyOf(field);
  if (key) {
    if (!ATTACK_SURFACE_APPLICABLE.has(type)) return false;
    return ATTACK_SURFACE_KEYS_BY_TYPE[type]?.includes(key as AttackSurfaceKey) ?? true;
  }
  return componentRegistry.acceptsPostureField(type, field as PostureEnumKey);
}

function currentValue(n: ImportNodeRef, field: string): FieldValue | undefined {
  const key = attackSurfaceKeyOf(field);
  const bag = (key ? n.attackSurface : n.posture) as Record<string, FieldValue | undefined> | undefined;
  return bag?.[key ?? field];
}

interface ResourceAcc {
  resource: string;
  checks: { checkId: string; value: FieldValue }[];
  value: FieldValue;
}

export function applyProwler(input: ApplyProwlerInput): ProwlerImportResult {
  const { nodes, map, nodeMap = {} } = input;
  const seenChecks = new Set<string>();
  const unknownChecks = new Set<string>();
  let manual = 0;

  // node id → field → 資源キー → 資源ごとの値（検査どうしで最も良い値）
  const acc = new Map<string, Map<string, Map<string, ResourceAcc>>>();
  const unmatched = new Map<string, UnmatchedResource>();
  const failHits: { canonicalId: string; hit: CrossCheckHit; nodeId?: string }[] = [];
  const unmappedFail = new Map<string, UnmappedCheck>();

  for (const f of input.findings) {
    const mapping = findProwlerMapping(map, f.checkId);
    if (!mapping) unknownChecks.add(f.checkId);
    else seenChecks.add(f.checkId);
    if (f.status === 'MANUAL') {
      manual += 1;
      continue;
    }
    if (f.status === 'FAIL' && !(mapping?.canonicalIds && mapping.canonicalIds.length > 0)) {
      const u = unmappedFail.get(f.checkId);
      if (u) u.count += 1;
      else unmappedFail.set(f.checkId, { checkId: f.checkId, severity: f.severity, title: f.title, count: 1 });
    }
    if (!mapping) continue;

    const value = mapping.set ? (f.status === 'PASS' ? mapping.set.pass : mapping.set.fail) : undefined;
    const resources: ProwlerResource[] = f.resources.length > 0 ? f.resources : [{}];
    for (const r of resources) {
      const label = resourceLabel(r);
      const ref = r.nodeTag ?? (r.uid ? nodeMap[r.uid] : undefined) ?? (r.name ? nodeMap[r.name] : undefined);
      const found: NodeLookup = ref ? lookupNode(nodes, ref) : { kind: 'unknown' };
      const node = found.kind === 'found' ? found.node : undefined;

      if (!node) {
        const key = `${label}|${ref ?? ''}`;
        const entry = unmatched.get(key) ?? {
          resource: label,
          type: r.type,
          service: r.service,
          region: r.region,
          reason: !ref ? 'none' : found.kind === 'ambiguous' ? 'ambiguous' : 'unknownNode',
          ref,
          checks: [],
        };
        if (!entry.checks.includes(f.checkId)) entry.checks.push(f.checkId);
        unmatched.set(key, entry);
      }

      if (f.status === 'FAIL') {
        for (const canonicalId of mapping.canonicalIds ?? []) {
          failHits.push({
            canonicalId,
            nodeId: node?.id,
            hit: { resource: label, node: node ? nodeLabel(node) : undefined, checkId: f.checkId },
          });
        }
      }

      if (!node || value === undefined || !mapping.set) continue;
      const fields = acc.get(node.id) ?? new Map<string, Map<string, ResourceAcc>>();
      acc.set(node.id, fields);
      const resources2 = fields.get(mapping.set.field) ?? new Map<string, ResourceAcc>();
      fields.set(mapping.set.field, resources2);
      const resKey = r.uid ?? r.name ?? '';
      const prev = resources2.get(resKey);
      if (prev) {
        prev.value = betterValue(mapping.set.field, prev.value, value);
        prev.checks.push({ checkId: f.checkId, value });
      } else {
        resources2.set(resKey, { resource: label, checks: [{ checkId: f.checkId, value }], value });
      }
    }
  }

  const applied: AppliedValue[] = [];
  const unchanged: UnchangedValue[] = [];
  const conflicts: ConflictValue[] = [];
  const notApplicable: NotApplicableValue[] = [];

  for (const [nodeId, fields] of acc) {
    const node = nodes.find((n) => n.id === nodeId);
    if (!node) continue;
    for (const [field, resources] of fields) {
      const basis: BasisEntry[] = [...resources.values()].map((r) => ({
        resource: r.resource,
        checks: r.checks,
        value: r.value,
      }));
      const value = basis.map((b) => b.value).reduce((a, b) => worseValue(field, a, b));
      const common = { nodeId, layer: node.layer, node: nodeLabel(node), field, basis };
      if (!acceptsField(node.type, field)) {
        notApplicable.push({ ...common, type: node.type, prowler: value });
        continue;
      }
      const current = currentValue(node, field);
      if (current === undefined) applied.push({ ...common, value });
      else if (current === value) unchanged.push({ ...common, value });
      else conflicts.push({ ...common, current, prowler: value });
    }
  }

  // 突き合わせ：FAIL の検査の canonicalId × 検出済みの脅威
  const confirmedMap = new Map<string, ConfirmedEntry>();
  const notInModelMap = new Map<string, NotInModelEntry>();
  const addHit = (hits: CrossCheckHit[], h: CrossCheckHit) => {
    if (!hits.some((x) => x.resource === h.resource && x.node === h.node && x.checkId === h.checkId)) hits.push(h);
  };
  for (const { canonicalId, hit, nodeId } of failHits) {
    const threats = input.threats.filter(
      (t) => t.canonicalId === canonicalId && (nodeId === undefined || t.nodeIds.includes(nodeId)),
    );
    if (threats.length > 0) {
      const e = confirmedMap.get(canonicalId) ?? { canonicalId, hits: [], threats: [] };
      confirmedMap.set(canonicalId, e);
      addHit(e.hits, hit);
      for (const t of threats) if (!e.threats.includes(t)) e.threats.push(t);
    } else {
      const e = notInModelMap.get(canonicalId) ?? { canonicalId, hits: [] };
      notInModelMap.set(canonicalId, e);
      addHit(e.hits, hit);
    }
  }

  const byId = <T extends { canonicalId: string }>(a: T, b: T) => a.canonicalId.localeCompare(b.canonicalId);
  const result: ProwlerImportResult = {
    summary: {
      findings: input.findings.length,
      mappedChecks: seenChecks.size,
      unknownChecks: unknownChecks.size,
      manual,
      applied: applied.length,
      unchanged: unchanged.length,
      conflicts: conflicts.length,
      notApplicable: notApplicable.length,
      unmatchedResources: unmatched.size,
    },
    applied,
    unchanged,
    conflicts,
    notApplicable,
    unmatchedResources: [...unmatched.values()],
    confirmed: [...confirmedMap.values()].sort(byId),
    notInModel: [...notInModelMap.values()].sort(byId),
    unmappedChecks: [...unmappedFail.values()].sort((a, b) => b.count - a.count || a.checkId.localeCompare(b.checkId)),
  };
  return result;
}

/**
 * 適用する値（`applied`）を 1 レイヤー分のノードに書き込んだ新しい配列を返す（元は変更しない）。
 * 既に値があるノードの項目は applyProwler が applied に含めない＝上書きしない。
 */
export function fillNodes<T extends { id: string; posture?: object; attackSurface?: object }>(
  nodes: readonly T[],
  applied: readonly AppliedValue[],
  layer: LayerKey,
): T[] {
  return nodes.map((n) => {
    let next = n;
    for (const a of applied) {
      if (a.layer !== layer || a.nodeId !== n.id) continue;
      const key = attackSurfaceKeyOf(a.field);
      next = key
        ? { ...next, attackSurface: { ...next.attackSurface, [key]: a.value } }
        : { ...next, posture: { ...next.posture, [a.field]: a.value } };
    }
    return next;
  });
}
