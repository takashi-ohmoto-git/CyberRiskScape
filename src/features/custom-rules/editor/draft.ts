import { z } from 'zod';
import {
  ThreatRuleSchema,
  type AgentAttributesMatch,
  type AttackSurfaceMatch,
  type ComplianceRef,
  type ConnectionDirection,
  type ConnectionRequirement,
  type Framework,
  type MitigationTiers,
  type Reference,
  type Severity,
  type ThreatRule,
} from '../../../threat-library/schema/threatRule';

/**
 * ルールエディタ（§2.25 Phase D「ワークフロー形式」）の **draft 状態モデル**と
 * `ThreatRule` との往復変換。
 *
 * 設計（[[architecture]] §5 / docs/plan.md §2.25）：
 * - `ThreatRuleSchema` を唯一の真実源とする。draft は編集途中の**緩い**表現で、
 *   `appliesTo` の「ちょうど1つ」制約や「最低1軸」制約は満たさなくてよい。
 *   検証は保存時に `ThreatRuleSchema.safeParse` に一任する（並行スキーマを作らない）。
 * - draft は UI が自由に編集できるよう、各条件軸を**常に存在する配列/フラグ**として持つ。
 *   空配列・null は「未指定（= その軸を出力しない）」を意味し、`draftToRule` で除去する。
 * - `draftToRule(ruleToDraft(rule))` は **正規化された形**で round-trip する
 *   （`draft.test.ts` 参照）。
 */

// schema 非公開型を公開 union から復元（detectThreats.ts と同じ手法）。
type EdgeAppliesTo = Extract<ThreatRule['appliesTo'], { kind: 'edge' }>;
type EdgeWhenLeaf = NonNullable<EdgeAppliesTo['when']>;
type EdgeConditionCase = NonNullable<EdgeAppliesTo['conditions']>[number];
type NodeAppliesTo = Extract<ThreatRule['appliesTo'], { kind: 'node' }>;

// ── draft 型 ────────────────────────────────────────────────────────────────

/**
 * Edge ルールのリーフ（5+ 軸）。各軸は常に通常配列（空 = 未指定）。
 * スキーマ側は `.nonempty()` の tuple 型だが、draft は編集途中に空を許すため要素配列に緩める。
 */
export type EdgeLeafDraft = { [K in keyof EdgeWhenLeaf]-?: NonNullable<EdgeWhenLeaf[K]>[number][] };

/** Attack Surface 条件。各属性 true/false/null（null = 不問）。 */
export type AttackSurfaceDraft = { [K in keyof AttackSurfaceMatch]-?: boolean | null };

/** エージェント属性条件。各フィールド常に通常配列（空 = 未指定）。 */
export type AgentAttributesDraft = {
  [K in keyof AgentAttributesMatch]-?: NonNullable<AgentAttributesMatch[K]>[number][];
};

export type EdgeMode = 'when' | 'allOf' | 'anyOf';
export type NodeMode = 'single' | 'anyOf';

/** severity / description の段階分岐（conditions[] の 1 ケース）。 */
export interface ConditionCaseDraft {
  when: EdgeLeafDraft;
  /** '' = severity を上書きしない。 */
  severity: Severity | '';
  /** '' = description を上書きしない。 */
  description: string;
}

/** Node ルールの接続要件 draft。 */
export interface ConnectionDraft {
  /** false = connection を出力しない（= デフォルト挙動: required:true / any）。 */
  enabled: boolean;
  /** false = 内在的脅威（接続不問）。このとき direction/peerType/peer 面は出力しない。 */
  required: boolean;
  direction: ConnectionDirection;
  peerType: string[];
  peerAttackSurface: AttackSurfaceDraft;
}

export interface NodeDraft {
  mode: NodeMode;
  /** single は [0] のみ、anyOf は全要素を使う。 */
  nodeTypes: string[];
  connection: ConnectionDraft;
  attackSurface: AttackSurfaceDraft;
  agentAttributes: AgentAttributesDraft;
}

export interface EdgeDraft {
  mode: EdgeMode;
  /** when は [0] のみ、allOf/anyOf は全要素を使う。 */
  leaves: EdgeLeafDraft[];
  conditions: ConditionCaseDraft[];
}

/** ルール 1 本ぶんの編集状態。 */
export interface RuleDraft {
  id: string;
  framework: Framework;
  category: string;
  /** 脅威名（表示用タイトル）。'' = 未設定（UI は category にフォールバック）。 */
  name: string;
  severity: Severity;
  description: string;
  /** '' = 未設定。 */
  mitigation: string;
  /** markup 由来の構造化 tier。round-trip 維持のため保持（編集 UI は後続段階）。 */
  mitigationTiers: MitigationTiers | null;
  complianceRefs: ComplianceRef[];
  references: Reference[];
  kind: 'node' | 'edge';
  /** kind に関わらず両方を保持し、対象切替時も入力を失わない。 */
  node: NodeDraft;
  edge: EdgeDraft;
}

// ── キー一覧（反復用） ────────────────────────────────────────────────────────

const EDGE_AXES = [
  'auth',
  'network',
  'encryption',
  'sourceType',
  'targetType',
  'sourceTrust',
  'targetTrust',
  'sourceManagedState',
  'targetManagedState',
  'sourceUserTrust',
  'targetUserTrust',
  'semantic',
] as const satisfies readonly (keyof EdgeLeafDraft)[];

const ATTACK_SURFACE_KEYS = [
  'hasGlobalIp',
  'hasSourceIpRestriction',
  'hasRemoteAccessRestriction',
  'hasUserAuthentication',
  'hasAccessLog',
  'hasWafProtection',
  'hasDdosProtection',
] as const satisfies readonly (keyof AttackSurfaceDraft)[];

const AGENT_ATTR_KEYS = [
  'agency',
  'blastRadius',
  'identityTier',
] as const satisfies readonly (keyof AgentAttributesDraft)[];

// ── 空 draft ファクトリ ───────────────────────────────────────────────────────

export function emptyLeaf(): EdgeLeafDraft {
  return {
    auth: [],
    network: [],
    encryption: [],
    sourceType: [],
    targetType: [],
    sourceTrust: [],
    targetTrust: [],
    sourceManagedState: [],
    targetManagedState: [],
    sourceUserTrust: [],
    targetUserTrust: [],
    semantic: [],
  };
}

export function emptyAttackSurface(): AttackSurfaceDraft {
  return {
    hasGlobalIp: null,
    hasSourceIpRestriction: null,
    hasRemoteAccessRestriction: null,
    hasUserAuthentication: null,
    hasAccessLog: null,
    hasWafProtection: null,
    hasDdosProtection: null,
  };
}

export function emptyAgentAttributes(): AgentAttributesDraft {
  return { agency: [], blastRadius: [], identityTier: [] };
}

export function emptyConnection(): ConnectionDraft {
  return {
    enabled: false,
    required: true,
    direction: 'any',
    peerType: [],
    peerAttackSurface: emptyAttackSurface(),
  };
}

export function emptyNodeDraft(): NodeDraft {
  return {
    mode: 'single',
    nodeTypes: [],
    connection: emptyConnection(),
    attackSurface: emptyAttackSurface(),
    agentAttributes: emptyAgentAttributes(),
  };
}

export function emptyEdgeDraft(): EdgeDraft {
  return { mode: 'when', leaves: [emptyLeaf()], conditions: [] };
}

/** 新規ルール用の空 draft。 */
export function emptyDraft(kind: 'node' | 'edge'): RuleDraft {
  return {
    id: '',
    framework: 'STRIDE',
    category: '',
    name: '',
    severity: 'Medium',
    description: '',
    mitigation: '',
    mitigationTiers: null,
    complianceRefs: [],
    references: [],
    kind,
    node: emptyNodeDraft(),
    edge: emptyEdgeDraft(),
  };
}

// ── ThreatRule → draft ───────────────────────────────────────────────────────

function leafToDraft(leaf: EdgeWhenLeaf): EdgeLeafDraft {
  const out = emptyLeaf();
  for (const k of EDGE_AXES) {
    const v = leaf[k];
    if (v) (out[k] as unknown[]) = [...v];
  }
  return out;
}

function conditionToDraft(c: EdgeConditionCase): ConditionCaseDraft {
  return {
    when: leafToDraft(c.when),
    severity: c.severity ?? '',
    description: c.description ?? '',
  };
}

function surfaceToDraft(match: AttackSurfaceMatch): AttackSurfaceDraft {
  const out = emptyAttackSurface();
  for (const k of ATTACK_SURFACE_KEYS) {
    const v = match[k];
    if (v !== undefined) out[k] = v;
  }
  return out;
}

function agentToDraft(match: AgentAttributesMatch): AgentAttributesDraft {
  const out = emptyAgentAttributes();
  for (const k of AGENT_ATTR_KEYS) {
    const v = match[k];
    if (v) (out[k] as unknown[]) = [...v];
  }
  return out;
}

function connectionToDraft(conn: ConnectionRequirement | undefined): ConnectionDraft {
  if (!conn) return emptyConnection();
  if (conn.required === false) {
    return { ...emptyConnection(), enabled: true, required: false };
  }
  return {
    enabled: true,
    required: true,
    direction: conn.direction ?? 'any',
    peerType: conn.peerType ? [...conn.peerType] : [],
    peerAttackSurface: conn.peerAttackSurface
      ? surfaceToDraft(conn.peerAttackSurface)
      : emptyAttackSurface(),
  };
}

function edgeToDraft(applies: EdgeAppliesTo): EdgeDraft {
  let mode: EdgeMode;
  let leaves: EdgeLeafDraft[];
  if (applies.when) {
    mode = 'when';
    leaves = [leafToDraft(applies.when)];
  } else if (applies.allOf) {
    mode = 'allOf';
    leaves = applies.allOf.map(leafToDraft);
  } else {
    mode = 'anyOf';
    leaves = (applies.anyOf ?? []).map(leafToDraft);
  }
  return { mode, leaves, conditions: (applies.conditions ?? []).map(conditionToDraft) };
}

function nodeToDraft(applies: NodeAppliesTo): NodeDraft {
  const mode: NodeMode = applies.nodeType ? 'single' : 'anyOf';
  const nodeTypes = applies.nodeType
    ? [applies.nodeType]
    : (applies.anyOf ?? []).map((l) => l.nodeType);
  return {
    mode,
    nodeTypes,
    connection: connectionToDraft(applies.connection),
    attackSurface: applies.attackSurface ? surfaceToDraft(applies.attackSurface) : emptyAttackSurface(),
    agentAttributes: applies.agentAttributes
      ? agentToDraft(applies.agentAttributes)
      : emptyAgentAttributes(),
  };
}

export function ruleToDraft(rule: ThreatRule): RuleDraft {
  const kind = rule.appliesTo.kind;
  return {
    id: rule.id,
    framework: rule.framework,
    category: rule.category,
    name: rule.name ?? '',
    severity: rule.severity,
    description: rule.description,
    mitigation: rule.mitigation ?? '',
    mitigationTiers: rule.mitigationTiers ?? null,
    complianceRefs: rule.complianceRefs ? rule.complianceRefs.map((r) => ({ ...r })) : [],
    references: rule.references ? rule.references.map((r) => ({ ...r })) : [],
    kind,
    node: kind === 'node' ? nodeToDraft(rule.appliesTo) : emptyNodeDraft(),
    edge: kind === 'edge' ? edgeToDraft(rule.appliesTo) : emptyEdgeDraft(),
  };
}

// ── draft → ThreatRule（保存時検証） ─────────────────────────────────────────

function cleanLeaf(leaf: EdgeLeafDraft): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of EDGE_AXES) {
    const v = leaf[k];
    if (v.length > 0) out[k] = v;
  }
  return out;
}

function buildAttackSurface(d: AttackSurfaceDraft): Record<string, boolean> | undefined {
  const out: Record<string, boolean> = {};
  for (const k of ATTACK_SURFACE_KEYS) {
    const v = d[k];
    if (v !== null) out[k] = v;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function buildAgentAttributes(d: AgentAttributesDraft): Record<string, string[]> | undefined {
  const out: Record<string, string[]> = {};
  for (const k of AGENT_ATTR_KEYS) {
    const v = d[k];
    if (v.length > 0) out[k] = [...v];
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function buildConnection(c: ConnectionDraft): Record<string, unknown> | undefined {
  if (!c.enabled) return undefined;
  if (!c.required) return { required: false };
  const out: Record<string, unknown> = { required: true, direction: c.direction };
  if (c.peerType.length > 0) out.peerType = [...c.peerType];
  const peer = buildAttackSurface(c.peerAttackSurface);
  if (peer) out.peerAttackSurface = peer;
  return out;
}

function buildConditionCase(c: ConditionCaseDraft): Record<string, unknown> {
  const out: Record<string, unknown> = { when: cleanLeaf(c.when) };
  if (c.severity !== '') out.severity = c.severity;
  if (c.description.trim() !== '') out.description = c.description;
  return out;
}

function buildEdgeAppliesTo(edge: EdgeDraft): Record<string, unknown> {
  const out: Record<string, unknown> = { kind: 'edge' };
  const leaves = edge.leaves.map(cleanLeaf);
  if (edge.mode === 'when') {
    if (leaves.length > 0) out.when = leaves[0];
  } else if (edge.mode === 'allOf') {
    out.allOf = leaves;
  } else {
    out.anyOf = leaves;
  }
  if (edge.conditions.length > 0) out.conditions = edge.conditions.map(buildConditionCase);
  return out;
}

function buildNodeAppliesTo(node: NodeDraft): Record<string, unknown> {
  const out: Record<string, unknown> = { kind: 'node' };
  if (node.mode === 'single') {
    if (node.nodeTypes[0]) out.nodeType = node.nodeTypes[0];
  } else {
    out.anyOf = node.nodeTypes.map((t) => ({ nodeType: t }));
  }
  const conn = buildConnection(node.connection);
  if (conn) out.connection = conn;
  const surface = buildAttackSurface(node.attackSurface);
  if (surface) out.attackSurface = surface;
  const agent = buildAgentAttributes(node.agentAttributes);
  if (agent) out.agentAttributes = agent;
  return out;
}

export type DraftToRuleResult =
  | { ok: true; rule: ThreatRule }
  | { ok: false; issues: string[] };

/** draft 文字列の `path: message` 形式整形（io.ts / schema.ts と同じ流儀）。 */
function formatIssues(error: z.ZodError): string[] {
  return error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`);
}

/**
 * draft を `ThreatRule` に変換し `ThreatRuleSchema` で検証する。
 * 失敗時は表示用エラーメッセージ配列を返す（throw しない）。
 */
export function draftToRule(draft: RuleDraft): DraftToRuleResult {
  const appliesTo =
    draft.kind === 'node' ? buildNodeAppliesTo(draft.node) : buildEdgeAppliesTo(draft.edge);

  const candidate: Record<string, unknown> = {
    id: draft.id,
    framework: draft.framework,
    category: draft.category,
    severity: draft.severity,
    description: draft.description,
    appliesTo,
  };
  if (draft.name.trim() !== '') candidate.name = draft.name;
  if (draft.mitigation.trim() !== '') candidate.mitigation = draft.mitigation;
  if (draft.mitigationTiers) candidate.mitigationTiers = draft.mitigationTiers;

  // 空行は出力しない。空 url（'' ）は ReferenceSchema の .url() を落とすため除去する。
  const complianceRefs = draft.complianceRefs.filter(
    (c) => c.standard.trim() !== '' && c.ref.trim() !== '',
  );
  if (complianceRefs.length > 0) candidate.complianceRefs = complianceRefs;

  const references = draft.references
    .filter((r) => r.title.trim() !== '')
    .map((r) => (r.url && r.url.trim() !== '' ? { title: r.title, url: r.url } : { title: r.title }));
  if (references.length > 0) candidate.references = references;

  const result = ThreatRuleSchema.safeParse(candidate);
  if (!result.success) return { ok: false, issues: formatIssues(result.error) };
  return { ok: true, rule: result.data };
}
