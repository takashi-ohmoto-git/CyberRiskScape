import { z } from 'zod';
import {
  deserializeProject,
  resolveIdCounters,
  resolveLayers,
} from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import {
  AgencyLevelSchema,
  AuthTypeSchema,
  BlastRadiusSchema,
  DataFlowSchema,
  EdgeSemanticSchema,
  EncryptionTypeSchema,
  IdentityProviderKindSchema,
  IdentityTierSchema,
  ManagedStateSchema,
  NetworkTypeSchema,
  TrustLevelSchema,
  UserTrustAttributeSchema,
} from '../threat-library/schema/threatRule';
import { componentRegistry } from '../component-library/defaultRegistry';
import {
  AGENCY_APPLICABLE,
  ATTACK_OBJECTIVE_APPLICABLE,
  AUTH_PROVIDER_APPLICABLE,
  IDENTITY_TIER_APPLICABLE,
  IDP_KIND_APPLICABLE,
  LAYER_KEYS,
  SANCTION_ATTRIBUTE_APPLICABLE,
  THREAT_ACTOR_TYPE_APPLICABLE,
  type BoundaryTypeId,
  type DiagramAnnotation,
  type DiagramBoundary,
  type DiagramEdge,
  type DiagramNode,
  type LayerData,
  type LayerKey,
  type ManagedState,
  type SeqCounters,
  type TrustLevel,
  type UserTrustAttribute,
} from '../core/model/types';
import {
  MACRO_TRUST_TO_TRUST_LEVEL,
  MICRO_TRUST_TO_TRUST_LEVEL,
} from '../core/constants/boundaryTypes';
import { boundaryAround, emptyBoundaryRect, placeAnnotation, placeNode } from './placement';

/**
 * MCP の `apply_model_changes` が使う「構成変更の適用」純粋モジュール。
 *
 * - 編集できるのは対象レイヤーの構成（ノード・エッジ・境界・注釈）のみ。座標・id・seq は
 *   エージェントに指定させない（操作スキーマは `.strict()`、座標はサーバー側の配置で決める）。
 * - 判断系フィールド（suppressions / riskScores / controlStatuses / manualThreats / projectMeta 等）
 *   と対象外レイヤーには一切触れない。
 * - 全件を検証・適用し、1 件でも失敗したら `McpOperationError` を throw して何も返さない（原子的）。
 */

/** 1 回の呼び出しで受け付ける操作数の上限。 */
export const MAX_OPERATIONS = 100;

export class McpOperationError extends Error {
  /** 失敗した操作の添字（0 始まり）。操作に紐づかない失敗は -1。 */
  readonly index: number;
  readonly reason: string;
  constructor(index: number, reason: string) {
    super(index >= 0 ? `operations[${index}]: ${reason}` : reason);
    this.name = 'McpOperationError';
    this.index = index;
    this.reason = reason;
  }
}

// ── スキーマ ──────────────────────────────────────────────────────────────

// ── エラーメッセージ（日本語） ─────────────────────────────────────────────
// SDK は入力検証（`z.array(OperationSchema)`）の Zod 既定メッセージをそのままクライアントへ返すため、
// スキーマ側に errorMap を付けて日本語化する（tools/list の JSON Schema は変わらない）。
// サーバーの他のメッセージと同じく日本語固定（locale は tools 側の脅威本文用）。

/** 判断系（受容・誤検知・リスク評価・対策実装状況・手動脅威）に当たるキー／操作名。 */
const JUDGEMENT_RE = /suppress|accept|false.?positive|risk|dread|control|manual.?threat|mitigat|project.?meta/i;

export const JUDGEMENT_GUIDANCE =
  '受容・誤検知・リスク評価・対策実装状況はこのツールでは変更できません。人が CyberRiskScape で設定し、PR で承認します。';

const opErrorMap: z.ZodErrorMap = (issue, ctx) => {
  if (issue.code === z.ZodIssueCode.unrecognized_keys) {
    const keys = issue.keys.map((k) => `"${k}"`).join(', ');
    const hint = issue.keys.some((k) => JUDGEMENT_RE.test(k))
      ? JUDGEMENT_GUIDANCE
      : '座標・id・seq などは指定できません。使えるキーは operations の入力スキーマを参照してください。';
    return { message: `この操作では使えないキーがあります: ${keys}。${hint}` };
  }
  if (issue.code === z.ZodIssueCode.invalid_union_discriminator) {
    const given = (ctx.data as { op?: unknown } | undefined)?.op;
    const name = typeof given === 'string' ? given : String(given);
    const hint = typeof given === 'string' && JUDGEMENT_RE.test(given) ? JUDGEMENT_GUIDANCE : '';
    return {
      message: `未定義の操作 "${name}" です（使える op: ${issue.options.map(String).join(' / ')}）。${hint}`,
    };
  }
  return { message: ctx.defaultError };
};

/** `.strict()` ＋日本語 errorMap の操作用オブジェクト。 */
const opObject = <T extends z.ZodRawShape>(shape: T) => z.object(shape, { errorMap: opErrorMap }).strict();

const DATA_FLOW_DESC =
  'データ通信の向き（source から見た向き）。outbound＝source → target（既定）、inbound＝target → source、bidirectional＝双方向。キャンバスの矢印の向きと、脅威ルールの接続方向（inbound＝対象ノードが target 側）の判定に使われる。';
const SEMANTIC_DESC =
  'エッジの意味（省略時は data_flow）：data_flow／tool_invocation（ツール呼び出し）／delegation（委任）／memory_read／memory_write／rag_retrieval／directory_sync。AI・エージェント系の脅威判定に使われる。';
const BOUNDARY_ID_DESC =
  '配置先の信頼境界の id（set の中ではなく操作の直下に置く）。座標は指定できず、サーバーが境界内に配置する。update_node では null で境界の外へ移動。';

/** `set` が空でないことの検査（スキーマの `.refine` は未知キー拒否の後に二次エラーを出すため適用側で行う）。 */
const failIfEmptySet = (set: object | undefined): void => {
  if (set !== undefined && Object.keys(set).length === 0) fail('set が空です');
};

const idStr = z.string().min(1).max(100);
const labelStr = z.string().min(1).max(200);
const descStr = z.string().max(2000);
/** 同一呼び出し内の後続操作から `@name` で参照するための名前。 */
const refStr = z.string().regex(/^[A-Za-z][A-Za-z0-9_-]{0,39}$/);

const CloudSanctionSchema = z.enum(['Sanctioned', 'Unsanctioned']);
const CloudOwnershipSchema = z.enum(['Company', 'ThirdParty', 'Personal']);
const ThreatActorTypeSchema = z.enum([
  'CyberCriminals',
  'NationStateActors',
  'FinanciallyMotivatedActors',
  'Hacktivists',
  'ScriptKiddies',
]);
const AttackSurfaceSchema = z
  .object({
    hasGlobalIp: z.boolean().optional(),
    hasSourceIpRestriction: z.boolean().optional(),
    hasRemoteAccessRestriction: z.boolean().optional(),
    hasUserAuthentication: z.boolean().optional(),
    hasAccessLog: z.boolean().optional(),
    hasWafProtection: z.boolean().optional(),
    hasDdosProtection: z.boolean().optional(),
  })
  .strict();
const AgentAttributesSchema = z
  .object({
    agency: AgencyLevelSchema.optional(),
    blastRadius: BlastRadiusSchema.optional(),
    identityTier: IdentityTierSchema.optional(),
  })
  .strict();

/** ノード属性（description を含む）。add / update で共通。 */
const nodeAttrShape = {
  description: descStr.optional(),
  managedState: ManagedStateSchema.optional(),
  userTrustAttribute: UserTrustAttributeSchema.optional(),
  cloudSanction: CloudSanctionSchema.optional(),
  cloudOwnership: CloudOwnershipSchema.optional(),
  threatActorType: ThreatActorTypeSchema.optional(),
  attackObjectiveId: idStr.optional(),
  identityProviderKind: IdentityProviderKindSchema.optional(),
  authProviderId: idStr.optional(),
  attackSurface: AttackSurfaceSchema.optional(),
  agentAttributes: AgentAttributesSchema.optional(),
};

/** `update_node.set`：許可リスト。null は「その属性を消す」。 */
const NodeSetSchema = opObject({
  label: labelStr.optional(),
  description: descStr.nullable().optional(),
  managedState: ManagedStateSchema.nullable().optional(),
  userTrustAttribute: UserTrustAttributeSchema.nullable().optional(),
  cloudSanction: CloudSanctionSchema.nullable().optional(),
  cloudOwnership: CloudOwnershipSchema.nullable().optional(),
  threatActorType: ThreatActorTypeSchema.nullable().optional(),
  attackObjectiveId: idStr.nullable().optional(),
  identityProviderKind: IdentityProviderKindSchema.nullable().optional(),
  authProviderId: idStr.nullable().optional(),
  attackSurface: AttackSurfaceSchema.nullable().optional(),
  agentAttributes: AgentAttributesSchema.nullable().optional(),
});

/** `update_edge.set`：source / target は変更不可（付け替えは delete + add）。 */
const EdgeSetSchema = opObject({
  auth: AuthTypeSchema.optional(),
  network: NetworkTypeSchema.optional(),
  encryption: EncryptionTypeSchema.optional(),
  dataFlow: DataFlowSchema.optional().describe(DATA_FLOW_DESC),
  dataFlowName: z.string().min(1).max(80).nullable().optional(),
  semantic: EdgeSemanticSchema.nullable().optional().describe(SEMANTIC_DESC),
  authProviderId: idStr.nullable().optional(),
});

const MacroTrustSchema = z.enum(['Public Area', 'Office Area', 'Security Zone']);
const MicroTrustSchema = z.enum(['Development', 'Staging', 'Production']);
const MicroStatusSchema = z.enum(['適用済み', '未適用']);
const SensitiveDataSchema = z.enum(['無し', '個人情報', '機密情報']);
const BoundaryTypeSchema = z.enum([
  'RECT',
  'RECT_DASHED',
  'ROUNDED',
  'ROUNDED_DASHED',
  'BLAST_RADIUS',
]);

/** 境界の型別属性（add / update で共通）。 */
const boundaryAttrShape = {
  macroTrust: MacroTrustSchema.optional(),
  vlanName: z.string().max(64).optional(),
  vlanId: z.number().int().min(0).max(4094).optional(),
  networkAddress: z.string().max(64).optional(),
  microTrust: MicroTrustSchema.optional(),
  microSegmentationStatus: MicroStatusSchema.optional(),
  sensitiveData: SensitiveDataSchema.optional(),
  blastRadiusLabel: z.string().max(64).optional(),
};

const BoundarySetSchema = opObject({
  trustLevel: TrustLevelSchema.optional(),
  macroTrust: MacroTrustSchema.optional(),
  vlanName: z.string().max(64).nullable().optional(),
  vlanId: z.number().int().min(0).max(4094).nullable().optional(),
  networkAddress: z.string().max(64).nullable().optional(),
  microTrust: MicroTrustSchema.optional(),
  microSegmentationStatus: MicroStatusSchema.optional(),
  sensitiveData: SensitiveDataSchema.optional(),
  blastRadiusLabel: z.string().max(64).nullable().optional(),
});


export const OperationSchema = z.discriminatedUnion(
  'op',
  [
  opObject({
      op: z.literal('add_node'),
      ref: refStr.optional(),
      type: z.string().min(1).max(100),
      label: labelStr,
      boundaryId: idStr.optional().describe(BOUNDARY_ID_DESC),
      parentId: idStr.optional(),
      ...nodeAttrShape,
    }),
  opObject({
      op: z.literal('update_node'),
      id: idStr,
      set: NodeSetSchema.optional(),
      /** 指定すると再配置（境界の移動）。null は「どの境界にも入らない位置」へ。 */
      boundaryId: idStr.nullable().optional().describe(BOUNDARY_ID_DESC),
    }),
  opObject({ op: z.literal('delete_node'), id: idStr }),
  opObject({
      op: z.literal('add_edge'),
      ref: refStr.optional(),
      source: idStr,
      target: idStr,
      auth: AuthTypeSchema,
      network: NetworkTypeSchema,
      encryption: EncryptionTypeSchema,
      dataFlow: DataFlowSchema.optional().describe(DATA_FLOW_DESC),
      dataFlowName: z.string().min(1).max(80).optional(),
      semantic: EdgeSemanticSchema.optional().describe(SEMANTIC_DESC),
      authProviderId: idStr.optional(),
    }),
  opObject({
      op: z.literal('update_edge'),
      id: idStr,
      set: EdgeSetSchema,
    }),
  opObject({ op: z.literal('delete_edge'), id: idStr }),
  opObject({
      op: z.literal('add_boundary'),
      ref: refStr.optional(),
      type: BoundaryTypeSchema,
      trustLevel: TrustLevelSchema.optional(),
      /** 指定ノード（と内包された子）を囲む。省略時は既存要素の右側に空の境界を作る。 */
      around: z.array(idStr).min(1).max(100).optional(),
      ...boundaryAttrShape,
    }),
  opObject({
      op: z.literal('update_boundary'),
      id: idStr,
      set: BoundarySetSchema,
    }),
  opObject({ op: z.literal('delete_boundary'), id: idStr }),
  opObject({
      op: z.literal('add_annotation'),
      kind: z.enum(['label', 'callout']),
      text: z.string().min(1).max(2000),
      targetNodeId: idStr.optional(),
    }),
],
  { errorMap: opErrorMap },
);

export type Operation = z.infer<typeof OperationSchema>;

export interface OperationResult {
  index: number;
  op: string;
  /** add_* は採番した id、それ以外は対象の id。 */
  id?: string;
}

// ── 採番 ──────────────────────────────────────────────────────────────────

/** `diagramStore` の `nextId` と同じ形式（prefix + Date.now() の 36 進 + 単調増加カウンタ）。 */
let idSeq = 0;
const nextId = (prefix: string): string =>
  `${prefix}${Date.now().toString(36)}${(idSeq++).toString(36)}`;

// ── 適用 ──────────────────────────────────────────────────────────────────

const AUTH_PROVIDER_EXCLUDED_CATEGORIES: ReadonlySet<string> = new Set(['DOCUMENTS', 'ATTACKER']);
const MANAGED_STATE_APPLICABLE: ReadonlySet<string> = new Set(['PC', 'SMARTPHONE', 'IOT']);
const ATTACK_SURFACE_APPLICABLE: ReadonlySet<string> = new Set(['FRONT_END_SERVER', 'GATEWAY']);
const USER_TRUST_TO_MANAGED: Record<UserTrustAttribute, ManagedState> = {
  Guest: 'Unmanaged',
  Employee: 'Managed',
  Contractor: 'Managed',
  Partner: 'Managed',
};

type Attrs = Record<string, unknown>;

/** 1 回の適用中の作業状態（対象レイヤーのみ）。 */
interface Work {
  layer: LayerData;
  counters: SeqCounters;
  refs: Map<string, string>;
}

function fail(message: string): never {
  throw new Error(message);
}

function resolveId(work: Work, id: string): string {
  if (!id.startsWith('@')) return id;
  const mapped = work.refs.get(id.slice(1));
  if (!mapped) fail(`参照 ${id} は、先行する操作で宣言された ref ではありません`);
  return mapped;
}

function findNode(work: Work, id: string): DiagramNode {
  return work.layer.nodes.find((n) => n.id === id) ?? fail(`ノード ${id} が存在しません`);
}

function findBoundary(work: Work, id: string): DiagramBoundary {
  return work.layer.boundaries.find((b) => b.id === id) ?? fail(`境界 ${id} が存在しません`);
}

function registerRef(work: Work, ref: string | undefined, id: string): void {
  if (ref === undefined) return;
  if (work.refs.has(ref)) fail(`ref ${ref} が重複しています`);
  work.refs.set(ref, id);
}

function pickDefined(obj: object): Attrs {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined));
}

/** 資格情報の発行元に指定できるノードか確認する（エッジ・ノード共通）。 */
function checkAuthProvider(work: Work, id: string, selfId?: string): void {
  const provider = findNode(work, id);
  if (provider.id === selfId) fail('authProviderId に自分自身は指定できません');
  if (!AUTH_PROVIDER_APPLICABLE.has(provider.type)) {
    fail(`authProviderId のノード ${id}（${provider.type}）は資格情報の発行元になれない型です`);
  }
}

/**
 * ノードに設定しようとした属性が、その型で意味を持つか・参照先が妥当かを検証する。
 * `keys` は今回設定した属性（既存の古い値は検証しない）。
 */
function validateNodeAttrs(work: Work, node: DiagramNode, keys: readonly string[]): void {
  const has = (k: string) => keys.includes(k);
  const must = (ok: boolean, k: string) => {
    if (!ok) fail(`属性 ${k} は型 ${node.type} には設定できません`);
  };
  if (has('managedState')) must(MANAGED_STATE_APPLICABLE.has(node.type), 'managedState');
  if (has('userTrustAttribute')) must(node.type === 'USER', 'userTrustAttribute');
  if (has('cloudSanction')) must(SANCTION_ATTRIBUTE_APPLICABLE.has(node.type), 'cloudSanction');
  if (has('cloudOwnership')) must(SANCTION_ATTRIBUTE_APPLICABLE.has(node.type), 'cloudOwnership');
  if (has('threatActorType')) must(THREAT_ACTOR_TYPE_APPLICABLE.has(node.type), 'threatActorType');
  if (has('identityProviderKind')) must(IDP_KIND_APPLICABLE.has(node.type), 'identityProviderKind');
  if (has('attackSurface')) must(ATTACK_SURFACE_APPLICABLE.has(node.type), 'attackSurface');
  if (has('attackObjectiveId')) {
    must(ATTACK_OBJECTIVE_APPLICABLE.has(node.type), 'attackObjectiveId');
    const target = findNode(work, node.attackObjectiveId as string);
    if (target.id === node.id) fail('attackObjectiveId に自分自身は指定できません');
    if (ATTACK_OBJECTIVE_APPLICABLE.has(target.type)) {
      fail(`attackObjectiveId の標的に攻撃者ノード ${target.id} は指定できません`);
    }
  }
  if (has('authProviderId')) {
    const category = componentRegistry.get(node.type)?.category;
    must(
      category !== undefined &&
        !AUTH_PROVIDER_EXCLUDED_CATEGORIES.has(category) &&
        node.type !== 'SHADOW' &&
        node.type !== 'SHADOW_APP',
      'authProviderId',
    );
    checkAuthProvider(work, node.authProviderId as string, node.id);
  }
  if (has('agentAttributes') && node.agentAttributes) {
    const a = node.agentAttributes;
    if (a.agency !== undefined && !AGENCY_APPLICABLE.has(node.type)) {
      fail(`agentAttributes.agency は型 ${node.type} には設定できません`);
    }
    if (a.identityTier !== undefined && !IDENTITY_TIER_APPLICABLE.has(node.type)) {
      fail(`agentAttributes.identityTier は型 ${node.type} には設定できません`);
    }
  }
}

/** 参照を持つノード属性の id を ref 解決する。 */
function resolveNodeRefs(work: Work, attrs: Attrs): void {
  for (const k of ['attackObjectiveId', 'authProviderId']) {
    const v = attrs[k];
    if (typeof v === 'string') attrs[k] = resolveId(work, v);
  }
}

function applyAddNode(work: Work, op: Extract<Operation, { op: 'add_node' }>): string {
  if (!componentRegistry.has(op.type)) fail(`未知のコンポーネント型 ${op.type} です（list_component_types で確認してください）`);
  const { op: _op, ref, type, label, boundaryId, parentId, ...rest } = op;
  const attrs = pickDefined(rest);
  resolveNodeRefs(work, attrs);

  let x: number;
  let y: number;
  let resolvedParent: string | undefined;
  if (parentId !== undefined) {
    if (boundaryId !== undefined) fail('parentId と boundaryId は同時に指定できません（内包された子は親の位置に属します）');
    resolvedParent = resolveId(work, parentId);
    const parent = findNode(work, resolvedParent);
    if (!componentRegistry.canContain(parent.type, type)) {
      fail(`型 ${parent.type} は型 ${type} を内包できません`);
    }
    x = parent.x;
    y = parent.y;
  } else {
    const placed = placeNode(work.layer, type, boundaryId === undefined ? null : resolveId(work, boundaryId));
    x = placed.x;
    y = placed.y;
    if (placed.expandedBoundary) expandBoundary(work, resolveId(work, boundaryId as string), placed.expandedBoundary);
  }

  const seq = work.counters.node + 1;
  const id = nextId('n');
  const node: DiagramNode = {
    id,
    seq,
    type,
    x,
    y,
    ...(resolvedParent !== undefined ? { parentId: resolvedParent } : {}),
    label,
    ...(attrs as Partial<DiagramNode>),
  };
  if (node.userTrustAttribute !== undefined) {
    node.managedState = USER_TRUST_TO_MANAGED[node.userTrustAttribute];
  }
  // 先にノードを置く（authProviderId 等の自己参照検査が id を引けるように）
  validateNodeAttrs({ ...work, layer: { ...work.layer, nodes: [...work.layer.nodes, node] } }, node, Object.keys(attrs));
  work.layer.nodes.push(node);
  work.counters.node = seq;
  registerRef(work, ref, id);
  return id;
}

function expandBoundary(work: Work, boundaryId: string, rect: { height: number }): void {
  work.layer.boundaries = work.layer.boundaries.map((b) =>
    b.id === boundaryId ? { ...b, height: rect.height } : b,
  );
}

function applyUpdateNode(work: Work, op: Extract<Operation, { op: 'update_node' }>): string {
  if (op.set === undefined && op.boundaryId === undefined) fail('set か boundaryId が必要です');
  failIfEmptySet(op.set);
  const id = resolveId(work, op.id);
  const current = findNode(work, id);
  let next: DiagramNode = { ...current };

  if (op.set) {
    const attrs: Attrs = { ...op.set };
    resolveNodeRefs(work, attrs);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null) delete (next as unknown as Attrs)[k];
      else (next as unknown as Attrs)[k] = v;
    }
    if (typeof attrs.userTrustAttribute === 'string') {
      next.managedState = USER_TRUST_TO_MANAGED[attrs.userTrustAttribute as UserTrustAttribute];
    } else if (attrs.userTrustAttribute === null) {
      delete next.managedState;
    }
    const setKeys = Object.keys(attrs).filter((k) => attrs[k] !== null && k !== 'label' && k !== 'description');
    const nodes = work.layer.nodes.map((n) => (n.id === id ? next : n));
    validateNodeAttrs({ ...work, layer: { ...work.layer, nodes } }, next, setKeys);
  }

  if (op.boundaryId !== undefined) {
    if (next.parentId !== undefined) {
      fail(`ノード ${id} は他のノードに内包されているため、境界へ再配置できません`);
    }
    const target = op.boundaryId === null ? null : resolveId(work, op.boundaryId);
    const placed = placeNode(work.layer, next.type, target, id);
    next = { ...next, x: placed.x, y: placed.y };
    if (placed.expandedBoundary && target !== null) expandBoundary(work, target, placed.expandedBoundary);
  }

  work.layer.nodes = work.layer.nodes.map((n) => (n.id === id ? next : n));
  return id;
}

/** `deleteNode`（diagramStore）と同じ解除に加え、接続エッジも除く（理由は報告参照）。 */
function applyDeleteNode(work: Work, op: Extract<Operation, { op: 'delete_node' }>): string {
  const id = resolveId(work, op.id);
  findNode(work, id);
  const l = work.layer;
  l.nodes = l.nodes
    .filter((n) => n.id !== id)
    .map((n) => {
      if (n.parentId !== id && n.attackObjectiveId !== id && n.authProviderId !== id) return n;
      const rest = { ...n };
      if (rest.parentId === id) delete rest.parentId;
      if (rest.attackObjectiveId === id) delete rest.attackObjectiveId;
      if (rest.authProviderId === id) delete rest.authProviderId;
      return rest;
    });
  l.edges = l.edges
    .filter((e) => e.source !== id && e.target !== id)
    .map((e) => {
      if (e.authProviderId !== id) return e;
      const rest = { ...e };
      delete rest.authProviderId;
      return rest;
    });
  l.annotations = l.annotations.map((a) => {
    if (a.targetNodeId !== id) return a;
    const rest = { ...a };
    delete rest.targetNodeId;
    return rest;
  });
  return id;
}

function applyAddEdge(work: Work, op: Extract<Operation, { op: 'add_edge' }>): string {
  const source = resolveId(work, op.source);
  const target = resolveId(work, op.target);
  findNode(work, source);
  findNode(work, target);
  if (source === target) fail('source と target に同じノードは指定できません');
  let authProviderId: string | undefined;
  if (op.authProviderId !== undefined) {
    authProviderId = resolveId(work, op.authProviderId);
    checkAuthProvider(work, authProviderId);
  }
  const seq = work.counters.edge + 1;
  const id = nextId('e');
  const edge: DiagramEdge = {
    id,
    seq,
    source,
    target,
    auth: op.auth,
    network: op.network,
    encryption: op.encryption,
    dataFlow: op.dataFlow ?? 'outbound',
    ...(op.dataFlowName !== undefined ? { dataFlowName: op.dataFlowName } : {}),
    ...(op.semantic !== undefined ? { semantic: op.semantic } : {}),
    ...(authProviderId !== undefined ? { authProviderId } : {}),
  };
  work.layer.edges.push(edge);
  work.counters.edge = seq;
  registerRef(work, op.ref, id);
  return id;
}

function applyUpdateEdge(work: Work, op: Extract<Operation, { op: 'update_edge' }>): string {
  failIfEmptySet(op.set);
  const id = resolveId(work, op.id);
  const current = work.layer.edges.find((e) => e.id === id) ?? fail(`エッジ ${id} が存在しません`);
  const next: DiagramEdge = { ...current };
  const attrs: Attrs = { ...op.set };
  if (typeof attrs.authProviderId === 'string') {
    attrs.authProviderId = resolveId(work, attrs.authProviderId);
    checkAuthProvider(work, attrs.authProviderId as string);
  }
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null) delete (next as unknown as Attrs)[k];
    else (next as unknown as Attrs)[k] = v;
  }
  work.layer.edges = work.layer.edges.map((e) => (e.id === id ? next : e));
  return id;
}

function applyDeleteEdge(work: Work, op: Extract<Operation, { op: 'delete_edge' }>): string {
  const id = resolveId(work, op.id);
  if (!work.layer.edges.some((e) => e.id === id)) fail(`エッジ ${id} が存在しません`);
  work.layer.edges = work.layer.edges.filter((e) => e.id !== id);
  return id;
}

/** 境界の型ごとに設定できる属性。 */
const BOUNDARY_ATTRS_BY_TYPE: Record<BoundaryTypeId, readonly string[]> = {
  RECT: [],
  RECT_DASHED: [],
  ROUNDED: ['macroTrust', 'vlanName', 'vlanId', 'networkAddress'],
  ROUNDED_DASHED: ['microTrust', 'microSegmentationStatus', 'sensitiveData'],
  BLAST_RADIUS: ['blastRadiusLabel'],
};
const ALL_BOUNDARY_ATTRS = Object.values(BOUNDARY_ATTRS_BY_TYPE).flat();

/** UI（BoundaryPanel）と同じ規則で型から信頼レベルを決める。RECT のみ指定値を採用する。 */
function deriveTrustLevel(b: DiagramBoundary, given: TrustLevel | undefined): TrustLevel {
  let derived: TrustLevel;
  switch (b.type) {
    case 'RECT':
      return given ?? b.trustLevel;
    case 'RECT_DASHED':
      derived = 'Internet';
      break;
    case 'ROUNDED':
      derived = MACRO_TRUST_TO_TRUST_LEVEL[b.macroTrust ?? 'Office Area'];
      break;
    case 'ROUNDED_DASHED':
      derived = MICRO_TRUST_TO_TRUST_LEVEL[b.microTrust ?? 'Production'];
      break;
    default:
      derived = 'Internal';
  }
  if (given !== undefined && given !== derived) {
    fail(`型 ${b.type} の trustLevel は ${derived} に固定されています（${given} は指定できません）`);
  }
  return derived;
}

function checkBoundaryAttrKeys(type: BoundaryTypeId, keys: readonly string[]): void {
  const allowed = BOUNDARY_ATTRS_BY_TYPE[type];
  for (const k of keys) {
    if (ALL_BOUNDARY_ATTRS.includes(k) && !allowed.includes(k)) {
      fail(`属性 ${k} は境界の型 ${type} には設定できません`);
    }
  }
}

function applyAddBoundary(work: Work, op: Extract<Operation, { op: 'add_boundary' }>): string {
  const { op: _op, ref, type, trustLevel, around, ...rest } = op;
  const attrs = pickDefined(rest);
  checkBoundaryAttrKeys(type, Object.keys(attrs));
  const rect = around
    ? boundaryAround(work.layer, around.map((id) => resolveId(work, id)))
    : emptyBoundaryRect(work.layer);

  // 型ごとの既定値は diagramStore.addBoundary と同じ。
  const defaults: Attrs =
    type === 'ROUNDED'
      ? { macroTrust: 'Office Area' }
      : type === 'ROUNDED_DASHED'
        ? { microTrust: 'Production', microSegmentationStatus: '未適用', sensitiveData: '無し' }
        : {};
  const seq = work.counters.boundary + 1;
  const id = nextId('b');
  const base = { id, seq, type, ...rect, trustLevel: 'Internal' as TrustLevel, ...defaults, ...attrs } as DiagramBoundary;
  const boundary: DiagramBoundary = { ...base, trustLevel: deriveTrustLevel(base, trustLevel) };
  work.layer.boundaries.push(boundary);
  work.counters.boundary = seq;
  registerRef(work, ref, id);
  return id;
}

function applyUpdateBoundary(work: Work, op: Extract<Operation, { op: 'update_boundary' }>): string {
  failIfEmptySet(op.set);
  const id = resolveId(work, op.id);
  const current = findBoundary(work, id);
  const { trustLevel, ...attrs } = op.set;
  checkBoundaryAttrKeys(current.type, Object.keys(attrs));
  const next = { ...current } as DiagramBoundary;
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null) delete (next as unknown as Attrs)[k];
    else (next as unknown as Attrs)[k] = v;
  }
  next.trustLevel = deriveTrustLevel(next, trustLevel);
  work.layer.boundaries = work.layer.boundaries.map((b) => (b.id === id ? next : b));
  return id;
}

function applyDeleteBoundary(work: Work, op: Extract<Operation, { op: 'delete_boundary' }>): string {
  const id = resolveId(work, op.id);
  findBoundary(work, id);
  work.layer.boundaries = work.layer.boundaries.filter((b) => b.id !== id);
  return id;
}

function applyAddAnnotation(work: Work, op: Extract<Operation, { op: 'add_annotation' }>): string {
  const targetNodeId = op.targetNodeId === undefined ? undefined : resolveId(work, op.targetNodeId);
  if (targetNodeId !== undefined) {
    if (op.kind !== 'callout') fail('targetNodeId は kind が callout のときだけ指定できます');
    findNode(work, targetNodeId);
  }
  const { x, y } = placeAnnotation(work.layer, targetNodeId);
  const id = nextId('ann');
  const annotation: DiagramAnnotation = {
    id,
    kind: op.kind,
    x,
    y,
    text: op.text,
    ...(targetNodeId !== undefined ? { targetNodeId } : {}),
  };
  work.layer.annotations.push(annotation);
  return id;
}

function applyOne(work: Work, op: Operation): string {
  switch (op.op) {
    case 'add_node':
      return applyAddNode(work, op);
    case 'update_node':
      return applyUpdateNode(work, op);
    case 'delete_node':
      return applyDeleteNode(work, op);
    case 'add_edge':
      return applyAddEdge(work, op);
    case 'update_edge':
      return applyUpdateEdge(work, op);
    case 'delete_edge':
      return applyDeleteEdge(work, op);
    case 'add_boundary':
      return applyAddBoundary(work, op);
    case 'update_boundary':
      return applyUpdateBoundary(work, op);
    case 'delete_boundary':
      return applyDeleteBoundary(work, op);
    case 'add_annotation':
      return applyAddAnnotation(work, op);
  }
}

/**
 * プロジェクト JSON（`raw`）の `layer` に構成変更 `ops` を適用し、新しいプロジェクトを返す。
 *
 * - 失敗時（入力不正・操作不正・配置不能・適用後の再検証失敗）は `McpOperationError` を throw し、
 *   何も返さない（全体が失敗）。入力 `raw` は変更しない。
 * - 判断系フィールドと対象外レイヤーは `deserializeProject` の結果をそのまま引き継ぐ。
 *   `updatedAt` のみ更新する。
 */
export function applyOperations(
  raw: unknown,
  layer: LayerKey,
  ops: unknown[],
): { project: PersistedProject; results: OperationResult[] } {
  if (!LAYER_KEYS.includes(layer)) throw new McpOperationError(-1, `不正なレイヤー ${String(layer)} です`);
  if (!Array.isArray(ops)) throw new McpOperationError(-1, 'operations は配列である必要があります');
  if (ops.length === 0) throw new McpOperationError(-1, 'operations が空です');
  if (ops.length > MAX_OPERATIONS) {
    throw new McpOperationError(-1, `operations は ${MAX_OPERATIONS} 件までです`);
  }
  const loaded = deserializeProject(raw);
  if (!loaded) {
    throw new McpOperationError(-1, 'プロジェクト JSON の形式が不正です（スキーマ検証に失敗しました）');
  }

  // 先に全操作をスキーマ検証する（座標・id 等の未許可フィールドはここで拒否される）。
  const parsed = ops.map((op, index) => {
    const r = OperationSchema.safeParse(op);
    if (!r.success) {
      const reason = r.error.issues
        .map((i) => (i.path.length > 0 ? `${i.path.join('.')}: ${i.message}` : i.message))
        .join('; ');
      throw new McpOperationError(index, reason);
    }
    return r.data;
  });

  const resolved = resolveLayers(loaded);
  const counted = resolveIdCounters(resolved.layers, loaded.idCounters);
  const source = counted.layers[layer];
  const work: Work = {
    layer: {
      nodes: [...source.nodes],
      edges: [...source.edges],
      boundaries: [...source.boundaries],
      annotations: [...source.annotations],
    },
    counters: { ...counted.idCounters[layer] },
    refs: new Map(),
  };

  const results: OperationResult[] = [];
  parsed.forEach((op, index) => {
    try {
      results.push({ index, op: op.op, id: applyOne(work, op) });
    } catch (e) {
      if (e instanceof McpOperationError) throw e;
      if (e instanceof Error) throw new McpOperationError(index, e.message);
      throw e;
    }
  });

  const baseLayers = loaded.layers ?? resolved.layers;
  const project: PersistedProject = {
    ...loaded,
    layers: { ...baseLayers, [layer]: work.layer } as NonNullable<PersistedProject['layers']>,
    idCounters: {
      ...(loaded.idCounters ?? counted.idCounters),
      [layer]: work.counters,
    } as NonNullable<PersistedProject['idCounters']>,
    updatedAt: Date.now(),
  };
  if (!loaded.layers) {
    // 旧形式（トップレベル nodes/edges/boundaries）は layers へ移行済みなので残さない。
    delete project.nodes;
    delete project.edges;
    delete project.boundaries;
  }

  if (!deserializeProject(project)) {
    throw new McpOperationError(-1, '適用後のプロジェクトがスキーマ検証に失敗しました（変更は破棄されます）');
  }
  return { project, results };
}
