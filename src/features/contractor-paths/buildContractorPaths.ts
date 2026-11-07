import { formatElementalId } from '../../core/model/elementalId';
import type {
  AuthType,
  ComponentTypeId,
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  LayerKey,
  NetworkType,
  ProjectMeta,
  Severity,
  ThreatView,
} from '../../core/model/types';
import {
  ATTACK_OBJECTIVE_APPLICABLE,
  ATTACK_SURFACE_APPLICABLE,
  ATTACK_SURFACE_KEYS_BY_TYPE,
  isSuppressed,
  type AttackSurfaceKey,
} from '../../core/model/types';
import { resolveNodeTrust } from '../../core/threat-engine/resolveNodeTrust';
import { reachableFrom } from '../attack-tree/recommendTargets';
import { BRANDING } from '../../core/branding';
import type { Locale } from '../../i18n';

/**
 * 委託先の接続経路の一覧（国家サイバー統括室の注意喚起への対応）。
 *
 * 委託先の判別はヒューリスティックで、行は「確認すべき候補」。委託先の評価はしない。
 * 識別の根拠は次の 3 つ（複数当たり得る。行ごとに根拠を示す）：
 * - userAttr：USER ノードの信頼区分が Contractor / Partner
 * - externalToGateway：外部組織（EXTERNAL_ENTITY・インターネット境界の利用者端末）から接続口（VPN/GW/踏み台/ZTNA）への線
 * - remoteMaintenance：外部から管理・リモート保守の終端型への線。線にはポートの項目が無いため、
 *   終端の型（管理面）とその攻撃面属性（リモートアクセス制限・送信元 IP 制限）で近似する
 * 未入力の属性は「対策なし」と同じに扱う（大方針）。
 */

export type ContractorBasis = 'userAttr' | 'externalToGateway' | 'remoteMaintenance';

/** 接続口（経由点）になる型。 */
export const GATEWAY_TYPES: ReadonlySet<ComponentTypeId> = new Set(['VPN_GATEWAY', 'GATEWAY', 'BASTION', 'ZTNA_PROXY']);

/** リモート保守・管理面の終端になる型。 */
export const REMOTE_MAINTENANCE_TYPES: ReadonlySet<ComponentTypeId> = new Set([
  'BASTION',
  'ADMIN_CONSOLE',
  'API_CONTROL_PLANE',
  'VPN_GATEWAY',
  'HYPERVISOR',
  'PAM',
]);

/** 外部組織側の端末・主体になる型。 */
const EXTERNAL_ORIGIN_TYPES: ReadonlySet<ComponentTypeId> = new Set(['EXTERNAL_ENTITY', 'USER', 'PC', 'SMARTPHONE']);

/** 到達できると影響が大きいデータ系の型。 */
const DATA_TYPES: ReadonlySet<ComponentTypeId> = new Set([
  'PERSONAL_INFO',
  'CONFIDENTIAL_INFO',
  'SOURCE_CODE',
  'VOICE_RECORDING',
  'DB',
  'DATABASE',
  'FILE_SERVER',
]);

/** MFA 相当の認証（多要素・パスキー・証明書）。パスワード・API キー・トークン単独は含まない。 */
const MFA_EQUIVALENT: ReadonlySet<AuthType> = new Set(['MFA', 'Passkey', 'Certificate']);

/** CISA ZTMM v2 の段階（edgeNotation.ts の CROSSING_AUTH_COLORS と同じ割り当て）。 */
export type ZtmmStage = 'None' | 'Traditional' | 'Initial' | 'Advanced';
const ZTMM_BY_AUTH: Record<AuthType, ZtmmStage> = {
  None: 'None',
  Password: 'Traditional',
  ApiKey: 'Traditional',
  MFA: 'Traditional',
  Token: 'Initial',
  Passkey: 'Advanced',
  Certificate: 'Advanced',
};

/** yes=有り / no=無し / unset=未入力（対策なしと同じ扱い）/ na=その型に項目が無い。 */
export type RestrictionState = 'yes' | 'no' | 'unset' | 'na';

export type RankReason = 'notMfa' | 'sensitiveReach' | 'weakRestrictions';

export interface PathThreat {
  nodeId: string;
  name: string;
  severity: Severity;
  canonicalId?: string;
}

export interface ContractorPathRow {
  rank: number;
  /** 順位の理由コード（出力側で文言にする）。 */
  reasons: RankReason[];
  bases: ContractorBasis[];
  fromId: string;
  fromLabel: string;
  fromType: string;
  /** 経由点（接続口）。接続口を経由しない行は null。 */
  viaId: string | null;
  viaLabel: string | null;
  /** 接続先。接続口の先に線が無い場合は null。 */
  toId: string | null;
  toLabel: string | null;
  edgeId: string;
  network: NetworkType;
  auth: AuthType;
  ztmm: ZtmmStage;
  mfaEquivalent: boolean;
  /** 入口側ノード（接続口または直接の接続先）の対策。unset と no は「対策なし」として数える。 */
  sourceIpRestriction: RestrictionState;
  remoteAccessRestriction: RestrictionState;
  accessLog: RestrictionState;
  /** ログ送信先（logSinkId）のノード表示名。未設定は null。 */
  logSink: string | null;
  /** 入口から到達できるデータ系ノード。 */
  reachableData: { id: string; label: string }[];
  threats: PathThreat[];
  /** 対策なし（no・unset）の項目数。 */
  weakCount: number;
}

export interface ContractorPaths {
  system: string;
  layer: LayerKey;
  generatedAt: string;
  product: string;
  locale: Locale;
  rows: ContractorPathRow[];
}

export interface ContractorPathsInput {
  threats: ThreatView[];
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  boundaries: DiagramBoundary[];
  projectMeta: ProjectMeta;
  layer: LayerKey;
}

const SEVERITY_ORDER: Record<Severity, number> = { Low: 1, Medium: 2, High: 3, Critical: 4 };

const nodeName = (n: DiagramNode): string =>
  `${n.seq != null ? `${formatElementalId('node', n.seq)} ` : ''}${n.label?.trim() || n.type}`;

/** 攻撃面属性の 1 項目の状態。その型が入力できない項目は na。 */
function surfaceState(node: DiagramNode, key: AttackSurfaceKey): RestrictionState {
  if (!ATTACK_SURFACE_APPLICABLE.has(node.type)) return 'na';
  const keys = ATTACK_SURFACE_KEYS_BY_TYPE[node.type];
  if (keys && !keys.includes(key)) return 'na';
  const v = node.attackSurface?.[key];
  return v === true ? 'yes' : v === false ? 'no' : 'unset';
}

/** 線の (起点, 終点)。dataFlow が inbound なら source 側が受ける側＝起点は target。 */
function orient(e: DiagramEdge): { from: string; to: string } {
  return e.dataFlow === 'inbound' ? { from: e.target, to: e.source } : { from: e.source, to: e.target };
}

/** 委託先の接続経路を列挙し、MFA 切り替えの優先順に並べる純粋関数。 */
export function buildContractorPaths(input: ContractorPathsInput, now: Date, locale: Locale = 'ja'): ContractorPaths {
  const { nodes, edges, boundaries, threats } = input;
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const trust = resolveNodeTrust(nodes, boundaries);

  /** 外部組織側とみなせる起点か（EXTERNAL_ENTITY、またはインターネット境界の利用者端末）。 */
  const isExternal = (n: DiagramNode): boolean =>
    !ATTACK_OBJECTIVE_APPLICABLE.has(n.type) &&
    EXTERNAL_ORIGIN_TYPES.has(n.type) &&
    (n.type === 'EXTERNAL_ENTITY' || trust.get(n.id) === 'Internet');

  const activeThreats = threats.filter((t) => !isSuppressed(t));
  const threatsOf = (ids: Set<string>, edgeIds: Set<string>): PathThreat[] => {
    const seen = new Set<string>();
    const out: PathThreat[] = [];
    for (const t of activeThreats) {
      const onEdge = t.subject?.kind === 'edge' && edgeIds.has(t.subject.id);
      if (!onEdge && !ids.has(t.nodeId)) continue;
      const name = t.name ?? t.category;
      const key = `${t.nodeId}|${t.canonicalId ?? name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ nodeId: t.nodeId, name, severity: t.severity, canonicalId: t.canonicalId });
    }
    return out.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
  };

  const reachableData = (originId: string): { id: string; label: string }[] => {
    const reach = reachableFrom(originId, edges);
    reach.delete(originId);
    const out: { id: string; label: string }[] = [];
    for (const n of nodes) {
      if (!DATA_TYPES.has(n.type)) continue;
      // 内包された子のデータ資産は、親に到達できれば到達とみなす
      if (reach.has(n.id) || (n.parentId && reach.has(n.parentId))) out.push({ id: n.id, label: nodeName(n) });
    }
    return out;
  };

  const rows: Omit<ContractorPathRow, 'rank' | 'reasons'>[] = [];
  const addRow = (first: DiagramEdge, second: DiagramEdge | null): void => {
    const o = byId.get(orient(first).from);
    const d = byId.get(orient(first).to);
    if (!o || !d || o.id === d.id) return;
    const isGateway = GATEWAY_TYPES.has(d.type);
    const toNode = second ? (byId.get(orient(second).to) ?? null) : isGateway ? null : d;
    const via = isGateway ? d : null;

    const bases: ContractorBasis[] = [];
    const isContractorUser =
      o.type === 'USER' && (o.userTrustAttribute === 'Contractor' || o.userTrustAttribute === 'Partner');
    if (isContractorUser) bases.push('userAttr');
    // API の GATEWAY は一般の利用者（会員等）も通るため、外部組織（EXTERNAL_ENTITY）からの線だけを数える。
    // VPN・踏み台・ZTNA は保守・業務の接続口なので、インターネット側の利用者端末からの線も数える。
    if (isExternal(o) && isGateway && (o.type === 'EXTERNAL_ENTITY' || d.type !== 'GATEWAY')) bases.push('externalToGateway');
    const maintTarget = [d, toNode].some((x) => x && REMOTE_MAINTENANCE_TYPES.has(x.type));
    if ((isExternal(o) || isContractorUser) && maintTarget) bases.push('remoteMaintenance');
    if (bases.length === 0) return;

    // 入口側（接続口、無ければ直接の接続先）の対策を見る
    const sourceIp = surfaceState(d, 'hasSourceIpRestriction');
    const remote = surfaceState(d, 'hasRemoteAccessRestriction');
    const log = surfaceState(d, 'hasAccessLog');
    const sink = d.logSinkId ? byId.get(d.logSinkId) : undefined;
    const weakCount = [sourceIp, remote, log].filter((s) => s === 'no' || s === 'unset').length;
    const ids = new Set([o.id, d.id, ...(toNode ? [toNode.id] : [])]);
    const edgeIds = new Set([first.id, ...(second ? [second.id] : [])]);

    rows.push({
      bases,
      fromId: o.id,
      fromLabel: nodeName(o),
      fromType: o.type,
      viaId: via?.id ?? null,
      viaLabel: via ? nodeName(via) : null,
      toId: toNode?.id ?? null,
      toLabel: toNode ? nodeName(toNode) : null,
      edgeId: first.id,
      network: first.network,
      auth: first.auth,
      ztmm: ZTMM_BY_AUTH[first.auth],
      mfaEquivalent: MFA_EQUIVALENT.has(first.auth),
      sourceIpRestriction: sourceIp,
      remoteAccessRestriction: remote,
      accessLog: log,
      logSink: sink ? nodeName(sink) : null,
      reachableData: reachableData(o.id),
      threats: threatsOf(ids, edgeIds),
      weakCount,
    });
  };

  for (const first of edges) {
    const { from, to } = orient(first);
    const d = byId.get(to);
    if (!byId.has(from) || !d) continue;
    if (GATEWAY_TYPES.has(d.type)) {
      // 接続口の先（接続口を起点とする別の線）ごとに 1 行。先が無ければ接続口で止まる 1 行
      const onward = edges.filter((e) => e.id !== first.id && orient(e).from === d.id && orient(e).to !== from);
      if (onward.length === 0) addRow(first, null);
      for (const second of onward) addRow(first, second);
    } else {
      addRow(first, null);
    }
  }

  const seqOf = (id: string) => byId.get(id)?.seq ?? Number.MAX_SAFE_INTEGER;
  rows.sort(
    (a, b) =>
      Number(a.mfaEquivalent) - Number(b.mfaEquivalent) ||
      b.reachableData.length - a.reachableData.length ||
      b.weakCount - a.weakCount ||
      seqOf(a.fromId) - seqOf(b.fromId) ||
      a.edgeId.localeCompare(b.edgeId),
  );

  return {
    system: input.projectMeta.systemName.trim() || input.projectMeta.name.trim() || BRANDING.name,
    layer: input.layer,
    generatedAt: now.toISOString().slice(0, 10),
    product: BRANDING.name,
    locale,
    rows: rows.map((r, i) => {
      const reasons: RankReason[] = [];
      if (!r.mfaEquivalent) reasons.push('notMfa');
      if (r.reachableData.length > 0) reasons.push('sensitiveReach');
      if (r.weakCount > 0) reasons.push('weakRestrictions');
      return { ...r, rank: i + 1, reasons };
    }),
  };
}
