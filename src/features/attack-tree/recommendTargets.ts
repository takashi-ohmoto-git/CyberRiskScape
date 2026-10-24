import type {
  ComponentTypeId,
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  NodePosture,
  Severity,
  ThreatView,
} from '../../core/model/types';
import { ATTACK_OBJECTIVE_APPLICABLE, isSuppressed } from '../../core/model/types';
import { buildAttackGraph } from './buildAttackGraph';
import { analyzeAttackGraph } from './analyzeAttackGraph';
import { buildHopEvidence, NEUTRAL_EVIDENCE, type HopCoverage, type HopEvidence } from './hopEvidence';
import { buildEntryEdges, ENTRY_SEARCH_APPLICABLE, findEntryPoints } from './findEntryPoints';

/**
 * 守る側が優先して保護する標的の推奨。エージェント型の攻撃ツールの悪用を前提に、
 * 「取られると被害が大きい・次の侵入を開く」資産を図から挙げ、対策立案の起点にする。
 * これは利用者自身の構成図に対する推奨で、攻撃の手順は出さない。
 */

/**
 * 認証系の標的になる型。取られると別のノードへのログイン・API 呼び出し・配布を開く、
 * 認証材料を集める／発行する／管理する基盤（防御側が「枝を開くノード」として先に守る）。
 */
const CREDENTIAL_HOLDER_TYPES: ReadonlySet<ComponentTypeId> = new Set([
  'IDENTITY_PROVIDER',
  'DIRECTORY',
  'PAM',
  'IGA',
  'SECRETS_VAULT',
  'HSM',
  'CI_PIPELINE',
  'API_CONTROL_PLANE',
  'API_DEV_WORKSPACE',
  'MCP_SERVER',
]);

/** データ系の標的とみなす機微データ資産の型（保護対象として優先度が高いもの）。 */
const SENSITIVE_DATA_TYPES: ReadonlySet<ComponentTypeId> = new Set([
  'PERSONAL_INFO',
  'CONFIDENTIAL_INFO',
  'SOURCE_CODE',
  'VOICE_RECORDING',
]);

/** 標的の候補にしない型（攻撃する側・利用者の端末・図の外の主体）。 */
const NON_TARGET_TYPES: ReadonlySet<ComponentTypeId> = new Set([
  'USER',
  'PC',
  'SMARTPHONE',
  'EXTERNAL_ENTITY',
]);

const SEVERITY_ORDER: Record<Severity, number> = { Low: 1, Medium: 2, High: 3, Critical: 4 };
const VOLUME_ORDER: Record<NonNullable<NodePosture['recordVolume']>, number> = {
  Under1K: 1,
  Under100K: 2,
  Under1M: 3,
  Over1M: 4,
};

/** 標的として推奨する理由。 */
export type TargetReason =
  /** 認証材料を集める／発行する基盤（取られると次の侵入を開く）。 */
  | 'credentialHolder'
  /** 機微データ資産を保持する。 */
  | 'sensitiveData'
  /** 大量の件数を保持する（取られたときの影響が大きい）。 */
  | 'highVolume';

/** 推奨の種別。認証系はデータ系より先に提示する（次の侵入を開く起点のため）。 */
export type TargetCategory = 'credential' | 'data';

export interface TargetRecommendation {
  nodeId: string;
  /** 1 始まりの順位。 */
  rank: number;
  category: TargetCategory;
  reasons: TargetReason[];
  /** このノード（と内包する資産）のアクティブな脅威の件数。 */
  threatCount: number;
  maxSeverity?: Severity;
  /** 自身・内包する資産の件数規模のうち最大。 */
  recordVolume?: NonNullable<NodePosture['recordVolume']>;
  /** 攻撃者から（侵入候補の仮想の線を含めて）到達できるか。 */
  reachable: boolean;
}

const CATEGORY_ORDER: Record<TargetCategory, number> = { credential: 0, data: 1 };

/** 無向隣接（図の線＋侵入候補の仮想の線）から攻撃者が到達できるノード集合を BFS で求める。 */
function reachableFrom(attackerId: string, edges: readonly DiagramEdge[]): Set<string> {
  const adj = new Map<string, string[]>();
  const add = (a: string, b: string) => {
    const arr = adj.get(a);
    if (arr) arr.push(b);
    else adj.set(a, [b]);
  };
  for (const e of edges) {
    add(e.source, e.target);
    add(e.target, e.source);
  }
  const seen = new Set<string>([attackerId]);
  const queue = [attackerId];
  while (queue.length > 0) {
    const cur = queue.shift()!;
    for (const next of adj.get(cur) ?? []) {
      if (!seen.has(next)) {
        seen.add(next);
        queue.push(next);
      }
    }
  }
  return seen;
}

/**
 * 守る側が優先して保護する標的を、優先度の高い順に推奨する純粋関数。
 *
 * トップレベルのノードのうち、次のいずれかを候補にする（内包する資産は親で集約）。
 * - 認証材料を集める／発行する基盤（CREDENTIAL_HOLDER_TYPES）
 * - 機微データ資産を保持する（自身がその型、または内包する子にその型がある）
 *
 * 順位は、攻撃者から到達できるもの → 認証系（次の侵入を開く）→ 脅威の最大重大度 →
 * 件数規模 → 脅威の件数 → 連番の順。攻撃者が対象外の型なら空配列。
 */
export function recommendTargets(
  nodes: readonly DiagramNode[],
  edges: readonly DiagramEdge[],
  boundaries: readonly DiagramBoundary[],
  threats: readonly ThreatView[],
  attackerId: string,
): TargetRecommendation[] {
  const attacker = nodes.find((n) => n.id === attackerId);
  if (!attacker || !ENTRY_SEARCH_APPLICABLE.has(attacker.type)) return [];

  const entryEdges = buildEntryEdges(attackerId, findEntryPoints(nodes, edges, boundaries, threats, attackerId));
  const reachable = reachableFrom(attackerId, [...edges, ...entryEdges]);
  const childrenOf = new Map<string, DiagramNode[]>();
  for (const n of nodes) {
    if (!n.parentId) continue;
    const arr = childrenOf.get(n.parentId);
    if (arr) arr.push(n);
    else childrenOf.set(n.parentId, [n]);
  }
  const ids = new Set(nodes.map((n) => n.id));

  const out: Omit<TargetRecommendation, 'rank'>[] = [];
  for (const n of nodes) {
    if (n.parentId && ids.has(n.parentId)) continue;
    if (ATTACK_OBJECTIVE_APPLICABLE.has(n.type) || NON_TARGET_TYPES.has(n.type)) continue;

    const children = childrenOf.get(n.id) ?? [];
    const reasons: TargetReason[] = [];
    const isCredential = CREDENTIAL_HOLDER_TYPES.has(n.type);
    if (isCredential) reasons.push('credentialHolder');
    const hasSensitive =
      SENSITIVE_DATA_TYPES.has(n.type) || children.some((c) => SENSITIVE_DATA_TYPES.has(c.type));
    if (hasSensitive) reasons.push('sensitiveData');

    // 件数規模は自身・内包する資産のうち最大。
    let recordVolume: NonNullable<NodePosture['recordVolume']> | undefined;
    for (const m of [n, ...children]) {
      const v = m.posture?.recordVolume;
      if (v && (!recordVolume || VOLUME_ORDER[v] > VOLUME_ORDER[recordVolume])) recordVolume = v;
    }
    if (hasSensitive && recordVolume && VOLUME_ORDER[recordVolume] >= VOLUME_ORDER.Under1M) {
      reasons.push('highVolume');
    }

    if (reasons.length === 0) continue;

    const childIds = new Set(children.map((c) => c.id));
    const active = threats.filter((t) => !isSuppressed(t) && (t.nodeId === n.id || childIds.has(t.nodeId)));
    const maxSeverity = active.reduce<Severity | undefined>(
      (max, t) => (!max || SEVERITY_ORDER[t.severity] > SEVERITY_ORDER[max] ? t.severity : max),
      undefined,
    );
    out.push({
      nodeId: n.id,
      category: isCredential ? 'credential' : 'data',
      reasons,
      threatCount: active.length,
      maxSeverity,
      recordVolume,
      reachable: reachable.has(n.id),
    });
  }

  const seqOf = new Map(nodes.map((n) => [n.id, n.seq ?? Number.MAX_SAFE_INTEGER]));
  out.sort(
    (a, b) =>
      Number(b.reachable) - Number(a.reachable) ||
      CATEGORY_ORDER[a.category] - CATEGORY_ORDER[b.category] ||
      (b.maxSeverity ? SEVERITY_ORDER[b.maxSeverity] : 0) - (a.maxSeverity ? SEVERITY_ORDER[a.maxSeverity] : 0) ||
      (b.recordVolume ? VOLUME_ORDER[b.recordVolume] : 0) - (a.recordVolume ? VOLUME_ORDER[a.recordVolume] : 0) ||
      b.threatCount - a.threatCount ||
      (seqOf.get(a.nodeId) ?? 0) - (seqOf.get(b.nodeId) ?? 0),
  );
  return out.map((r, i) => ({ ...r, rank: i + 1 }));
}

/** 優先的に守るべき要素（複数の標的の経路に共通して現れるチョークポイント）1 件。 */
export interface PriorityDefense {
  /** `node:<nodeId>` または `hop:<hopKey>`。 */
  elementKey: string;
  /** この要素を経路に含む推奨標的の数（多いほど 1 つの対策で多くの標的を守れる）。 */
  targetHits: number;
  /** その要素の対策被覆度（最も弱いもの）。 */
  coverage: HopCoverage;
}

const COVERAGE_RANK: Record<HopCoverage, number> = { none: 0, partial: 1, full: 2 };

/**
 * 推奨標的（到達できるもの）の攻撃経路を標的ごとに求め、経路に共通して現れる
 * チョークポイントを集計する純粋関数。多くの標的の経路に載る要素ほど、1 つの対策で
 * 多くの被害を止められる＝優先的に守るべき経路になる。
 *
 * 侵入候補の仮想の線（P2 と同じ `buildEntryEdges`）を使うので、攻撃者からの線を
 * 手で引いていなくても集計できる。
 */
export function aggregatePriorityDefenses(
  nodes: readonly DiagramNode[],
  edges: readonly DiagramEdge[],
  boundaries: readonly DiagramBoundary[],
  threats: readonly ThreatView[],
  attackerId: string,
  recommendations: readonly TargetRecommendation[],
): PriorityDefense[] {
  const attacker = nodes.find((n) => n.id === attackerId);
  if (!attacker || !ENTRY_SEARCH_APPLICABLE.has(attacker.type)) return [];

  const entryEdges = buildEntryEdges(attackerId, findEntryPoints(nodes, edges, boundaries, threats, attackerId));
  const analysisEdges = [...edges, ...entryEdges];
  const evidenceMap = buildHopEvidence(threats);
  const getEvidence = (key: string): HopEvidence => evidenceMap.get(key) ?? NEUTRAL_EVIDENCE;

  const targetHits = new Map<string, number>();
  const worstCoverage = new Map<string, HopCoverage>();
  for (const rec of recommendations) {
    if (!rec.reachable) continue;
    const graph = buildAttackGraph(nodes, analysisEdges, attackerId, rec.nodeId);
    if (graph.routes.length === 0) continue;
    const analysis = analyzeAttackGraph(graph, getEvidence);
    // この標的への経路に現れた要素を 1 回だけ数える（標的単位の重複を除く）。
    const seen = new Set<string>();
    for (const cp of analysis.chokePoints) {
      if (seen.has(cp.elementKey)) continue;
      seen.add(cp.elementKey);
      // 推奨標的そのもの（終点）は守る対象であって経由点ではないので除く。
      if (cp.elementKey === `node:${rec.nodeId}`) continue;
      targetHits.set(cp.elementKey, (targetHits.get(cp.elementKey) ?? 0) + 1);
      const cur = worstCoverage.get(cp.elementKey);
      if (cur === undefined || COVERAGE_RANK[cp.coverage] < COVERAGE_RANK[cur]) {
        worstCoverage.set(cp.elementKey, cp.coverage);
      }
    }
  }

  const defenses: PriorityDefense[] = [...targetHits].map(([elementKey, hits]) => ({
    elementKey,
    targetHits: hits,
    coverage: worstCoverage.get(elementKey) ?? 'none',
  }));
  defenses.sort(
    (a, b) => b.targetHits - a.targetHits || COVERAGE_RANK[a.coverage] - COVERAGE_RANK[b.coverage],
  );
  return defenses;
}
