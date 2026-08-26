import type { DiagramEdge, DiagramNode } from '../../core/model/types';

/** 1 パスあたりの最大ホップ数（経路爆発の抑止）。 */
export const MAX_PATH_LENGTH = 8;
/** 列挙するパスの最大本数（経路爆発の抑止）。 */
export const MAX_PATHS = 50;

/**
 * 無向正規化した論理ホップ。並行エッジ（同一ノード対を結ぶ複数チャネル）は
 * 1 本の LogicalHop に畳み込まれ、経由した edgeId を edgeIds に蓄積する。
 */
export interface LogicalHop {
  key: string;
  /** ソート後の小さい方の nodeId。 */
  a: string;
  /** ソート後の大きい方の nodeId。 */
  b: string;
  /** このホップを構成する並行エッジ（DF）の id（重複排除、出現順）。 */
  edgeIds: string[];
}

/** 攻撃者→標的のノード列（チャネル選択を含まない）。 */
export interface AttackRoute {
  nodeIds: string[];
  /** 通過する論理ホップ key（nodeIds.length - 1 本）。 */
  hopKeys: string[];
}

export interface AttackGraphResult {
  /** いずれかの経路に現れる全ノード（初出順、攻撃者が先頭）。 */
  nodeIds: string[];
  hops: Map<string, LogicalHop>;
  /** ノード列で重複排除済みの経路。 */
  routes: AttackRoute[];
  /** 列挙した生パス本数（チャネル組合せ数。旧 pathCount 相当）。 */
  channelCombinations: number;
  /** 探索上限（深さ / パス数）で一部省略した場合 true。 */
  truncated: boolean;
}

/** 無向正規化キー `${小}--${大}`（両端 nodeId を文字列比較でソート）。 */
function hopKey(a: string, b: string): string {
  return a < b ? `${a}--${b}` : `${b}--${a}`;
}

/**
 * 攻撃者ノードから標的ノードまでの全単純パスをエッジ集合から列挙し、
 * ノード列ベースの経路（AttackRoute）と、並行エッジを畳み込んだ論理ホップ
 * （LogicalHop）へ変換する純粋関数。
 *
 * DFS 単純パス列挙は buildAttackTree.ts と同一ロジック（エッジは無向として辿る、
 * dangling エッジ無視、同一ノード再訪なし。上限は MAX_PATH_LENGTH / MAX_PATHS を共有）。
 * 列挙後、同一ノード列に射影される生パスを 1 本の AttackRoute へ重複排除し、
 * 隣接ノード対ごとに LogicalHop へ経由 edgeId を集約する。
 */
export function buildAttackGraph(
  nodes: readonly DiagramNode[],
  edges: readonly DiagramEdge[],
  attackerId: string,
  targetId: string,
): AttackGraphResult {
  const nodeIdSet = new Set(nodes.map((n) => n.id));
  if (!nodeIdSet.has(attackerId) || !nodeIdSet.has(targetId) || attackerId === targetId) {
    return { nodeIds: [], hops: new Map(), routes: [], channelCombinations: 0, truncated: false };
  }

  // 無向の隣接リスト（dangling エッジは無視）
  const adj = new Map<string, { nodeId: string; edgeId: string }[]>();
  const addAdj = (from: string, to: string, edgeId: string) => {
    if (!nodeIdSet.has(from) || !nodeIdSet.has(to)) return;
    const arr = adj.get(from) ?? [];
    arr.push({ nodeId: to, edgeId });
    adj.set(from, arr);
  };
  for (const e of edges) {
    addAdj(e.source, e.target, e.id);
    addAdj(e.target, e.source, e.id);
  }

  // DFS で単純パスを列挙（buildAttackTree.ts と同一ロジック）
  const paths: { nodeId: string; edgeId: string }[][] = [];
  let truncated = false;
  const visited = new Set<string>([attackerId]);
  const current: { nodeId: string; edgeId: string }[] = [];

  const dfs = (at: string) => {
    if (at === targetId) {
      if (paths.length < MAX_PATHS) paths.push([...current]);
      else truncated = true;
      return;
    }
    if (current.length >= MAX_PATH_LENGTH) {
      if ((adj.get(at) ?? []).some((n) => !visited.has(n.nodeId))) truncated = true;
      return;
    }
    for (const next of adj.get(at) ?? []) {
      if (visited.has(next.nodeId)) continue;
      if (paths.length >= MAX_PATHS) {
        truncated = true;
        return;
      }
      visited.add(next.nodeId);
      current.push(next);
      dfs(next.nodeId);
      current.pop();
      visited.delete(next.nodeId);
    }
  };
  dfs(attackerId);

  // 生パスをノード列へ射影し、経路の重複排除とホップ畳み込みを行う
  const hops = new Map<string, LogicalHop>();
  const routeByKey = new Map<string, AttackRoute>();
  const nodeIdsOut: string[] = [];
  const seenNodeIds = new Set<string>();
  const addNodeId = (id: string) => {
    if (!seenNodeIds.has(id)) {
      seenNodeIds.add(id);
      nodeIdsOut.push(id);
    }
  };
  addNodeId(attackerId);

  for (const path of paths) {
    const nodeSeq = [attackerId, ...path.map((step) => step.nodeId)];
    for (const id of nodeSeq) addNodeId(id);

    const hopKeys: string[] = [];
    for (let i = 0; i < path.length; i++) {
      const a = nodeSeq[i];
      const b = nodeSeq[i + 1];
      const key = hopKey(a, b);
      hopKeys.push(key);
      let hop = hops.get(key);
      if (!hop) {
        const [small, large] = a < b ? [a, b] : [b, a];
        hop = { key, a: small, b: large, edgeIds: [] };
        hops.set(key, hop);
      }
      if (!hop.edgeIds.includes(path[i].edgeId)) hop.edgeIds.push(path[i].edgeId);
    }

    const routeKey = nodeSeq.join('->');
    if (!routeByKey.has(routeKey)) {
      routeByKey.set(routeKey, { nodeIds: nodeSeq, hopKeys });
    }
  }

  return {
    nodeIds: nodeIdsOut,
    hops,
    routes: [...routeByKey.values()],
    channelCombinations: paths.length,
    truncated,
  };
}
