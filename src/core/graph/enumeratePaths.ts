import type { DiagramEdge, DiagramNode } from '../model/types';

/** 1 パスあたりの最大ホップ数（経路爆発の抑止）。 */
export const MAX_PATH_LENGTH = 8;
/** 列挙するパスの最大本数（経路爆発の抑止）。 */
export const MAX_PATHS = 50;

export interface EnumeratedPath {
  /** 始点〜終点のノード id。 */
  nodeIds: string[];
  /** 通過した edge の id（nodeIds.length - 1 本）。 */
  edgeIds: string[];
}

export interface EnumeratePathsResult {
  paths: EnumeratedPath[];
  /** 探索上限（深さ / パス数）で一部省略した場合 true。 */
  truncated: boolean;
}

export interface EnumeratePathsOptions {
  /**
   * true なら edge を source → target の向きにだけ辿る（`dataFlow === 'bidirectional'` は両方向）。
   * 既定 false（無向）。
   */
  directed?: boolean;
  maxLength?: number;
  maxPaths?: number;
}

/**
 * 始点から終点までの全単純パス（同一ノード再訪なし）を DFS で列挙する純粋関数。
 * dangling edge（端点ノードが存在しない edge）は無視する。並行 edge は別パスとして列挙する。
 * 始点・終点が存在しない、または同一の場合は空を返す。
 */
export function enumeratePaths(
  nodes: readonly DiagramNode[],
  edges: readonly DiagramEdge[],
  startId: string,
  endId: string,
  options: EnumeratePathsOptions = {},
): EnumeratePathsResult {
  const { directed = false, maxLength = MAX_PATH_LENGTH, maxPaths = MAX_PATHS } = options;
  const nodeIdSet = new Set(nodes.map((n) => n.id));
  if (!nodeIdSet.has(startId) || !nodeIdSet.has(endId) || startId === endId) {
    return { paths: [], truncated: false };
  }

  const adj = new Map<string, { nodeId: string; edgeId: string }[]>();
  const addAdj = (from: string, to: string, edgeId: string) => {
    if (!nodeIdSet.has(from) || !nodeIdSet.has(to)) return;
    const arr = adj.get(from) ?? [];
    arr.push({ nodeId: to, edgeId });
    adj.set(from, arr);
  };
  for (const e of edges) {
    addAdj(e.source, e.target, e.id);
    if (!directed || e.dataFlow === 'bidirectional') addAdj(e.target, e.source, e.id);
  }

  const paths: EnumeratedPath[] = [];
  let truncated = false;
  const visited = new Set<string>([startId]);
  const current: { nodeId: string; edgeId: string }[] = [];

  const dfs = (at: string) => {
    if (at === endId) {
      if (paths.length < maxPaths) {
        paths.push({
          nodeIds: [startId, ...current.map((s) => s.nodeId)],
          edgeIds: current.map((s) => s.edgeId),
        });
      } else truncated = true;
      return;
    }
    if (current.length >= maxLength) {
      if ((adj.get(at) ?? []).some((n) => !visited.has(n.nodeId))) truncated = true;
      return;
    }
    for (const next of adj.get(at) ?? []) {
      if (visited.has(next.nodeId)) continue;
      if (paths.length >= maxPaths) {
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
  dfs(startId);

  return { paths, truncated };
}
