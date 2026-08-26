import type { DiagramNode } from './types';

/**
 * 内包ノード（`parentId` を持つ）に対して、親チェーンを遡って祖先ノードを返す。
 *
 * 信頼境界の包含判定（`resolveNodeTrust`）で「子ノードがどの境界の中に居るか」を
 * 判定するために親の x/y を使う、という用途で利用される。
 *
 * エッジ描画（EdgeLayer）の端点解決には使わない：エッジ端点はバッジの視覚位置に
 * 接続する必要があるため `getEdgeEndpointGeometry`（nodeGeometry.ts）を用いる。
 *
 * - 孤児（親 ID が `allNodes` に存在しない）はトップレベル扱いで自身を返す。
 * - サイクルが混入していた場合は安全のため自身を返す。
 *
 * 純粋関数：レジストリや DOM に依存しないため、threat-engine / canvas 双方から
 * 参照できる中立な配置（`core/model/`）に置いている。
 */
export function resolveDrawableAncestor(
  node: DiagramNode,
  allNodes: readonly DiagramNode[],
): DiagramNode {
  let current = node;
  const seen = new Set<string>([current.id]);
  while (current.parentId !== undefined) {
    const parent = allNodes.find((n) => n.id === current.parentId);
    if (!parent) return current; // orphan: 親が存在しない
    if (seen.has(parent.id)) return current; // サイクル防御
    seen.add(parent.id);
    current = parent;
  }
  return current;
}
