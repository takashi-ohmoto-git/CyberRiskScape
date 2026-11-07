import type { DiagramBoundary, DiagramNode } from '../model/types';
import { resolveDrawableAncestor } from '../model/parentChain';
import { getNodeCenter } from '../canvas/nodeGeometry';

/**
 * 各ノードの所属する管理境界（`MANAGEMENT`。クラウドのアカウント・サブスクリプション等）を解決する。
 *
 * 仕様（`resolveNodeSegment` と同じ包含判定）：
 * - 対象は `MANAGEMENT` だけ。
 * - **ノード中心**を矩形に含む管理境界を所属とみなす。入れ子は**面積最小（最内側）**を採用。
 * - 内包ノード（parentId 持ち）は描画上の祖先の中心で判定する。
 * - どの管理境界にも入らないノードは Map に載せない。
 */
export function resolveNodeManagement(
  nodes: DiagramNode[],
  boundaries: DiagramBoundary[],
): Map<string, string> {
  const map = new Map<string, string>();
  const scopes = boundaries.filter((b) => b.type === 'MANAGEMENT');
  if (scopes.length === 0) return map;
  for (const node of nodes) {
    const anchor = getNodeCenter(resolveDrawableAncestor(node, nodes));
    let inner: DiagramBoundary | null = null;
    let innerArea = Infinity;
    for (const b of scopes) {
      if (anchor.x >= b.x && anchor.x <= b.x + b.width && anchor.y >= b.y && anchor.y <= b.y + b.height) {
        const area = b.width * b.height;
        if (area < innerArea) {
          inner = b;
          innerArea = area;
        }
      }
    }
    if (inner) map.set(node.id, inner.id);
  }
  return map;
}
