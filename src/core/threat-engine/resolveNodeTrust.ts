import type { DiagramBoundary, DiagramNode, TrustLevel } from '../model/types';
import { resolveDrawableAncestor } from '../model/parentChain';

/**
 * 各ノードの所属境界を解決し、`trustLevel` のマップを返す。
 *
 * 仕様：
 * - ノード座標 `(x, y)` を矩形 `[bx, bx+w] × [by, by+h]` に含む境界を所属とみなす（点包含）。
 * - 入れ子境界を許可。複数に含まれる場合は **面積最小（= 最内側）** の trustLevel を採用。
 * - どの境界にも属さないノードは `'Internet'` 扱い（= 信頼できない外部）。
 * - 内包ノード（parentId 持ち）は描画上は親に従属するため、判定座標は
 *   `resolveDrawableAncestor` で遡った祖先の x/y を用いる。これにより親と子は
 *   同じ境界・同じ trustLevel になる。
 *
 * 設計判断は CLAUDE.md / docs（境界の入れ子可、未所属は Internet）に従う。
 */
export function resolveNodeTrust(
  nodes: DiagramNode[],
  boundaries: DiagramBoundary[],
): Map<string, TrustLevel> {
  const map = new Map<string, TrustLevel>();
  for (const node of nodes) {
    const anchor = resolveDrawableAncestor(node, nodes);
    let inner: DiagramBoundary | null = null;
    let innerArea = Infinity;
    for (const b of boundaries) {
      if (
        anchor.x >= b.x &&
        anchor.x <= b.x + b.width &&
        anchor.y >= b.y &&
        anchor.y <= b.y + b.height
      ) {
        const area = b.width * b.height;
        if (area < innerArea) {
          inner = b;
          innerArea = area;
        }
      }
    }
    map.set(node.id, inner ? inner.trustLevel : 'Internet');
  }
  return map;
}
