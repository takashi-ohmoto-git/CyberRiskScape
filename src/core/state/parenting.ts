import type { DiagramNode } from '../model/types';
import type { ComponentRegistry } from '../../component-library/registry';
import { getNodeCenter, getNodeDimensions } from '../canvas/nodeGeometry';

/**
 * ドラッグ終了時に「対象ノードがどの親に格納されるべきか」を判定する純粋関数。
 *
 * 仕様：
 * - 対象ノードの中心点が他ノードのバウンディングボックス内にあり、かつ
 *   `registry.canContain(target.type, dragged.type)` が true なら、その他ノードを
 *   親候補とする。
 * - 候補が複数ある（ノードが重なっている）場合は、`nodes` 配列の末尾優先
 *   （= 描画順で最前面）。
 * - 候補に対して dragged の子孫を親にするとサイクルを生むため除外する。
 * - どの候補にも該当しない場合は `undefined`（親解除）を返す。
 *
 * @param dragged 判定対象ノード（最新の x/y を含む）
 * @param allNodes 全ノード（dragged 自身を含む配列でよい）
 * @param registry 内包可否を引く `ComponentRegistry`
 * @returns 新しい parentId、または undefined（トップレベル化）
 */
export function findDropTargetParent(
  dragged: DiagramNode,
  allNodes: readonly DiagramNode[],
  registry: Pick<ComponentRegistry, 'canContain' | 'get'>,
): string | undefined {
  const center = getNodeCenter(dragged);
  const descendants = collectDescendantIds(dragged.id, allNodes);

  // 末尾を最前面とみなして後ろから走査
  for (let i = allNodes.length - 1; i >= 0; i--) {
    const candidate = allNodes[i];
    if (candidate.id === dragged.id) continue;
    if (descendants.has(candidate.id)) continue; // サイクル防止
    if (!registry.canContain(candidate.type, dragged.type)) continue;

    const dim = getNodeDimensions(candidate);
    const insideX = center.x >= candidate.x && center.x <= candidate.x + dim.w;
    const insideY = center.y >= candidate.y && center.y <= candidate.y + dim.h;
    if (insideX && insideY) {
      return candidate.id;
    }
  }
  return undefined;
}

/**
 * `rootId` を親とするノード ID 集合を再帰的に収集する（rootId 自身は含まない）。
 * サイクル防止のため、再親付け候補に rootId の子孫が含まれないようフィルタするのに使う。
 */
function collectDescendantIds(rootId: string, allNodes: readonly DiagramNode[]): Set<string> {
  const childrenByParent = new Map<string, string[]>();
  for (const n of allNodes) {
    if (n.parentId === undefined) continue;
    const arr = childrenByParent.get(n.parentId) ?? [];
    arr.push(n.id);
    childrenByParent.set(n.parentId, arr);
  }
  const out = new Set<string>();
  const stack = [...(childrenByParent.get(rootId) ?? [])];
  while (stack.length > 0) {
    const id = stack.pop()!;
    if (out.has(id)) continue;
    out.add(id);
    const children = childrenByParent.get(id);
    if (children) stack.push(...children);
  }
  return out;
}
