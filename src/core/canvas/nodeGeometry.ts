import type { DiagramNode, ShapeKind } from '../model/types';
import { componentRegistry } from '../../component-library/defaultRegistry';

export interface NodeDimensions {
  w: number;
  h: number;
}

/**
 * バッジ表示パラメータ。NodeView.tsx の DOM レイアウトと一致させる必要がある。
 * 親の左上 (-top-2 -left-2 = -8px) を起点に、p-1(4) + border(1) + icon(10) + border(1) + p-1(4)
 * = 20px 角のボタンが gap-0.5 (2px) で水平に並ぶ。BADGE_VISIBLE_LIMIT を超えた子は "+N"
 * チップに集約され視覚的に追えないため、エッジ端点としては親中心へフォールバックする。
 */
const BADGE_OFFSET_X = -8;
const BADGE_OFFSET_Y = -8;
const BADGE_SIZE = 20;
const BADGE_GAP = 2;
const BADGE_VISIBLE_LIMIT = 3;

/**
 * 形状ごとの描画サイズ（px）。
 * NodeView の inline style と EdgeLayer のアンカー計算で共通利用する。
 * Tailwind の w-* / h-* クラスではなく数値で持つことで、
 * エッジ座標との整合性を一元管理する。
 */
export const SHAPE_DIMENSIONS: Record<ShapeKind, NodeDimensions> = {
  rounded: { w: 128, h: 96 },
  rectangle: { w: 128, h: 96 },
  circle: { w: 112, h: 112 },
  'data-store': { w: 128, h: 96 },
  connector: { w: 40, h: 40 },
};

/** 未登録コンポーネント型のフォールバック形状（汎用矩形）。 */
const FALLBACK_SHAPE: ShapeKind = 'rounded';

export function getNodeDimensions(node: DiagramNode): NodeDimensions {
  const shape = componentRegistry.get(node.type)?.shape ?? FALLBACK_SHAPE;
  return SHAPE_DIMENSIONS[shape];
}


/**
 * エッジ接続点として使うノード中心座標。
 */
export function getNodeCenter(node: DiagramNode): { x: number; y: number } {
  const d = getNodeDimensions(node);
  return { x: node.x + d.w / 2, y: node.y + d.h / 2 };
}

/**
 * ノード中心から (towardX, towardY) への半直線が、与えられた中心/寸法を持つ矩形の
 * 境界と交わる点を返す。エッジ線の端点をノード本体ではなく縁で止めるために使う
 * （矢印マーカーがノードに隠れないようにするため）。
 *
 * 親子内包の子ノードはバッジ表示なのでノード本体寸法ではなくバッジ寸法を渡す。
 */
export function getEdgeAnchorAt(
  center: { x: number; y: number },
  dims: NodeDimensions,
  towardX: number,
  towardY: number,
): { x: number; y: number } {
  const hw = dims.w / 2;
  const hh = dims.h / 2;
  const dx = towardX - center.x;
  const dy = towardY - center.y;
  if (dx === 0 && dy === 0) return center;
  const absDx = Math.abs(dx) || 1e-9;
  const absDy = Math.abs(dy) || 1e-9;
  const scale = Math.min(hw / absDx, hh / absDy);
  return { x: center.x + dx * scale, y: center.y + dy * scale };
}

/**
 * エッジ端点としての視覚位置（中心座標と寸法）を返す。
 *
 * - 親無し（トップレベル）ノード：通常のノード中心/寸法。
 * - 親有り（バッジ表示の子）ノード：親の左上に並ぶバッジの中心/寸法。
 *   兄弟リスト内のインデックスから水平方向に積み上げ計算する。
 * - 孤児（親 ID が存在しない）：Canvas が topLevelNodes 扱いするため通常のノード中心。
 * - overflow（"+N" 圏内、4 番目以降）の子：視覚的に判別できないため親中心へフォールバック。
 *
 * `resolveDrawableAncestor` は信頼境界包含判定（resolveNodeTrust）で別途使われるが、
 * エッジ描画はこちらの関数で「実際に見えている位置」へ接続する。
 */
export function getEdgeEndpointGeometry(
  node: DiagramNode,
  allNodes: readonly DiagramNode[],
): { center: { x: number; y: number }; dims: NodeDimensions } {
  if (!node.parentId) {
    return { center: getNodeCenter(node), dims: getNodeDimensions(node) };
  }
  const parent = allNodes.find((n) => n.id === node.parentId);
  if (!parent) {
    return { center: getNodeCenter(node), dims: getNodeDimensions(node) };
  }
  const siblings = allNodes.filter((n) => n.parentId === parent.id);
  const index = siblings.findIndex((n) => n.id === node.id);
  if (index < 0 || index >= BADGE_VISIBLE_LIMIT) {
    return { center: getNodeCenter(parent), dims: getNodeDimensions(parent) };
  }
  const left = parent.x + BADGE_OFFSET_X + index * (BADGE_SIZE + BADGE_GAP);
  const top = parent.y + BADGE_OFFSET_Y;
  return {
    center: { x: left + BADGE_SIZE / 2, y: top + BADGE_SIZE / 2 },
    dims: { w: BADGE_SIZE, h: BADGE_SIZE },
  };
}
