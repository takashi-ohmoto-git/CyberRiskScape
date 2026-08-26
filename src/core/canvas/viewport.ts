import type { DiagramBoundary, DiagramNode, Viewport } from '../model/types';
import { getNodeDimensions } from './nodeGeometry';

/** 倍率の下限・上限。 */
export const MIN_SCALE = 0.2;
export const MAX_SCALE = 3.0;
/** ボタン／ホイール 1 段あたりの倍率係数。 */
export const ZOOM_STEP = 1.2;

/** 初期ビューポート（等倍・パンなし）。 */
export const IDENTITY_VIEWPORT: Viewport = { scale: 1, tx: 0, ty: 0 };

/** 倍率を [MIN_SCALE, MAX_SCALE] に丸める。 */
export function clampScale(scale: number): number {
  return Math.min(MAX_SCALE, Math.max(MIN_SCALE, scale));
}

/**
 * client 座標を `main` 矩形とビューポートからワールド座標へ変換する。
 * worldX = (clientX - rectLeft - tx) / scale。
 */
export function screenToWorld(
  clientX: number,
  clientY: number,
  rect: { left: number; top: number },
  vp: Viewport,
): { x: number; y: number } {
  return {
    x: (clientX - rect.left - vp.tx) / vp.scale,
    y: (clientY - rect.top - vp.ty) / vp.scale,
  };
}

/**
 * `main` ローカル座標 (localX, localY) の点を固定したまま倍率を nextScale へ変える
 * ビューポートを返す。ホイール／ボタンズーム共通。
 * 固定条件: localX = tx + worldX*scale = tx' + worldX*nextScale。
 */
export function zoomAtPoint(vp: Viewport, localX: number, localY: number, nextScale: number): Viewport {
  const scale = clampScale(nextScale);
  const worldX = (localX - vp.tx) / vp.scale;
  const worldY = (localY - vp.ty) / vp.scale;
  return { scale, tx: localX - worldX * scale, ty: localY - worldY * scale };
}

/**
 * 全ノード・境界を `main`（width×height）にパディング付きで収めるビューポートを計算する。
 * 要素が無ければ等倍・パンなしを返す。
 */
export function computeFit(
  nodes: readonly DiagramNode[],
  boundaries: readonly DiagramBoundary[],
  viewWidth: number,
  viewHeight: number,
  padding = 48,
): Viewport {
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;

  for (const n of nodes) {
    const { w, h } = getNodeDimensions(n);
    minX = Math.min(minX, n.x);
    minY = Math.min(minY, n.y);
    maxX = Math.max(maxX, n.x + w);
    maxY = Math.max(maxY, n.y + h);
  }
  for (const b of boundaries) {
    minX = Math.min(minX, b.x);
    minY = Math.min(minY, b.y);
    maxX = Math.max(maxX, b.x + b.width);
    maxY = Math.max(maxY, b.y + b.height);
  }

  if (!Number.isFinite(minX)) return IDENTITY_VIEWPORT;

  const contentW = Math.max(1, maxX - minX);
  const contentH = Math.max(1, maxY - minY);
  const scale = clampScale(
    Math.min((viewWidth - padding * 2) / contentW, (viewHeight - padding * 2) / contentH),
  );
  // bbox 中心を view 中心へ。tx = viewCenter - worldCenter*scale。
  const tx = viewWidth / 2 - ((minX + maxX) / 2) * scale;
  const ty = viewHeight / 2 - ((minY + maxY) / 2) * scale;
  return { scale, tx, ty };
}
