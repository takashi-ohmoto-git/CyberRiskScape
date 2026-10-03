import type { LayerData } from '../../../core/model/types';
import { getNodeDimensions } from '../../../core/canvas/nodeGeometry';

export interface ContentBounds {
  minX: number;
  minY: number;
  maxX: number;
  maxY: number;
}

/** callout の固定幅（AnnotationView の w-56 と一致）。 */
const CALLOUT_WIDTH = 224;

/**
 * 注釈の描画サイズの概算。実寸は本文に応じた自動サイズで純粋関数からは測れないため、
 * 切れを避けて少し大きめに見積もる（余白で吸収される）。
 */
function estimateAnnotationSize(a: LayerData['annotations'][number]): { w: number; h: number } {
  const lines = a.text.split('\n');
  if (a.kind === 'callout') {
    // text-xs(12px, 行高 16) の太字。全角混在を見込み 1 行 ≒ 16 文字で折り返す。
    const rows = lines.reduce((sum, l) => sum + Math.max(1, Math.ceil(l.length / 16)), 0);
    return { w: CALLOUT_WIDTH, h: rows * 16 + 20 };
  }
  // text-sm(14px, 行高 20) の極太。全角を見込み 1 文字 ≒ 15px。
  const maxLen = lines.reduce((m, l) => Math.max(m, l.length), 1);
  return { w: maxLen * 15 + 8, h: lines.length * 20 };
}

/** レイヤーの内容 bbox（ノード・境界・注釈）。要素が無ければ null。 */
export function computeContentBounds(
  layer: Pick<LayerData, 'nodes' | 'boundaries' | 'annotations'>,
): ContentBounds | null {
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  const add = (x: number, y: number, w: number, h: number) => {
    minX = Math.min(minX, x);
    minY = Math.min(minY, y);
    maxX = Math.max(maxX, x + w);
    maxY = Math.max(maxY, y + h);
  };
  for (const n of layer.nodes) {
    const { w, h } = getNodeDimensions(n);
    add(n.x, n.y, w, h);
  }
  for (const b of layer.boundaries) add(b.x, b.y, b.width, b.height);
  for (const a of layer.annotations) {
    const { w, h } = estimateAnnotationSize(a);
    add(a.x, a.y, w, h);
  }
  if (!Number.isFinite(minX)) return null;
  return { minX, minY, maxX, maxY };
}
