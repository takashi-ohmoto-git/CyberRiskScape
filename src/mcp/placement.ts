import type { DiagramBoundary, DiagramNode, LayerData } from '../core/model/types';
import { TRUST_BEARING_BOUNDARY_TYPES } from '../core/model/types';
import { resolveNodeBoundaries } from '../core/canvas/boundaryCrossing';
import { getNodeDimensions } from '../core/canvas/nodeGeometry';
import { resolveDrawableAncestor } from '../core/model/parentChain';

/**
 * MCP サーバー用の配置。座標はエージェントに渡させず、ここで決める。
 *
 * 信頼境界の所属は座標で決まるため、配置結果は必ず `resolveNodeBoundaries`（アプリ・脅威エンジンと
 * 同じ包含規則）で検証し、意図した境界に入らない／他の要素の所属を変えてしまう場合は
 * `PlacementError` で拒否する。純粋関数（入力は変更しない）。
 */

export interface Rect {
  x: number;
  y: number;
  width: number;
  height: number;
}

export class PlacementError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PlacementError';
  }
}

export interface PlacementResult {
  x: number;
  y: number;
  /** 境界を下へ広げた場合のみ。広げた後の境界矩形（x/y/width は元のまま、height のみ増える）。 */
  expandedBoundary?: Rect;
}

/** ノード間の余白。 */
const GAP = 32;
/** 境界内側の余白。 */
const PAD = 32;
/** 探索する行数の上限（無限ループ防止）。 */
const MAX_ROWS = 100;
/** 注釈の概算サイズ（配置の衝突回避にだけ使う）。 */
const ANNOTATION_W = 160;
const ANNOTATION_H = 40;
const DEFAULT_BOUNDARY_W = 400;
const DEFAULT_BOUNDARY_H = 200;

const CANDIDATE_ID = '__placement_candidate__';
const PROBE_ID = '__placement_probe__';

function candidateNode(type: string, x: number, y: number): DiagramNode {
  return { id: CANDIDATE_ID, type, x, y };
}

function rectOf(n: DiagramNode): Rect {
  const d = getNodeDimensions(n);
  return { x: n.x, y: n.y, width: d.w, height: d.h };
}

function overlaps(a: Rect, b: Rect): boolean {
  return (
    a.x < b.x + b.width + GAP &&
    b.x < a.x + a.width + GAP &&
    a.y < b.y + b.height + GAP &&
    b.y < a.y + a.height + GAP
  );
}

function boundaryRect(b: DiagramBoundary): Rect {
  return { x: b.x, y: b.y, width: b.width, height: b.height };
}

/** `outer` が `inner` を完全に含むか（境界どうしの包含。点包含ではないので既存関数の対象外）。 */
function rectContains(outer: Rect, inner: Rect): boolean {
  return (
    inner.x >= outer.x &&
    inner.y >= outer.y &&
    inner.x + inner.width <= outer.x + outer.width &&
    inner.y + inner.height <= outer.y + outer.height
  );
}

/** 矩形の内側にアンカー（中心）が入るノード ID。包含判定は `resolveNodeBoundaries` に委ねる。 */
function nodeIdsInside(nodes: readonly DiagramNode[], rect: Rect): Set<string> {
  const probe: DiagramBoundary = { id: PROBE_ID, type: 'RECT', trustLevel: 'Internal', ...rect };
  const owning = resolveNodeBoundaries(nodes, [probe]);
  const ids = new Set<string>();
  for (const [id, list] of owning) if (list.length > 0) ids.add(id);
  return ids;
}

/** 配置の衝突回避に使う障害物（トップレベルノードのみ。内包された子は親の位置で描かれる）。 */
function obstacles(nodes: readonly DiagramNode[]): Rect[] {
  return nodes.filter((n) => n.parentId === undefined).map(rectOf);
}

interface Bounds {
  minX: number;
  minY: number;
  maxX: number;
  maxY: number;
}

function contentBounds(
  layer: LayerData,
  nodes: readonly DiagramNode[],
  withAnnotations: boolean,
): Bounds | null {
  const rects: Rect[] = [...obstacles(nodes), ...layer.boundaries.map(boundaryRect)];
  if (withAnnotations) {
    for (const a of layer.annotations) {
      rects.push({ x: a.x, y: a.y, width: ANNOTATION_W, height: ANNOTATION_H });
    }
  }
  if (rects.length === 0) return null;
  return {
    minX: Math.min(...rects.map((r) => r.x)),
    minY: Math.min(...rects.map((r) => r.y)),
    maxX: Math.max(...rects.map((r) => r.x + r.width)),
    maxY: Math.max(...rects.map((r) => r.y + r.height)),
  };
}

/**
 * ノードの配置先を決める。
 *
 * - `boundaryId` 指定：境界内のグリッド上の空きへ置く。空きが無ければ境界を下へ広げる。
 *   広げた結果、その境界に元々属さないノードの中心や他の境界を新たに包含する場合は拒否する。
 * - `boundaryId` が null：どの信頼境界にも入らない位置（既存要素全体の右側の空き）。
 *
 * `ignoreNodeId` は移動中のノード自身（障害物・所属判定から除く）。
 */
export function placeNode(
  layer: LayerData,
  nodeType: string,
  boundaryId: string | null,
  ignoreNodeId?: string,
): PlacementResult {
  const nodes = layer.nodes.filter((n) => n.id !== ignoreNodeId);
  return boundaryId === null
    ? placeOutside(layer, nodes, nodeType)
    : placeInBoundary(layer, nodes, nodeType, boundaryId);
}

function placeOutside(
  layer: LayerData,
  nodes: readonly DiagramNode[],
  nodeType: string,
): PlacementResult {
  const bounds = contentBounds(layer, nodes, false);
  const x = bounds ? bounds.maxX + GAP * 2 : GAP * 2;
  const y0 = bounds ? bounds.minY : GAP * 2;
  const dims = getNodeDimensions(candidateNode(nodeType, 0, 0));
  const obs = obstacles(nodes);
  for (let row = 0; row < MAX_ROWS; row += 1) {
    const y = y0 + row * (dims.h + GAP);
    const rect = { x, y, width: dims.w, height: dims.h };
    if (obs.some((o) => overlaps(rect, o))) continue;
    const owning = resolveNodeBoundaries(
      [...nodes, candidateNode(nodeType, x, y)],
      layer.boundaries,
    ).get(CANDIDATE_ID);
    if (owning && owning.length > 0) continue;
    return { x, y };
  }
  throw new PlacementError('境界の外側に空き位置を確保できませんでした');
}

function placeInBoundary(
  layer: LayerData,
  nodes: readonly DiagramNode[],
  nodeType: string,
  boundaryId: string,
): PlacementResult {
  const b = layer.boundaries.find((x) => x.id === boundaryId);
  if (!b) throw new PlacementError(`境界 ${boundaryId} が存在しません`);
  const oldRect = boundaryRect(b);
  const trustBearing = TRUST_BEARING_BOUNDARY_TYPES.has(b.type);
  // この境界を完全に内包する（外側の）信頼境界。配置後もこれらに属したままでなければならない。
  const ancestors = layer.boundaries.filter(
    (o) =>
      o.id !== b.id && TRUST_BEARING_BOUNDARY_TYPES.has(o.type) && rectContains(boundaryRect(o), oldRect),
  );

  const dims = getNodeDimensions(candidateNode(nodeType, 0, 0));
  const cellW = dims.w + GAP;
  const cellH = dims.h + GAP;
  const cols = Math.max(1, Math.floor((b.width - 2 * PAD + GAP) / cellW));
  const obs = obstacles(nodes);

  for (let row = 0; row < MAX_ROWS; row += 1) {
    const y = b.y + PAD + row * cellH;
    const needHeight = Math.max(b.height, y + dims.h + PAD - b.y);
    const rect: Rect = { ...oldRect, height: needHeight };
    const boundaries = layer.boundaries.map((o) => (o.id === b.id ? { ...o, height: needHeight } : o));
    for (let col = 0; col < cols; col += 1) {
      const x = b.x + PAD + col * cellW;
      const cell = { x, y, width: dims.w, height: dims.h };
      if (obs.some((o) => overlaps(cell, o))) continue;
      const candidate = candidateNode(nodeType, x, y);
      const all = [...nodes, candidate];
      if (trustBearing) {
        const owning = resolveNodeBoundaries(all, boundaries).get(CANDIDATE_ID) ?? [];
        // 最内側がこの境界であり、外側の境界にも属したままであること。
        if (owning[0]?.id !== b.id) continue;
        if (!ancestors.every((a) => owning.some((o) => o.id === a.id))) continue;
      } else if (!nodeIdsInside([candidate], rect).has(CANDIDATE_ID)) {
        continue;
      }
      if (needHeight === b.height) return { x, y };
      assertExpansionSafe(layer, nodes, b, oldRect, rect);
      return { x, y, expandedBoundary: rect };
    }
  }
  throw new PlacementError(`境界 ${boundaryId} の内側に空き位置を確保できませんでした`);
}

/** 境界を広げた結果、他のノードや他の境界を新たに包含しないことを確認する。 */
function assertExpansionSafe(
  layer: LayerData,
  nodes: readonly DiagramNode[],
  b: DiagramBoundary,
  oldRect: Rect,
  newRect: Rect,
): void {
  const before = nodeIdsInside(nodes, oldRect);
  const after = nodeIdsInside(nodes, newRect);
  const swallowed = [...after].filter((id) => !before.has(id));
  if (swallowed.length > 0) {
    throw new PlacementError(
      `境界 ${b.id} を広げると、境界に属さない既存ノード（${swallowed.join(', ')}）を巻き込みます`,
    );
  }
  const swallowedBoundaries = layer.boundaries.filter(
    (o) => o.id !== b.id && rectContains(newRect, boundaryRect(o)) && !rectContains(oldRect, boundaryRect(o)),
  );
  if (swallowedBoundaries.length > 0) {
    throw new PlacementError(
      `境界 ${b.id} を広げると、他の境界（${swallowedBoundaries.map((o) => o.id).join(', ')}）を巻き込みます`,
    );
  }
}

/**
 * `nodeIds`（とその内包された子）を囲む境界矩形（外接矩形＋余白）を返す。
 * 対象以外のノードの中心を包含する場合は拒否する。
 */
export function boundaryAround(layer: LayerData, nodeIds: readonly string[]): Rect {
  if (nodeIds.length === 0) throw new PlacementError('around には 1 件以上のノード id が必要です');
  const targets = new Set(nodeIds);
  for (const id of nodeIds) {
    if (!layer.nodes.some((n) => n.id === id)) throw new PlacementError(`ノード ${id} が存在しません`);
  }
  // 内包された子（親チェーンが対象に届くもの）も囲む対象に含める。
  for (const n of layer.nodes) {
    let cur: DiagramNode | undefined = n;
    const seen = new Set<string>();
    while (cur?.parentId !== undefined && !seen.has(cur.id)) {
      seen.add(cur.id);
      if (targets.has(cur.parentId)) {
        targets.add(n.id);
        break;
      }
      cur = layer.nodes.find((p) => p.id === cur!.parentId);
    }
  }
  const rects = nodeIds.map((id) => {
    const node = layer.nodes.find((n) => n.id === id) as DiagramNode;
    return rectOf(resolveDrawableAncestor(node, layer.nodes));
  });
  const minX = Math.min(...rects.map((r) => r.x));
  const minY = Math.min(...rects.map((r) => r.y));
  const maxX = Math.max(...rects.map((r) => r.x + r.width));
  const maxY = Math.max(...rects.map((r) => r.y + r.height));
  const rect: Rect = {
    x: minX - PAD,
    y: minY - PAD,
    width: maxX - minX + 2 * PAD,
    height: maxY - minY + 2 * PAD,
  };
  const others = layer.nodes.filter((n) => !targets.has(n.id));
  const swallowed = [...nodeIdsInside(others, rect)];
  if (swallowed.length > 0) {
    throw new PlacementError(
      `指定ノードを囲む境界が、対象外のノード（${swallowed.join(', ')}）を巻き込みます`,
    );
  }
  return rect;
}

/** `around` 無しで作る境界の矩形（既存要素の右側の空き。ノードは囲まない）。 */
export function emptyBoundaryRect(layer: LayerData): Rect {
  const bounds = contentBounds(layer, layer.nodes, false);
  return {
    x: bounds ? bounds.maxX + GAP * 2 : GAP * 2,
    y: bounds ? bounds.minY : GAP * 2,
    width: DEFAULT_BOUNDARY_W,
    height: DEFAULT_BOUNDARY_H,
  };
}

/**
 * 注釈の配置先。`targetNodeId` があればそのノードの右隣、無ければ既存要素の下。
 */
export function placeAnnotation(layer: LayerData, targetNodeId?: string): { x: number; y: number } {
  if (targetNodeId !== undefined) {
    const target = layer.nodes.find((n) => n.id === targetNodeId);
    if (!target) throw new PlacementError(`ノード ${targetNodeId} が存在しません`);
    const anchor = resolveDrawableAncestor(target, layer.nodes);
    const r = rectOf(anchor);
    return { x: r.x + r.width + GAP, y: r.y };
  }
  const bounds = contentBounds(layer, layer.nodes, true);
  return bounds ? { x: bounds.minX, y: bounds.maxY + GAP } : { x: GAP * 2, y: GAP * 2 };
}

