import type { AuthType, DiagramBoundary, DiagramEdge, DiagramNode } from '../model/types';
import { resolveDrawableAncestor } from '../model/parentChain';

/**
 * エッジが信頼境界を越える箇所（クロッシング）を求める純関数群。
 *
 * 設計（[[plan]] §2.39 A-1）：
 * - **越境判定は所属境界集合の対称差**で行う。`resolveNodeTrust` と同じ包含規則を使うため、
 *   図に出るマーカーと脅威エンジンの `sourceTrust` / `targetTrust` 判定が食い違わない。
 * - **幾何交点はマーカーの位置決めにのみ使う**。両端が同じ境界集合に属するのに線が矩形の縁を
 *   かすめるようなケースでマーカーを出さないのは、位相（集合差）を真とするこの方針の帰結。
 * - 交点が得られない退行ケース（ノードが矩形の縁に載っている等）は経路中点へフォールバックする。
 */

export interface Point {
  x: number;
  y: number;
}

/** 描画済みの経路。`c` があれば二次ベジェ、無ければ線分。 */
export interface EdgePath {
  s: Point;
  t: Point;
  c?: Point;
}

export interface BoundaryCrossing {
  /** 越えた境界。マーカーの色は この `trustLevel` から引く。 */
  boundary: DiagramBoundary;
  /** マーカーを描く座標。 */
  x: number;
  y: number;
  /** 交点における経路の接線方向（度）。マーカーの二重線はこれに直交させる。 */
  angle: number;
  /** 幾何交点が得られず経路中点へフォールバックしたか。 */
  isFallback: boolean;
}

/** 曲線経路を折れ線に落とすときの分割数。 */
const CURVE_SAMPLES = 32;

function contains(b: DiagramBoundary, p: Point): boolean {
  return p.x >= b.x && p.x <= b.x + b.width && p.y >= b.y && p.y <= b.y + b.height;
}

function area(b: DiagramBoundary): number {
  return b.width * b.height;
}

/**
 * 各ノードが属する境界の一覧を解決する（**面積昇順＝内側が先**）。
 *
 * 包含規則は `resolveNodeTrust` と同一：ノード座標の点包含、内包ノード（parentId 持ち）は
 * `resolveDrawableAncestor` で遡った祖先の座標で判定する。どの境界にも属さないノードは空配列
 * （= Internet 扱い）。
 */
export function resolveNodeBoundaries(
  nodes: readonly DiagramNode[],
  boundaries: readonly DiagramBoundary[],
): Map<string, DiagramBoundary[]> {
  const map = new Map<string, DiagramBoundary[]>();
  for (const node of nodes) {
    const anchor = resolveDrawableAncestor(node, nodes);
    const owning = boundaries.filter((b) => contains(b, anchor));
    owning.sort((a, b) => area(a) - area(b));
    map.set(node.id, owning);
  }
  return map;
}

/**
 * エッジが越える境界（2 つの所属集合の**対称差**）を面積降順＝外側から返す。
 * 両端が同じ集合に属する（= 同一ゾーン内の通信）場合は空配列。
 */
export function crossedBoundaries(
  sourceOwning: readonly DiagramBoundary[],
  targetOwning: readonly DiagramBoundary[],
): DiagramBoundary[] {
  const sourceIds = new Set(sourceOwning.map((b) => b.id));
  const targetIds = new Set(targetOwning.map((b) => b.id));
  const result = [
    ...sourceOwning.filter((b) => !targetIds.has(b.id)),
    ...targetOwning.filter((b) => !sourceIds.has(b.id)),
  ];
  result.sort((a, b) => area(b) - area(a));
  return result;
}

/** 経路を折れ線（頂点列）に落とす。線分はそのまま 2 点。 */
function toPolyline(path: EdgePath): Point[] {
  if (!path.c) return [path.s, path.t];
  const { s, t, c } = path;
  const points: Point[] = [];
  for (let i = 0; i <= CURVE_SAMPLES; i += 1) {
    const u = i / CURVE_SAMPLES;
    const inv = 1 - u;
    points.push({
      x: inv * inv * s.x + 2 * inv * u * c.x + u * u * t.x,
      y: inv * inv * s.y + 2 * inv * u * c.y + u * u * t.y,
    });
  }
  return points;
}

/**
 * 線分 p0→p1 と軸平行矩形の**辺**との交差パラメータ（0..1）を昇順で返す。
 * 辺ごとに 1 次方程式を解き、線分内かつ辺のスパン内に載るものだけを採用する。
 */
function segmentRectIntersections(p0: Point, p1: Point, b: DiagramBoundary): number[] {
  const dx = p1.x - p0.x;
  const dy = p1.y - p0.y;
  const left = b.x;
  const right = b.x + b.width;
  const top = b.y;
  const bottom = b.y + b.height;
  const hits: number[] = [];

  if (dx !== 0) {
    for (const vx of [left, right]) {
      const u = (vx - p0.x) / dx;
      if (u < 0 || u > 1) continue;
      const y = p0.y + u * dy;
      if (y >= top && y <= bottom) hits.push(u);
    }
  }
  if (dy !== 0) {
    for (const hy of [top, bottom]) {
      const u = (hy - p0.y) / dy;
      if (u < 0 || u > 1) continue;
      const x = p0.x + u * dx;
      if (x >= left && x <= right) hits.push(u);
    }
  }
  hits.sort((a, c) => a - c);
  return hits;
}

function angleOf(p0: Point, p1: Point): number {
  return (Math.atan2(p1.y - p0.y, p1.x - p0.x) * 180) / Math.PI;
}

/** 経路中点（曲線は t=0.5 のベジエ点）とその接線方向。 */
function midpointOf(path: EdgePath): { point: Point; angle: number } {
  const angle = angleOf(path.s, path.t);
  if (!path.c) {
    return { point: { x: (path.s.x + path.t.x) / 2, y: (path.s.y + path.t.y) / 2 }, angle };
  }
  // 二次ベジェの t=0.5 における接線は (t - s) と平行なので角度は線分時と同じ。
  return {
    point: {
      x: 0.25 * path.s.x + 0.5 * path.c.x + 0.25 * path.t.x,
      y: 0.25 * path.s.y + 0.5 * path.c.y + 0.25 * path.t.y,
    },
    angle,
  };
}

/**
 * 越える境界ごとに、経路上で**最初に**矩形の辺と交わる点を求める。
 * 交点が無ければ経路中点へフォールバックする（マーカーを落とさない）。
 */
export function computeCrossings(
  crossed: readonly DiagramBoundary[],
  path: EdgePath,
): BoundaryCrossing[] {
  if (crossed.length === 0) return [];
  const polyline = toPolyline(path);

  return crossed.map((boundary) => {
    for (let i = 0; i < polyline.length - 1; i += 1) {
      const p0 = polyline[i];
      const p1 = polyline[i + 1];
      const hits = segmentRectIntersections(p0, p1, boundary);
      if (hits.length === 0) continue;
      const u = hits[0];
      return {
        boundary,
        x: p0.x + u * (p1.x - p0.x),
        y: p0.y + u * (p1.y - p0.y),
        angle: angleOf(p0, p1),
        isFallback: false,
      };
    }
    const { point, angle } = midpointOf(path);
    return { boundary, x: point.x, y: point.y, angle, isFallback: true };
  });
}

/**
 * 図中で実際に境界を越えているエッジの `auth` 値を distinct 抽出する（凡例用）。
 * 越境が 1 件も無ければ空集合＝クロッシング凡例を出さない。
 *
 * 並び順は呼び出し側（`CROSSING_AUTH_LEGEND` の宣言順）に委ね、ここでは集合だけを返す。
 */
export function presentCrossingAuths(
  nodes: readonly DiagramNode[],
  edges: readonly DiagramEdge[],
  boundaries: readonly DiagramBoundary[],
): Set<AuthType> {
  const owning = resolveNodeBoundaries(nodes, boundaries);
  const auths = new Set<AuthType>();
  for (const edge of edges) {
    if (edge.source === edge.target) continue;
    const crossed = crossedBoundaries(owning.get(edge.source) ?? [], owning.get(edge.target) ?? []);
    if (crossed.length > 0) auths.add(edge.auth);
  }
  return auths;
}
