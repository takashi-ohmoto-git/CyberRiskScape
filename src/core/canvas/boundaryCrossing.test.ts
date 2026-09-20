import { describe, expect, it } from 'vitest';
import {
  computeCrossings,
  crossedBoundaries,
  resolveNodeBoundaries,
} from './boundaryCrossing';
import { getNodeDimensions } from './nodeGeometry';
import type { DiagramBoundary, DiagramNode } from '../model/types';

/** 外側 400x400 の Internal ゾーン。 */
const outer: DiagramBoundary = {
  id: 'b-outer',
  type: 'RECT',
  x: 100,
  y: 100,
  width: 400,
  height: 400,
  trustLevel: 'Internal',
};
/** outer に内包される 100x100 の Partner ゾーン。 */
const inner: DiagramBoundary = {
  id: 'b-inner',
  type: 'RECT',
  x: 200,
  y: 200,
  width: 100,
  height: 100,
  trustLevel: 'Partner',
};

/**
 * 中心が (cx, cy) に来るようノードを置く。包含判定はノード中心で行うため、
 * テストの座標は「ノードの中心をどこに置くか」で書く。
 */
function nodeAt(id: string, cx: number, cy: number): DiagramNode {
  const probe: DiagramNode = { id, type: 'PROCESS', x: 0, y: 0 };
  const { w, h } = getNodeDimensions(probe);
  return { ...probe, x: cx - w / 2, y: cy - h / 2 };
}

function owningOf(nodes: DiagramNode[], boundaries: DiagramBoundary[], id: string) {
  return resolveNodeBoundaries(nodes, boundaries).get(id) ?? [];
}

describe('resolveNodeBoundaries', () => {
  it('入れ子境界に含まれるノードは面積昇順（内側が先）で両方を返す', () => {
    const nodes = [nodeAt('n1', 250, 250)];
    const owning = owningOf(nodes, [outer, inner], 'n1');
    expect(owning.map((b) => b.id)).toEqual(['b-inner', 'b-outer']);
  });

  it('どの境界にも属さないノードは空配列になる', () => {
    const nodes = [nodeAt('n1', 900, 900)];
    expect(owningOf(nodes, [outer, inner], 'n1')).toEqual([]);
  });

  it('左上が枠外でも中心が枠内なら所属とみなす', () => {
    // PROCESS は 112×112。左上 (60,60) は outer の外だが中心 (116,116) は内側。
    const nodes: DiagramNode[] = [{ id: 'n1', type: 'PROCESS', x: 60, y: 60 }];
    expect(owningOf(nodes, [outer, inner], 'n1').map((b) => b.id)).toEqual(['b-outer']);
  });

  it('内包ノード（parentId 持ち）は親の座標で判定される', () => {
    const parent = nodeAt('p', 250, 250);
    const child: DiagramNode = { id: 'c', type: 'PROCESS', x: 0, y: 0, parentId: 'p' };
    const owning = owningOf([parent, child], [outer, inner], 'c');
    expect(owning.map((b) => b.id)).toEqual(['b-inner', 'b-outer']);
  });
});

describe('crossedBoundaries', () => {
  it('単一境界を 1 枚越えるエッジは 1 件を返す', () => {
    const nodes = [nodeAt('in', 150, 150), nodeAt('out', 900, 900)];
    const crossed = crossedBoundaries(
      owningOf(nodes, [outer], 'in'),
      owningOf(nodes, [outer], 'out'),
    );
    expect(crossed.map((b) => b.id)).toEqual(['b-outer']);
  });

  it('入れ子境界を 2 枚越えるエッジは外側から順に 2 件を返す', () => {
    const nodes = [nodeAt('deep', 250, 250), nodeAt('out', 900, 900)];
    const crossed = crossedBoundaries(
      owningOf(nodes, [outer, inner], 'deep'),
      owningOf(nodes, [outer, inner], 'out'),
    );
    expect(crossed.map((b) => b.id)).toEqual(['b-outer', 'b-inner']);
  });

  it('同一境界内の通信は越境ゼロ', () => {
    const nodes = [nodeAt('a', 150, 150), nodeAt('b', 450, 450)];
    const crossed = crossedBoundaries(
      owningOf(nodes, [outer], 'a'),
      owningOf(nodes, [outer], 'b'),
    );
    expect(crossed).toEqual([]);
  });

  it('双方とも境界外なら、線が矩形の上を通っても越境ゼロ（位相を真とする）', () => {
    const nodes = [nodeAt('l', 0, 300), nodeAt('r', 900, 300)];
    const crossed = crossedBoundaries(
      owningOf(nodes, [outer], 'l'),
      owningOf(nodes, [outer], 'r'),
    );
    expect(crossed).toEqual([]);
  });
});

describe('computeCrossings', () => {
  it('越境ゼロならマーカーも出さない', () => {
    expect(computeCrossings([], { s: { x: 0, y: 0 }, t: { x: 10, y: 10 } })).toEqual([]);
  });

  it('直線経路では矩形の辺との交点にマーカーを置く', () => {
    // y=300 の水平線が outer の右辺 x=500 と交わる。
    const [crossing] = computeCrossings([outer], { s: { x: 300, y: 300 }, t: { x: 900, y: 300 } });
    expect(crossing.isFallback).toBe(false);
    expect(crossing.x).toBeCloseTo(500);
    expect(crossing.y).toBeCloseTo(300);
    expect(crossing.angle).toBeCloseTo(0);
  });

  it('経路上で最初に出会う辺を採る（逆向きでは反対側の辺になる）', () => {
    const [crossing] = computeCrossings([outer], { s: { x: 900, y: 300 }, t: { x: 300, y: 300 } });
    expect(crossing.x).toBeCloseTo(500);
    expect(crossing.angle).toBeCloseTo(180);
  });

  it('入れ子を 2 枚越える経路は境界ごとに別々の交点を持つ', () => {
    const crossings = computeCrossings([outer, inner], {
      s: { x: 250, y: 250 },
      t: { x: 900, y: 250 },
    });
    expect(crossings).toHaveLength(2);
    expect(crossings[0].x).toBeCloseTo(500); // outer の右辺
    expect(crossings[1].x).toBeCloseTo(300); // inner の右辺
    expect(crossings.every((c) => c.isFallback)).toBe(false);
  });

  it('曲線経路（二次ベジェ）でも交点を取れる', () => {
    const [crossing] = computeCrossings([outer], {
      s: { x: 300, y: 300 },
      t: { x: 900, y: 300 },
      c: { x: 600, y: 200 },
    });
    expect(crossing.isFallback).toBe(false);
    expect(crossing.x).toBeCloseTo(500, 0);
  });

  it('交点が取れない退行ケースは経路中点へフォールバックする', () => {
    // 経路が矩形に一切触れないのに越境扱い（＝ノードが縁に載る等の退行）を想定。
    const [crossing] = computeCrossings([inner], { s: { x: 700, y: 700 }, t: { x: 900, y: 700 } });
    expect(crossing.isFallback).toBe(true);
    expect(crossing.x).toBeCloseTo(800);
    expect(crossing.y).toBeCloseTo(700);
  });
});
