import { describe, expect, it } from 'vitest';
import type { DiagramBoundary, DiagramNode } from '../model/types';
import {
  MAX_SCALE,
  MIN_SCALE,
  clampScale,
  computeFit,
  screenToWorld,
  zoomAtPoint,
} from './viewport';

describe('clampScale', () => {
  it('範囲内はそのまま', () => {
    expect(clampScale(1)).toBe(1);
  });
  it('下限・上限で丸める', () => {
    expect(clampScale(0.01)).toBe(MIN_SCALE);
    expect(clampScale(99)).toBe(MAX_SCALE);
  });
});

describe('screenToWorld', () => {
  const rect = { left: 100, top: 50 };
  it('等倍・パンなしは rect 分だけ差し引く', () => {
    expect(screenToWorld(150, 80, rect, { scale: 1, tx: 0, ty: 0 })).toEqual({ x: 50, y: 30 });
  });
  it('scale と tx/ty を反映', () => {
    // worldX = (clientX - left - tx) / scale = (300 - 100 - 40) / 2 = 80
    expect(screenToWorld(300, 250, rect, { scale: 2, tx: 40, ty: 10 })).toEqual({
      x: 80,
      y: 95,
    });
  });
});

describe('zoomAtPoint', () => {
  it('カーソル直下のワールド点を固定する', () => {
    const vp = { scale: 1, tx: 0, ty: 0 };
    const localX = 200;
    const localY = 120;
    const worldBefore = { x: (localX - vp.tx) / vp.scale, y: (localY - vp.ty) / vp.scale };
    const next = zoomAtPoint(vp, localX, localY, 2);
    expect(next.scale).toBe(2);
    // 同じ local 点に同じワールド点が来る
    const worldAfter = { x: (localX - next.tx) / next.scale, y: (localY - next.ty) / next.scale };
    expect(worldAfter.x).toBeCloseTo(worldBefore.x);
    expect(worldAfter.y).toBeCloseTo(worldBefore.y);
  });
  it('倍率はクランプされる', () => {
    expect(zoomAtPoint({ scale: 1, tx: 0, ty: 0 }, 0, 0, 99).scale).toBe(MAX_SCALE);
  });
});

describe('computeFit', () => {
  const node = (id: string, x: number, y: number): DiagramNode => ({
    id,
    seq: 1,
    type: 'USER',
    x,
    y,
  });
  it('要素なしは等倍・パンなし', () => {
    expect(computeFit([], [], 800, 600)).toEqual({ scale: 1, tx: 0, ty: 0 });
  });
  it('bbox 中心を view 中心へ寄せる', () => {
    // USER は 128x96。単一ノードを (100,100) に置くと bbox 中心 = (164,148)。
    const fit = computeFit([node('n1', 100, 100)], [], 800, 600);
    const centerX = fit.tx + 164 * fit.scale;
    const centerY = fit.ty + 148 * fit.scale;
    expect(centerX).toBeCloseTo(400);
    expect(centerY).toBeCloseTo(300);
  });
  it('境界も bbox に含める', () => {
    const b: DiagramBoundary = {
      id: 'b1',
      seq: 1,
      type: 'ROUNDED',
      x: 0,
      y: 0,
      width: 2000,
      height: 2000,
      trustLevel: 'Internal',
    };
    const fit = computeFit([], [b], 800, 600);
    // 2000x2000 を 800x600（padding 48）に収めるので 1 未満
    expect(fit.scale).toBeLessThan(1);
  });
});
