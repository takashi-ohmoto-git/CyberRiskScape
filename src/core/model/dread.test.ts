import { describe, expect, it } from 'vitest';
import { dreadRank, dreadTotal, effectiveSeverity } from './dread';
import type { DreadScore } from './types';

const score = (
  d: 1 | 2 | 3,
  r: 1 | 2 | 3,
  e: 1 | 2 | 3,
  a: 1 | 2 | 3,
  disc: 1 | 2 | 3,
): DreadScore => ({
  damage: d,
  reproducibility: r,
  exploitability: e,
  affectedUsers: a,
  discoverability: disc,
  at: 0,
});

describe('dreadTotal', () => {
  it('5 項目の合計を返す（最小 5・最大 15）', () => {
    expect(dreadTotal(score(1, 1, 1, 1, 1))).toBe(5);
    expect(dreadTotal(score(3, 3, 3, 3, 3))).toBe(15);
    expect(dreadTotal(score(1, 2, 3, 2, 1))).toBe(9);
  });
});

describe('dreadRank', () => {
  it('合計 5–7 は Low', () => {
    expect(dreadRank(5)).toBe('Low');
    expect(dreadRank(7)).toBe('Low');
  });
  it('合計 8–10 は Medium', () => {
    expect(dreadRank(8)).toBe('Medium');
    expect(dreadRank(10)).toBe('Medium');
  });
  it('合計 11–12 は High', () => {
    expect(dreadRank(11)).toBe('High');
    expect(dreadRank(12)).toBe('High');
  });
  it('合計 13–15 は Critical', () => {
    expect(dreadRank(13)).toBe('Critical');
    expect(dreadRank(15)).toBe('Critical');
  });
});

describe('effectiveSeverity', () => {
  it('DREAD 評価済みなら評価由来ランクを優先する', () => {
    expect(effectiveSeverity({ severity: 'Low', dread: score(3, 3, 3, 3, 3) })).toBe('Critical');
    expect(effectiveSeverity({ severity: 'Critical', dread: score(1, 1, 1, 1, 1) })).toBe('Low');
  });
  it('未評価ならルール由来 severity をそのまま返す', () => {
    expect(effectiveSeverity({ severity: 'High' })).toBe('High');
  });
});
