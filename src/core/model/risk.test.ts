import { describe, expect, it } from 'vitest';
import {
  effectiveSeverity,
  impactLevel,
  likelihoodLevel,
  riskRank,
  riskSeverity,
  type AxisLevel,
} from './risk';
import type { RiskScore } from './types';

const score = (
  damage: RiskScore['damage'],
  affectedUsers: RiskScore['affectedUsers'],
  reproducibility: RiskScore['reproducibility'],
  exploitability: RiskScore['exploitability'],
): RiskScore => ({ damage, affectedUsers, reproducibility, exploitability, at: 0 });

describe('impactLevel', () => {
  it('和 3 は Low（境界）', () => {
    expect(impactLevel(score(1, 2, 1, 1))).toBe('Low');
  });

  it('和 4 は Medium（境界）', () => {
    expect(impactLevel(score(2, 2, 1, 1))).toBe('Medium');
  });

  it('和 5 は High（境界）', () => {
    expect(impactLevel(score(2, 3, 1, 1))).toBe('High');
  });
});

describe('likelihoodLevel', () => {
  it('和 3 は Low（境界）', () => {
    expect(likelihoodLevel(score(1, 1, 1, 2))).toBe('Low');
  });

  it('和 4 は Medium（境界）', () => {
    expect(likelihoodLevel(score(1, 1, 2, 2))).toBe('Medium');
  });

  it('和 5 は High（境界）', () => {
    expect(likelihoodLevel(score(1, 1, 2, 3))).toBe('High');
  });
});

describe('riskRank', () => {
  const expected: Record<AxisLevel, Record<AxisLevel, string>> = {
    High: { Low: 'Medium', Medium: 'High', High: 'Critical' },
    Medium: { Low: 'Low', Medium: 'Medium', High: 'High' },
    Low: { Low: 'Low', Medium: 'Low', High: 'Medium' },
  };

  const levels: AxisLevel[] = ['Low', 'Medium', 'High'];
  for (const impact of levels) {
    for (const likelihood of levels) {
      it(`impact=${impact} / likelihood=${likelihood} → ${expected[impact][likelihood]}`, () => {
        expect(riskRank(impact, likelihood)).toBe(expected[impact][likelihood]);
      });
    }
  }
});

describe('riskSeverity', () => {
  it('全項目 1（Low × Low）は Low', () => {
    expect(riskSeverity(score(1, 1, 1, 1))).toBe('Low');
  });

  it('全項目 2（Medium × Medium）は Medium', () => {
    expect(riskSeverity(score(2, 2, 2, 2))).toBe('Medium');
  });

  it('全項目 3（High × High）は Critical', () => {
    expect(riskSeverity(score(3, 3, 3, 3))).toBe('Critical');
  });

  it('Impact High・Likelihood Low は Medium', () => {
    expect(riskSeverity(score(3, 3, 1, 1))).toBe('Medium');
  });
});

describe('effectiveSeverity', () => {
  it('risk 未評価はルール由来 severity をそのまま使う', () => {
    expect(effectiveSeverity({ severity: 'High' })).toBe('High');
  });

  it('risk 評価済みは評価由来ランクでルール由来 severity を上書きする', () => {
    // ルール由来は Critical だが、risk は全項目 1（Low）→ 評価由来 Low が優先される
    expect(effectiveSeverity({ severity: 'Critical', risk: score(1, 1, 1, 1) })).toBe('Low');
  });
});
