import { describe, expect, it } from 'vitest';
import {
  BUNDLED_INDICATOR_WEIGHTS,
  computeIndicators,
  formatRate,
  loadIndicatorWeights,
} from './computeIndicators';
import type { ControlStatusValue, Severity, SuppressionStatus } from '../../core/model/types';

const threat = (severity: Severity, control?: ControlStatusValue, treatment?: SuppressionStatus) => ({
  severity,
  ...(control ? { controlStatus: { status: control, at: 1 } } : {}),
  ...(treatment ? { suppression: { status: treatment, at: 1 } } : {}),
});

describe('computeIndicators', () => {
  it('脅威が無ければ割合は null（0% とも 100% ともしない）', () => {
    const r = computeIndicators([]);
    expect(r).toMatchObject({ total: 0, inScope: 0, controlSetRate: null, implementedRate: null, value: null });
  });

  it('何も設定していなければ 3 つとも 0', () => {
    const r = computeIndicators([threat('High'), threat('Low')]);
    expect(r).toMatchObject({ inScope: 2, controlSetRate: 0, treatmentSetRate: 0, implementedRate: 0, value: 0 });
  });

  it('重大度で重みを付ける（Critical 8・High 4・Medium 2・Low 1）', () => {
    // Critical だけ実装済み：8 / (8 + 4 + 2 + 1)
    const r = computeIndicators([
      threat('Critical', 'implemented'),
      threat('High'),
      threat('Medium'),
      threat('Low'),
    ]);
    expect(r.implementedRate).toBeCloseTo(8 / 15);
    expect(r.controlSetRate).toBeCloseTo(8 / 15);
    expect(r.counts).toEqual({ controlSet: 1, treatmentSet: 0, implemented: 1 });
  });

  it('設定率は「必須」「拒否」も数えるが、実装済みの割合は「実装済み」だけを数える', () => {
    const r = computeIndicators([
      threat('High', 'required'),
      threat('High', 'rejected'),
      threat('High', 'implemented'),
      threat('High'),
    ]);
    expect(r.controlSetRate).toBeCloseTo(3 / 4);
    expect(r.implementedRate).toBeCloseTo(1 / 4);
  });

  it('検討率はリスク対応方針が未設定でないものを数える（受容も数え、受容は分母に残る）', () => {
    const r = computeIndicators([
      threat('High', undefined, 'accepted'),
      threat('High', undefined, 'reduce'),
      threat('High'),
    ]);
    expect(r.inScope).toBe(3);
    expect(r.treatmentSetRate).toBeCloseTo(2 / 3);
  });

  it('誤検知と適用外は分子にも分母にも入れない', () => {
    const r = computeIndicators([
      threat('Critical', undefined, 'false-positive'),
      threat('Critical', 'not-applicable'),
      threat('Low', 'implemented', 'reduce'),
    ]);
    expect(r).toMatchObject({
      total: 3,
      excluded: 2,
      inScope: 1,
      controlSetRate: 1,
      treatmentSetRate: 1,
      implementedRate: 1,
      value: 1,
    });
  });

  it('誤検知・適用外しか無ければ null', () => {
    expect(computeIndicators([threat('High', 'not-applicable')]).value).toBeNull();
  });

  it('リスク評価があれば、評価後の重大度で重みを付ける', () => {
    const lowRisk = { damage: 1, affectedUsers: 1, reproducibility: 1, exploitability: 1, at: 1 } as const;
    const r = computeIndicators([
      { ...threat('Critical', 'implemented'), risk: lowRisk }, // 評価後は Low（重み 1）
      threat('High'),
    ]);
    expect(r.implementedRate).toBeCloseTo(1 / 5);
  });

  it('脅威モデルの値は 3 つの指標の重み付きの平均（設定率 1・検討率 1・実装済み 2）', () => {
    // 設定率 1・検討率 0・実装済み 0.5 → (1*1 + 0*1 + 0.5*2) / 4
    const r = computeIndicators([threat('High', 'implemented'), threat('High', 'required')]);
    expect(r.value).toBeCloseTo(0.5);
  });

  it('重みを渡せば、その重みで計算する', () => {
    const flat = {
      severity: { Critical: 1, High: 1, Medium: 1, Low: 1 },
      indicators: { controlSet: 1, treatmentSet: 1, implemented: 1 },
    };
    const r = computeIndicators([threat('Critical', 'implemented'), threat('Low')], flat);
    expect(r.implementedRate).toBeCloseTo(0.5);
  });
});

describe('loadIndicatorWeights', () => {
  it('同梱の重みが読める', () => {
    expect(BUNDLED_INDICATOR_WEIGHTS.severity).toEqual({ Critical: 8, High: 4, Medium: 2, Low: 1 });
    expect(BUNDLED_INDICATOR_WEIGHTS.indicators).toEqual({ controlSet: 1, treatmentSet: 1, implemented: 2 });
  });

  it('0 以下の重み・欠けた重みは受け付けない', () => {
    const base = 'schemaVersion: 1\nindicators: { controlSet: 1, treatmentSet: 1, implemented: 2 }\n';
    expect(() => loadIndicatorWeights(`${base}severity: { Critical: 8, High: 4, Medium: 2, Low: 0 }`)).toThrow();
    expect(() => loadIndicatorWeights(`${base}severity: { Critical: 8, High: 4, Medium: 2 }`)).toThrow();
  });
});

describe('formatRate', () => {
  it.each([
    [null, '—'],
    [0, '0%'],
    [0.424, '42%'],
    [1, '100%'],
  ])('%s → %s', (rate, expected) => {
    expect(formatRate(rate)).toBe(expected);
  });
});
