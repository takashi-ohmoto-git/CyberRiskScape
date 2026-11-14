import { describe, expect, it } from 'vitest';
import type { ControlStatusValue, DetectionAssumptionFlag, LayerKey, Severity } from '../../../core/model/types';
import type { AxisLevel } from '../../../core/model/risk';
import type { ThreatReportRow } from '../threatReport';
import {
  computeSummary,
  firstStep,
  itemIndicators,
  mitigationLines,
  rankThreats,
  stripTierTags,
  type SummaryItem,
  type Treatment,
} from './summary';

let seq = 0;
function item(o: {
  layer?: LayerKey;
  index?: number;
  severity?: Severity;
  impact?: AxisLevel | '';
  likelihood?: AxisLevel | '';
  treatment?: Treatment;
  control?: ControlStatusValue;
  id?: string;
  assumptions?: DetectionAssumptionFlag[];
}): SummaryItem {
  const id = o.id ?? `t${seq++}`;
  return {
    layer: o.layer ?? 'L1',
    index: o.index ?? seq,
    row: { id } as ThreatReportRow,
    severity: o.severity ?? 'High',
    impact: o.impact ?? '',
    likelihood: o.likelihood ?? '',
    treatment: o.treatment ?? 'unaddressed',
    control: o.control,
    assumptions: o.assumptions ?? [],
  };
}
const ids = (xs: SummaryItem[]) => xs.map((x) => x.row.id);

describe('rankThreats', () => {
  it('実効深刻度 → Impact → Likelihood の順（未評価は最下位）', () => {
    const xs = [
      item({ id: 'low', severity: 'Low' }),
      item({ id: 'high-unrated', severity: 'High' }),
      item({ id: 'high-L', severity: 'High', impact: 'Low', likelihood: 'High' }),
      item({ id: 'high-H-M', severity: 'High', impact: 'High', likelihood: 'Medium' }),
      item({ id: 'high-H-H', severity: 'High', impact: 'High', likelihood: 'High' }),
      item({ id: 'crit', severity: 'Critical' }),
    ];
    expect(ids(rankThreats(xs, ['L1']))).toEqual(['crit', 'high-H-H', 'high-H-M', 'high-L', 'high-unrated', 'low']);
  });

  it('同順位なら未対応（回避・低減・移転より）を優先し、最後は元の並び', () => {
    const xs = [
      item({ id: 'b-reduce', index: 0, treatment: 'reduce' }),
      item({ id: 'c-unaddressed', index: 1 }),
      item({ id: 'a-unaddressed', index: 0 }),
    ];
    expect(ids(rankThreats(xs, ['L1']))).toEqual(['a-unaddressed', 'c-unaddressed', 'b-reduce']);
  });

  it('レイヤー順 → 行順で安定', () => {
    const xs = [item({ id: 'l2', layer: 'L2', index: 0 }), item({ id: 'l1', layer: 'L1', index: 5 })];
    expect(ids(rankThreats(xs, ['L1', 'L2']))).toEqual(['l1', 'l2']);
  });

  it('受容・誤検知は除外し、回避・低減・移転は残す', () => {
    const xs = [
      item({ id: 'acc', severity: 'Critical', treatment: 'accepted' }),
      item({ id: 'fp', severity: 'Critical', treatment: 'false-positive' }),
      item({ id: 'avoid', severity: 'Low', treatment: 'avoid' }),
    ];
    expect(ids(rankThreats(xs, ['L1']))).toEqual(['avoid']);
  });

  it('レイヤー横断で上位 10 件に絞る', () => {
    const xs = [
      ...Array.from({ length: 8 }, (_, i) => item({ layer: 'L0', index: i, severity: 'Medium' })),
      ...Array.from({ length: 8 }, (_, i) => item({ layer: 'L1', index: i, severity: 'High' })),
    ];
    const top = rankThreats(xs, ['L0', 'L1']);
    expect(top).toHaveLength(10);
    expect(top.filter((x) => x.layer === 'L1')).toHaveLength(8);
    expect(top.filter((x) => x.layer === 'L0')).toHaveLength(2);
  });
});

describe('itemIndicators（画面・CLI と同じ指標）', () => {
  it('適用外は対象から外す。未設定・要対応・却下は未実装として対象に残る', () => {
    const r = itemIndicators([
      item({ severity: 'High', control: 'implemented' }),
      item({ severity: 'High', control: 'implemented' }),
      item({ severity: 'High', control: 'required' }),
      item({ severity: 'High', control: 'rejected' }),
      item({ severity: 'High' }),
      item({ severity: 'High', control: 'not-applicable' }),
    ]);
    expect(r.inScope).toBe(5);
    expect(r.counts.implemented).toBe(2);
    expect(r.implementedRate).toBeCloseTo(0.4);
    expect(r.controlSetRate).toBeCloseTo(0.8);
  });

  it('受容は対象に残り、誤検知は外す。重大度で重みを付ける', () => {
    const r = itemIndicators([
      item({ severity: 'Critical', treatment: 'accepted' }),
      item({ severity: 'Low', control: 'implemented' }),
      item({ severity: 'Critical', treatment: 'false-positive' }),
    ]);
    expect(r.inScope).toBe(2);
    expect(r.implementedRate).toBeCloseTo(1 / 9);
    expect(r.treatmentSetRate).toBeCloseTo(8 / 9);
  });

  it('対象が 0 件なら null', () => {
    expect(itemIndicators([]).implementedRate).toBeNull();
    expect(itemIndicators([item({ control: 'not-applicable' })]).implementedRate).toBeNull();
  });
});

describe('computeSummary', () => {
  const xs = [
    item({ layer: 'L0', severity: 'Critical', control: 'implemented' }),
    item({ layer: 'L0', severity: 'High', treatment: 'reduce', control: 'required' }),
    item({ layer: 'L1', severity: 'Low', control: 'implemented' }),
    item({ layer: 'L1', severity: 'High', treatment: 'accepted', control: 'implemented' }),
    item({ layer: 'L1', severity: 'Medium', treatment: 'false-positive' }),
  ];
  const s = computeSummary(xs, ['L0', 'L1']);

  it('有効脅威・Critical+High・未対応は受容/誤検知を除く', () => {
    expect(s.activeCount).toBe(3);
    expect(s.criticalHighCount).toBe(2);
    expect(s.unaddressedCount).toBe(2);
  });

  it('指標は全体と Critical+High の 2 つ（受容は対象に残り、誤検知は外す）', () => {
    // 対象：Critical 実装済み・High 必須・Low 実装済み・High 受容＋実装済み（Medium 誤検知は外す）
    expect(s.indicators).toMatchObject({ inScope: 4, counts: { implemented: 3, controlSet: 4, treatmentSet: 2 } });
    expect(s.indicators.implementedRate).toBeCloseTo((8 + 1 + 4) / (8 + 4 + 1 + 4));
    expect(s.indicatorsCriticalHigh.inScope).toBe(3);
    expect(s.indicatorsCriticalHigh.implementedRate).toBeCloseTo(12 / 16);
  });

  it('対応方針別は受容・誤検知も数え、対策実装状況別は有効脅威のみ', () => {
    expect(s.treatmentCounts).toMatchObject({ unaddressed: 2, reduce: 1, accepted: 1, 'false-positive': 1 });
    expect(s.controlCounts).toMatchObject({ implemented: 2, required: 1, unset: 0 });
  });

  it('レイヤー別の深刻度件数と抑制件数', () => {
    expect(s.byLayer[1]).toEqual({
      layer: 'L1',
      severity: { Critical: 0, High: 0, Medium: 0, Low: 1 },
      active: 1,
      suppressed: 2,
    });
  });
});

describe('緩和策の整形', () => {
  const row = (m: Partial<ThreatReportRow>) => m as ThreatReportRow;

  it('stripTierTags は生タグを除く', () => {
    expect(stripTierTags('[Foundation] A [Enterprise] B')).toBe('A B');
  });

  it('mitigationTiers を段階ごとの行にする（タグ無し）', () => {
    const lines = mitigationLines(row({ mitigationTiers: { foundation: '[Foundation] A', advanced: 'C' } }));
    expect(lines).toEqual([
      { tier: 'Foundation', text: 'A' },
      { tier: 'Advanced', text: 'C' },
    ]);
    expect(mitigationLines(row({}))).toEqual([]);
  });

  it('まず着手すべき対策は Foundation。実装済みには出さない', () => {
    const r = row({ mitigationTiers: { foundation: 'F' } });
    expect(firstStep(r, undefined)).toBe('F');
    expect(firstStep(r, 'required')).toBe('F');
    expect(firstStep(r, 'implemented')).toBe('');
    expect(firstStep(row({}), undefined)).toBe('');
  });
});

describe('computeSummary（未入力の仮定）', () => {
  it('有効脅威のうち仮定で出たものだけを数え、受容・誤検知は数えない', () => {
    const xs = [
      item({ assumptions: ['posture'] }),
      item({ assumptions: ['attackSurface', 'posture'] }),
      item({}),
      item({ assumptions: ['userTrust'], treatment: 'accepted' }),
    ];
    expect(computeSummary(xs, ['L1']).assumedActiveCount).toBe(2);
  });
});
