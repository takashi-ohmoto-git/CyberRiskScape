import { describe, expect, it } from 'vitest';
import { ssvcPointsFor, technicalImpactFromCvss, type SsvcInput } from './ssvc';
import type { Finding, Severity } from '../../core/model/types';

function input(over: Partial<Omit<SsvcInput, 'finding'>> & { finding?: Partial<Finding> } = {}): SsvcInput {
  const { finding, ...rest } = over;
  return {
    finding: {
      id: 'f',
      source: { format: 'cyclonedx', product: 'x', importedAt: '2026-11-01T00:00:00Z' },
      externalId: 'f',
      identifiers: [],
      severity: 'Low',
      canonicalIds: [],
      ...finding,
    } as Finding,
    exposure: 'reachable',
    exposureAssumed: false,
    reachesTargets: [],
    chainIndexes: [],
    isTarget: false,
    ...rest,
  };
}
const pentest = { source: { format: 'pentest', product: 'p', importedAt: '2026-11-01T00:00:00Z' } } as Partial<Finding>;

describe('ssvcPointsFor', () => {
  it.each<[string, Partial<Finding>, string]>([
    ['KEV → active', { kev: { dateAdded: '2099-01-01' } as never }, 'active'],
    ['実証されたペンテスト → poc', pentest, 'poc'],
    ['試行のみのペンテスト → none', { ...pentest, outcome: 'attempted' }, 'none'],
    ['EPSS が高いだけ → none', { epss: { score: 0.95 } as never }, 'none'],
  ])('Exploitation：%s', (_n, finding, expected) => {
    expect(ssvcPointsFor(input({ finding })).points.exploitation).toBe(expected);
  });

  it('KEV はペンテストより優先して active', () => {
    expect(ssvcPointsFor(input({ finding: { ...pentest, kev: { dateAdded: '2099-01-01' } as never } })).points.exploitation).toBe('active');
  });

  it.each<[string, Partial<SsvcInput>, string, boolean]>([
    ['entry → yes', { exposure: 'entry' }, 'yes', false],
    ['entry（入口が仮定）→ yes・仮定', { exposure: 'entry', exposureAssumed: true }, 'yes', true],
    ['reachable＋連鎖 → yes', { exposure: 'reachable', chainIndexes: [0] }, 'yes', false],
    ['reachable・連鎖なし → no', { exposure: 'reachable' }, 'no', false],
    ['unreachable → no', { exposure: 'unreachable' }, 'no', false],
    ['unbound → yes・仮定', { exposure: 'unbound' }, 'yes', true],
    ['unevaluated → yes・仮定', { exposure: 'unevaluated' }, 'yes', true],
  ])('Automatable：%s', (_n, over, expected, assumed) => {
    const a = ssvcPointsFor(input(over));
    expect(a.points.automatable).toBe(expected);
    expect(a.assumed.automatable).toBe(assumed);
  });

  it.each<[Severity, string]>([
    ['Critical', 'total'],
    ['High', 'total'],
    ['Medium', 'partial'],
    ['Low', 'partial'],
  ])('Technical Impact：%s → %s（常に仮置き）', (severity, expected) => {
    const a = ssvcPointsFor(input({ finding: { severity } }));
    expect(a.points.technicalImpact).toBe(expected);
    expect(a.assumed.technicalImpact).toBe(true);
  });

  it.each<[string, Partial<SsvcInput>, string, boolean]>([
    ['ノード自身が標的 → high', { isTarget: true, reachesTargets: [{}] }, 'high', false],
    ['標的に届く → medium', { reachesTargets: [{}] }, 'medium', false],
    ['届かない → low', {}, 'low', false],
    ['unbound → high・仮定', { exposure: 'unbound' }, 'high', true],
    ['unevaluated → high・仮定', { exposure: 'unevaluated' }, 'high', true],
  ])('Mission & Well-being：%s', (_n, over, expected, assumed) => {
    const a = ssvcPointsFor(input(over));
    expect(a.points.missionWellbeing).toBe(expected);
    expect(a.assumed.missionWellbeing).toBe(assumed);
  });

  it('判定は表の結果（active/yes/total/high → Act）と理由を持つ', () => {
    const a = ssvcPointsFor(input({ finding: { severity: 'High', kev: { dateAdded: '2099-01-01' } as never }, exposure: 'entry', isTarget: true }));
    expect(a.decision).toBe('Act');
    expect(a.reasons.length).toBeGreaterThanOrEqual(4);
  });
});

describe('technicalImpactFromCvss', () => {
  it.each<[string, string, string[]]>([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 'total', ['C:H']],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N', 'total', ['I:H']],
    ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 'total', ['C:H', 'I:H']],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 'partial', []],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N', 'partial', []],
    ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N', 'total', ['VI:H']],
    ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:H/SI:H/SA:H', 'partial', []],
  ])('%s → %s', (vector, value, matched) => {
    expect(technicalImpactFromCvss(vector)).toEqual({ value, matched });
  });

  it.each([undefined, '', 'AV:N/AC:L/Au:N/C:C/I:C/A:C', 'CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C'])('受け付けない形 %s → undefined', (v) => {
    expect(technicalImpactFromCvss(v)).toBeUndefined();
  });
});

describe('ssvcPointsFor（CVSS ベクターあり）', () => {
  it('ベクターがあれば深刻度より優先し、仮定の印を外す', () => {
    const a = ssvcPointsFor(input({ finding: { severity: 'Critical', cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' } }));
    expect(a.points.technicalImpact).toBe('partial');
    expect(a.assumed.technicalImpact).toBe(false);
    expect(a.reasons.some((r) => r.startsWith('Technical Impact=partial：CVSS'))).toBe(true);
  });

  it('Low でも C:H があれば total、根拠に指標を書く', () => {
    const a = ssvcPointsFor(input({ finding: { severity: 'Low', cvss: 'CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N' } }));
    expect(a.points.technicalImpact).toBe('total');
    expect(a.assumed.technicalImpact).toBe(false);
    expect(a.reasons).toContain('Technical Impact=total：CVSS ベクターに C:H がある');
  });
});
