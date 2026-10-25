import { describe, expect, it } from 'vitest';
import type { Severity, ThreatView } from '../../core/model/types';
import { sortThreatsBySeverity } from './sortThreatsBySeverity';

const threat = (id: string, severity: Severity, suppressed = false): ThreatView =>
  ({
    id,
    severity,
    ...(suppressed ? { suppression: { status: 'accepted' } } : {}),
  }) as unknown as ThreatView;

describe('sortThreatsBySeverity', () => {
  it('Critical → High → Medium → Low の順に並べ、同順位は元の順を保つ', () => {
    const sorted = sortThreatsBySeverity([
      threat('a', 'Low'),
      threat('b', 'High'),
      threat('c', 'Medium'),
      threat('d', 'Critical'),
      threat('e', 'High'),
    ]);
    expect(sorted.map((t) => t.id)).toEqual(['d', 'b', 'e', 'c', 'a']);
  });

  it('抑制済み（受容・誤検知）は重大度に関わらず末尾に回す', () => {
    const sorted = sortThreatsBySeverity([threat('a', 'Critical', true), threat('b', 'Low')]);
    expect(sorted.map((t) => t.id)).toEqual(['b', 'a']);
  });

  it('抑制状態を持たない型（攻撃経路分析の ThreatRef）も重大度順に並べる', () => {
    const sorted = sortThreatsBySeverity([
      { threatId: 'a', severity: 'Medium' as const },
      { threatId: 'b', severity: 'Critical' as const },
    ]);
    expect(sorted.map((t) => t.threatId)).toEqual(['b', 'a']);
  });
});
