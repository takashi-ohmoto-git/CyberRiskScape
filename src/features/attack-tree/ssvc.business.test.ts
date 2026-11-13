import { describe, expect, it } from 'vitest';
import { ssvcPointsFor, type SsvcInput } from './ssvc';
import type { Finding } from '../../core/model/types';

function input(over: Partial<Omit<SsvcInput, 'finding'>> = {}): SsvcInput {
  return {
    finding: {
      id: 'f',
      source: { format: 'cyclonedx', product: 'x', importedAt: '2026-11-01T00:00:00Z' },
      externalId: 'f',
      identifiers: [],
      severity: 'Low',
      canonicalIds: [],
    } as Finding,
    exposure: 'reachable',
    exposureAssumed: false,
    reachesTargets: [],
    chainIndexes: [],
    isTarget: false,
    ...over,
  };
}

describe('ssvcPointsFor（業務の重要度）', () => {
  it('重要度なしは low のまま（既存の挙動）', () => {
    expect(ssvcPointsFor(input()).points.missionWellbeing).toBe('low');
  });

  it('High は low から high に引き上げ、根拠を残す。仮定の印は付けない', () => {
    const a = ssvcPointsFor(input({ businessCriticality: 'High', businessCriticalitySource: 'declared' }));
    expect(a.points.missionWellbeing).toBe('high');
    expect(a.assumed.missionWellbeing).toBe(false);
    expect(a.reasons).toContain('Mission & Well-being=high：業務の重要度 High（表に記載／手入力）');
  });

  it('金額の割合から決めた High は理由にそう書く', () => {
    const a = ssvcPointsFor(input({ businessCriticality: 'High', businessCriticalitySource: 'derived' }));
    expect(a.reasons).toContain('Mission & Well-being=high：業務の重要度 High（金額の割合から）');
  });

  it('Medium は low から medium に引き上げる。既に high なら下げない', () => {
    expect(ssvcPointsFor(input({ businessCriticality: 'Medium' })).points.missionWellbeing).toBe('medium');
    expect(ssvcPointsFor(input({ businessCriticality: 'Medium', isTarget: true })).points.missionWellbeing).toBe('high');
  });

  it('Low は何も変えない', () => {
    const a = ssvcPointsFor(input({ businessCriticality: 'Low' }));
    expect(a.points.missionWellbeing).toBe('low');
    expect(a.reasons.some((r) => r.includes('業務の重要度'))).toBe(false);
  });

  it('評価できず仮定で high のときは、仮定の印を保つ', () => {
    const a = ssvcPointsFor(input({ exposure: 'unbound', businessCriticality: 'High' }));
    expect(a.points.missionWellbeing).toBe('high');
    expect(a.assumed.missionWellbeing).toBe(true);
  });
});
