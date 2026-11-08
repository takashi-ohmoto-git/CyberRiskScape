import { describe, expect, it } from 'vitest';
import { detectThreats } from './detectThreats';
import type { DiagramEdge, DiagramNode, NodePosture } from '../model/types';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';

/**
 * 料金が発生する外部機能を上限なく呼ばせる API（api-metered-function-cost-abuse-001、2026-11-08）の発火確認。
 * 「呼ぶ（Yes）」と入力したときだけ発火する例外のルール（未入力では出さない）。
 * 呼ぶと宣言して上限が未入力なら、上限なしと同じ扱いで発火する。
 */

const RULE_ID = 'api-metered-function-cost-abuse-001';

const fire = (type: DiagramNode['type'], posture?: NodePosture, withCaller = true) => {
  const rule = BUNDLED_THREAT_LIBRARY.rules.find((r) => r.id === RULE_ID);
  expect(rule).toBeDefined();
  const nodes: DiagramNode[] = [
    { id: 'u', type: 'SMARTPHONE', x: 0, y: 0 },
    { id: 'n', type, x: 0, y: 0, ...(posture ? { posture } : {}) },
  ];
  const edges: DiagramEdge[] = withCaller
    ? [{ id: 'e', source: 'u', target: 'n', network: 'Internet', encryption: 'TLS', auth: 'Token' }]
    : [];
  return detectThreats({ nodes, edges, framework: 'ALL', rules: [rule!] });
};

describe(RULE_ID, () => {
  it.each(['BACKEND_API', 'FRONT_END_SERVER'] as const)('%s: 呼ぶ＋上限なし → 発火する', (type) => {
    const r = fire(type, { meteredCalls: 'Yes', meteredCallLimit: 'None' });
    expect(r).toHaveLength(1);
    expect(r[0].canonicalId).toBe('metered-function-cost-exhaustion');
  });

  it('未入力 → 発火しない（明示宣言時のみ）', () => {
    expect(fire('BACKEND_API')).toHaveLength(0);
  });

  it('呼ぶ＋上限が未入力 → 上限なしと同じ扱いで発火し、運用状況の印が付く', () => {
    const r = fire('BACKEND_API', { meteredCalls: 'Yes' });
    expect(r).toHaveLength(1);
    expect(r[0].assumptionFlags).toEqual(['posture']);
  });

  it('呼ぶ＋上限を強制 → 発火しない', () => {
    expect(fire('BACKEND_API', { meteredCalls: 'Yes', meteredCallLimit: 'Enforced' })).toHaveLength(0);
  });

  it('呼ばない → 上限が無くても発火しない', () => {
    expect(fire('BACKEND_API', { meteredCalls: 'No', meteredCallLimit: 'None' })).toHaveLength(0);
  });

  it('呼び出し元から受け取る線が無い → 発火しない', () => {
    expect(fire('BACKEND_API', { meteredCalls: 'Yes' }, false)).toHaveLength(0);
  });

  it('運用状況のグループを持たない型 → 発火しない', () => {
    expect(fire('DATABASE', { meteredCalls: 'Yes' })).toHaveLength(0);
  });
});
