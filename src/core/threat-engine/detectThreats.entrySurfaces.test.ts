import { describe, expect, it } from 'vitest';
import { detectThreats } from './detectThreats';
import type { DiagramEdge, DiagramNode } from '../model/types';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';

/**
 * 攻撃経路の入口の高価値の面（docs の攻撃経路分析の設計メモ §14）の穴埋め 4 ルールの発火確認。
 * 競合状態・型の混同・符号化と正規化の境界のずれ・認証前の組み込みルート。
 * いずれも属性が未入力でも発火する（大方針「未入力＝悪い値」）。
 */

const fire = (id: string, nodes: DiagramNode[], edges: DiagramEdge[]) => {
  const rule = BUNDLED_THREAT_LIBRARY.rules.find((r) => r.id === id);
  expect(rule).toBeDefined();
  return detectThreats({ nodes, edges, framework: 'ALL', rules: [rule!] });
};

const node = (id: string, type: DiagramNode['type'], extra: Partial<DiagramNode> = {}): DiagramNode => ({
  id,
  type,
  x: 0,
  y: 0,
  ...extra,
});
const edge = (source: string, target: string): DiagramEdge => ({
  id: `${source}-${target}`,
  source,
  target,
  network: 'Internet',
  encryption: 'TLS',
  auth: 'Token',
});

const appRules = [
  ['api-race-condition-toctou-001', 'request-race-condition'],
  ['api-parameter-type-confusion-001', 'parameter-type-confusion'],
  ['api-input-canonicalization-mismatch-001', 'input-canonicalization-mismatch'],
] as const;

describe.each(appRules)('%s', (id, canonicalId) => {
  it.each(['BACKEND_API', 'FRONT_END_SERVER'] as const)('属性が未入力の %s が要求を受ける → 発火する', (type) => {
    const r = fire(id, [node('u', 'PC'), node('a', type)], [edge('u', 'a')]);
    expect(r).toHaveLength(1);
    expect(r[0].canonicalId).toBe(canonicalId);
  });

  it('要求を送るだけ（受ける線が無い）→ 発火しない', () => {
    expect(fire(id, [node('a', 'BACKEND_API'), node('d', 'DATABASE')], [edge('a', 'd')])).toHaveLength(0);
  });

  it('対象外の型（DATABASE・REVERSE_PROXY）が要求を受けても発火しない', () => {
    const nodes = [node('u', 'PC'), node('p', 'REVERSE_PROXY'), node('d', 'DATABASE')];
    expect(fire(id, nodes, [edge('u', 'p'), edge('u', 'd')])).toHaveLength(0);
  });
});

describe('api-pre-auth-builtin-route-001', () => {
  const id = 'api-pre-auth-builtin-route-001';

  it.each(['FRONT_END_SERVER', 'BACKEND_API', 'ADMIN_CONSOLE', 'API_CONTROL_PLANE', 'GATEWAY'] as const)(
    '属性が未入力の %s が要求を受ける → High で発火する',
    (type) => {
      const r = fire(id, [node('u', 'PC'), node('a', type)], [edge('u', 'a')]);
      expect(r).toHaveLength(1);
      expect(r[0].canonicalId).toBe('pre-auth-builtin-route');
      expect(r[0].severity).toBe('High');
    },
  );

  it('Global IP 無しと明示 → 発火は続き、Medium に下がる', () => {
    const r = fire(id, [node('u', 'PC'), node('a', 'BACKEND_API', { attackSurface: { hasGlobalIp: false } })], [edge('u', 'a')]);
    expect(r).toHaveLength(1);
    expect(r[0].severity).toBe('Medium');
  });

  it('対象外の型（VPN_GATEWAY・DATABASE）では発火しない', () => {
    const nodes = [node('u', 'PC'), node('v', 'VPN_GATEWAY'), node('d', 'DATABASE')];
    expect(fire(id, nodes, [edge('u', 'v'), edge('u', 'd')])).toHaveLength(0);
  });
});
