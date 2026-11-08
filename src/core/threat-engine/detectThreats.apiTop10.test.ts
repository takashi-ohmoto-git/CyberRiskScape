import { describe, expect, it } from 'vitest';
import { detectThreats } from './detectThreats';
import type { DiagramEdge, DiagramNode } from '../model/types';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';

/**
 * OWASP API Security Top 10 2023 の穴埋め（2026-11-08）の発火確認。
 * API10 外部 API の応答の信用・API2 再認証の欠如・API8 CORS の設定不備・API9 SaaS・委託先に預けたデータの漏えい・API6 機微な業務フローの自動化。
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
const edge = (source: string, target: string, extra: Partial<DiagramEdge> = {}): DiagramEdge => ({
  id: `${source}-${target}`,
  source,
  target,
  network: 'Internet',
  encryption: 'TLS',
  auth: 'Token',
  ...extra,
});

describe('api-third-party-response-trust-001', () => {
  const id = 'api-third-party-response-trust-001';

  it.each(['SAAS', 'EXTERNAL_ENTITY', 'CRM'] as const)('BACKEND_API が %s とつながる → 発火する', (peer) => {
    const r = fire(id, [node('a', 'BACKEND_API'), node('s', peer)], [edge('a', 's')]);
    expect(r).toHaveLength(1);
    expect(r[0].canonicalId).toBe('third-party-api-response-trust');
  });

  it('外部から送られてくる向き（SaaS → API）でも発火する', () => {
    expect(fire(id, [node('a', 'BACKEND_API'), node('s', 'SAAS')], [edge('s', 'a')])).toHaveLength(1);
  });

  it('FRONT_END_SERVER も対象', () => {
    expect(fire(id, [node('f', 'FRONT_END_SERVER'), node('s', 'SAAS')], [edge('f', 's')])).toHaveLength(1);
  });

  it('内部の DB とだけつながる → 発火しない', () => {
    expect(fire(id, [node('a', 'BACKEND_API'), node('d', 'DATABASE')], [edge('a', 'd')])).toHaveLength(0);
  });
});

describe('api-sensitive-account-change-reauth-001', () => {
  const id = 'api-sensitive-account-change-reauth-001';

  it('利用者の端末から呼ばれる BACKEND_API → 発火する', () => {
    const r = fire(id, [node('u', 'SMARTPHONE'), node('a', 'BACKEND_API')], [edge('u', 'a')]);
    expect(r).toHaveLength(1);
    expect(r[0].canonicalId).toBe('sensitive-account-change-without-reauth');
  });

  it('ゲートウェイの背後の BACKEND_API で発火し、ゲートウェイ自身には出ない', () => {
    const nodes = [node('u', 'PC'), node('g', 'GATEWAY'), node('a', 'BACKEND_API')];
    const r = fire(id, nodes, [edge('u', 'g'), edge('g', 'a', { network: 'VPC' })]);
    expect(r.map((t) => t.nodeId)).toEqual(['a']);
  });

  it('内部のサービスからだけ呼ばれる → 発火しない', () => {
    expect(fire(id, [node('o', 'OTHER_APP'), node('a', 'BACKEND_API')], [edge('o', 'a', { network: 'VPC' })])).toHaveLength(0);
  });
});

describe('zt-saas-third-party-data-exposure-001', () => {
  const id = 'zt-saas-third-party-data-exposure-001';

  it.each(['PERSONAL_INFO', 'CONFIDENTIAL_INFO', 'VOICE_RECORDING', 'SOURCE_CODE'] as const)(
    '%s を内包する SAAS → 接続が無くても発火する',
    (child) => {
      const r = fire(id, [node('s', 'SAAS'), node('c', child, { parentId: 's' })], []);
      expect(r).toHaveLength(1);
      expect(r[0].canonicalId).toBe('third-party-held-data-exposure');
    },
  );

  it('個人情報を内包する CRM → 発火する', () => {
    const r = fire(id, [node('m', 'CRM'), node('c', 'PERSONAL_INFO', { parentId: 'm' })], []);
    expect(r).toHaveLength(1);
  });

  it('何も内包しない CRM → 発火しない', () => {
    expect(fire(id, [node('m', 'CRM')], [])).toHaveLength(0);
  });

  it('預けるデータを内包しない SAAS → 発火しない', () => {
    expect(fire(id, [node('s', 'SAAS'), node('c', 'LOG', { parentId: 's' })], [])).toHaveLength(0);
  });

  it('自組織の DATABASE が個人情報を内包 → 発火しない', () => {
    expect(fire(id, [node('d', 'DATABASE'), node('c', 'PERSONAL_INFO', { parentId: 'd' })], [])).toHaveLength(0);
  });
});

describe('api-sensitive-business-flow-abuse-001', () => {
  const id = 'api-sensitive-business-flow-abuse-001';
  const run = (type: DiagramNode['type'], posture?: DiagramNode['posture'], withCaller = true) =>
    fire(id, [node('u', 'PC'), node('a', type, posture ? { posture } : {})], withCaller ? [edge('u', 'a')] : []);

  it.each(['BACKEND_API', 'FRONT_END_SERVER'] as const)('%s: 持つ＋対策なし → 発火する', (type) => {
    const r = run(type, { sensitiveBusinessFlow: 'Yes', businessFlowProtection: 'None' });
    expect(r).toHaveLength(1);
    expect(r[0].canonicalId).toBe('sensitive-business-flow-automation');
  });

  it('未入力 → 発火しない（明示宣言時のみ）', () => {
    expect(run('BACKEND_API')).toHaveLength(0);
  });

  it('持つ＋対策が未入力 → 対策なしと同じ扱いで発火し、運用状況の印が付く', () => {
    const r = run('BACKEND_API', { sensitiveBusinessFlow: 'Yes' });
    expect(r).toHaveLength(1);
    expect(r[0].assumptionFlags).toEqual(['posture']);
  });

  it('持つ＋対策して強制・持たない・呼び出し元の線が無い → 発火しない', () => {
    expect(run('BACKEND_API', { sensitiveBusinessFlow: 'Yes', businessFlowProtection: 'Enforced' })).toHaveLength(0);
    expect(run('BACKEND_API', { sensitiveBusinessFlow: 'No', businessFlowProtection: 'None' })).toHaveLength(0);
    expect(run('BACKEND_API', { sensitiveBusinessFlow: 'Yes' }, false)).toHaveLength(0);
  });
});

describe('api-cors-misconfiguration-001', () => {
  const id = 'api-cors-misconfiguration-001';

  it.each(['PC', 'USER'] as const)('%s → BACKEND_API（公衆網）→ 発火する', (src) => {
    const r = fire(id, [node('u', src), node('a', 'BACKEND_API')], [edge('u', 'a')]);
    expect(r).toHaveLength(1);
    expect(r[0].canonicalId).toBe('api-cors-misconfiguration');
  });

  it('社員と宣言した利用者でも発火する（ブラウザの被害者になりうる）', () => {
    const r = fire(id, [node('u', 'USER', { userTrustAttribute: 'Employee' }), node('g', 'GATEWAY')], [edge('u', 'g')]);
    expect(r).toHaveLength(1);
  });

  it('スマートフォン（アプリ）からの線・VPN の線では発火しない', () => {
    expect(fire(id, [node('u', 'SMARTPHONE'), node('a', 'BACKEND_API')], [edge('u', 'a')])).toHaveLength(0);
    expect(fire(id, [node('u', 'PC'), node('a', 'BACKEND_API')], [edge('u', 'a', { network: 'VPN' })])).toHaveLength(0);
  });
});
