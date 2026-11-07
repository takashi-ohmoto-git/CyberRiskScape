import { describe, expect, it } from 'vitest';
import { detectThreats } from './detectThreats';
import type { DiagramEdge, DiagramNode } from '../model/types';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';

/**
 * ソース監査の対応表の見直し（2026-11-07）で足した 2 ルールの発火確認。
 * - dev-agent-action-budget-001（AGENT の運用状況 agentActionBudget。未入力で発火・Enforced で消える）
 * - api-webhook-source-authenticity-001（SaaS・外部 → BACKEND_API / PROCESS で認証 None のとき発火）
 */

const fire = (id: string, nodes: DiagramNode[], edges: DiagramEdge[] = []) => {
  const rule = BUNDLED_THREAT_LIBRARY.rules.find((r) => r.id === id);
  expect(rule).toBeDefined();
  return detectThreats({ nodes, edges, framework: 'ALL', rules: [rule!] });
};

describe('dev-agent-action-budget-001（エージェントの行動予算）', () => {
  const id = 'dev-agent-action-budget-001';
  const agent: DiagramNode = { id: 'a', type: 'AGENT', x: 0, y: 0 };

  it('未入力は上限なしとして発火し、運用状況の印が付く', () => {
    const r = fire(id, [agent]);
    expect(r).toHaveLength(1);
    expect(r[0].assumptionFlags).toEqual(['posture']);
  });

  it('None は発火し、Enforced で消える', () => {
    expect(fire(id, [{ ...agent, posture: { agentActionBudget: 'None' } }])).toHaveLength(1);
    expect(fire(id, [{ ...agent, posture: { agentActionBudget: 'Enforced' } }])).toHaveLength(0);
  });

  it('AGENT 以外の型では発火しない', () => {
    expect(fire(id, [{ id: 'd', type: 'DATABASE', x: 0, y: 0 }])).toHaveLength(0);
  });

  it('canonicalId は新グループ agent-action-budget-gap（権限過剰のカードとは別）', () => {
    const rule = BUNDLED_THREAT_LIBRARY.rules.find((r) => r.id === id);
    expect(rule?.canonicalId).toBe('agent-action-budget-gap');
  });
});

describe('api-webhook-source-authenticity-001（イベントの送信元の真正性）', () => {
  const id = 'api-webhook-source-authenticity-001';
  const node = (nid: string, type: DiagramNode['type']): DiagramNode => ({ id: nid, type, x: 0, y: 0 });
  const edge = (source: string, target: string, auth: DiagramEdge['auth']): DiagramEdge => ({
    id: `${source}-${target}`,
    source,
    target,
    auth,
    network: 'Internet',
    encryption: 'TLS',
  });

  it.each(['SAAS', 'EXTERNAL_ENTITY', 'CRM', 'CHAT', 'MAIL', 'OTHER_APP'] as const)(
    '%s → BACKEND_API で認証 None のとき発火する',
    (type) => {
      const r = fire(id, [node('s', type), node('api', 'BACKEND_API')], [edge('s', 'api', 'None')]);
      expect(r).toHaveLength(1);
    },
  );

  it('GATEWAY・OTHER_APP への経路でも発火する', () => {
    expect(fire(id, [node('s', 'SAAS'), node('g', 'GATEWAY')], [edge('s', 'g', 'None')])).toHaveLength(1);
    expect(fire(id, [node('s', 'SAAS'), node('o', 'OTHER_APP')], [edge('s', 'o', 'None')])).toHaveLength(1);
  });

  it('PROCESS への経路でも発火する', () => {
    expect(fire(id, [node('s', 'SAAS'), node('p', 'PROCESS')], [edge('s', 'p', 'None')])).toHaveLength(1);
  });

  it.each(['Token', 'ApiKey', 'Certificate'] as const)('認証が %s なら発火しない', (auth) => {
    expect(fire(id, [node('s', 'SAAS'), node('api', 'BACKEND_API')], [edge('s', 'api', auth)])).toHaveLength(0);
  });

  it('API → SaaS の線でも dataFlow が inbound（SaaS から API へ流れる）なら発火し、bidirectional でも発火する', () => {
    const e = (dataFlow: DiagramEdge['dataFlow']): DiagramEdge => ({ ...edge('api', 's', 'None'), dataFlow });
    const nodes = [node('s', 'SAAS'), node('api', 'BACKEND_API')];
    expect(fire(id, nodes, [e('inbound')])).toHaveLength(1);
    expect(fire(id, nodes, [e('bidirectional')])).toHaveLength(1);
  });

  it('API → SaaS の線で dataFlow が outbound（API から SaaS へ流れる）なら発火しない', () => {
    const e: DiagramEdge = { ...edge('api', 's', 'None'), dataFlow: 'outbound' };
    expect(fire(id, [node('s', 'SAAS'), node('api', 'BACKEND_API')], [e])).toHaveLength(0);
  });

  it('送り元が SaaS 等でない（USER → BACKEND_API）、または dataFlow 未入力で向きが逆（BACKEND_API → SAAS）なら発火しない', () => {
    expect(fire(id, [node('u', 'USER'), node('api', 'BACKEND_API')], [edge('u', 'api', 'None')])).toHaveLength(0);
    expect(fire(id, [node('s', 'SAAS'), node('api', 'BACKEND_API')], [edge('api', 's', 'None')])).toHaveLength(0);
  });

  it('canonicalId は webhook-signature-verification-gap を再利用している（LINE 専用ルールとは別の subject）', () => {
    const rule = BUNDLED_THREAT_LIBRARY.rules.find((r) => r.id === id);
    expect(rule?.canonicalId).toBe('webhook-signature-verification-gap');
  });
});
