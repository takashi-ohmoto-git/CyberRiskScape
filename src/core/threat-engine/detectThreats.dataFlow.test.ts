import { describe, expect, it } from 'vitest';
import { detectThreats } from './detectThreats';
import type { DataFlow, DiagramEdge, DiagramNode } from '../model/types';
import { ThreatRuleSchema, type ThreatRule } from '../../threat-library/schema/threatRule';

// エッジのルールの dataFlow 軸（データの流れの向き。§2.120 手順 3）
const nodes: DiagramNode[] = [
  { id: 'saas', type: 'SAAS', x: 0, y: 0 },
  { id: 'api', type: 'BACKEND_API', x: 0, y: 0 },
];

/** 「SaaS が API へ送る」を、描いた向きと流れの向きの両方で受けるルール。 */
const rule: ThreatRule = ThreatRuleSchema.parse({
  id: 'test-sender-receiver-001',
  framework: 'STRIDE',
  category: 'Spoofing',
  severity: 'High',
  description: '送り元の真正性',
  appliesTo: {
    kind: 'edge',
    anyOf: [
      { sourceType: ['SAAS'], targetType: ['BACKEND_API'], dataFlow: ['outbound', 'bidirectional'] },
      { sourceType: ['BACKEND_API'], targetType: ['SAAS'], dataFlow: ['inbound', 'bidirectional'] },
    ],
  },
});

const edge = (source: string, target: string, dataFlow?: DataFlow): DiagramEdge => ({
  id: 'e1',
  source,
  target,
  auth: 'None',
  network: 'Internet',
  encryption: 'TLS',
  ...(dataFlow ? { dataFlow } : {}),
});

const fired = (e: DiagramEdge) => detectThreats({ nodes, edges: [e], framework: 'STRIDE', rules: [rule] }).length > 0;

describe('detectThreats - dataFlow 条件', () => {
  it.each([
    ['SaaS → API・向き未入力（outbound 扱い）→ 発火', edge('saas', 'api'), true],
    ['SaaS → API・outbound → 発火', edge('saas', 'api', 'outbound'), true],
    ['API → SaaS・inbound（SaaS から受ける）→ 発火', edge('api', 'saas', 'inbound'), true],
    ['API → SaaS・bidirectional → 発火', edge('api', 'saas', 'bidirectional'), true],
    ['API → SaaS・向き未入力（API が送る）→ 発火しない', edge('api', 'saas'), false],
    ['SaaS → API・inbound（API が送る）→ 発火しない', edge('saas', 'api', 'inbound'), false],
  ])('%s', (_label, e, expected) => {
    expect(fired(e)).toBe(expected);
  });

  it('dataFlow の値が列挙に無いルールはスキーマで拒否する', () => {
    const bad = { ...rule, appliesTo: { kind: 'edge', when: { dataFlow: ['sideways'] } } };
    expect(ThreatRuleSchema.safeParse(bad).success).toBe(false);
  });
});
