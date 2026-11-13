import { describe, expect, it } from 'vitest';
import { recommendTargets } from './recommendTargets';
import type { BusinessCriticality, DiagramEdge, DiagramNode, NodeBusinessContext } from '../../core/model/types';

function node(id: string, type: string, extra: Partial<DiagramNode> = {}): DiagramNode {
  return { id, type, x: 0, y: 0, ...extra };
}
function edge(id: string, source: string, target: string): DiagramEdge {
  return { id, source, target, auth: 'None', network: 'VPC', encryption: 'Plain' };
}
const bc = (criticality: BusinessCriticality): NodeBusinessContext => ({
  criticality,
  criticalitySource: 'declared',
  processes: [{ name: 'Order-to-Cash' }],
});

const attacker = node('atk', 'AGENTIC_ATTACKER');
const ids = (r: ReturnType<typeof recommendTargets>) => r.map((c) => c.nodeId);

describe('recommendTargets（業務の重要度）', () => {
  it('業務の重要度が High のノードだけが理由で標的に入る。Medium・Low・未設定は入らない', () => {
    const r = recommendTargets(
      [
        attacker,
        node('erp', 'DATABASE', { businessContext: bc('High') }),
        node('crm', 'DATABASE', { businessContext: bc('Medium') }),
        node('wh', 'DATABASE', { businessContext: bc('Low') }),
        node('none', 'DATABASE'),
      ],
      [],
      [],
      [],
      'atk',
    );
    expect(ids(r)).toEqual(['erp']);
    expect(r[0]).toMatchObject({ category: 'business', reasons: ['businessCritical'] });
  });

  it('カテゴリの順は 認証系 → 業務上重要 → データ系（到達性が同じとき）', () => {
    const r = recommendTargets(
      [
        attacker,
        node('data', 'DATABASE', { seq: 1 }),
        node('pii', 'PERSONAL_INFO', { parentId: 'data' }),
        node('erp', 'DATABASE', { seq: 2, businessContext: bc('High') }),
        node('vault', 'SECRETS_VAULT', { seq: 3 }),
      ],
      [],
      [],
      [],
      'atk',
    );
    expect(r.map((c) => c.category)).toEqual(['credential', 'business', 'data']);
    expect(ids(r)).toEqual(['vault', 'erp', 'data']);
  });

  it('認証系かつ High のノードは認証系のまま、理由を両方持つ', () => {
    const r = recommendTargets([attacker, node('idp', 'IDENTITY_PROVIDER', { businessContext: bc('High') })], [], [], [], 'atk');
    expect(r[0]).toMatchObject({ category: 'credential', reasons: ['credentialHolder', 'businessCritical'] });
  });

  it('標的にしない型（利用者の端末など）は High でも入らない。到達できれば reachable', () => {
    const r = recommendTargets(
      [attacker, node('pc', 'PC', { businessContext: bc('High') }), node('erp', 'DATABASE', { businessContext: bc('High') })],
      [edge('e1', 'atk', 'erp')],
      [],
      [],
      'atk',
    );
    expect(ids(r)).toEqual(['erp']);
    expect(r[0].reachable).toBe(true);
  });
});
