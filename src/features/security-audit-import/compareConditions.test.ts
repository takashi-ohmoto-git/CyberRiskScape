import { describe, expect, it } from 'vitest';
import type { DiagramBoundary, DiagramEdge, DiagramNode, Finding, LayerData } from '../../core/model/types';
import { compareConditions } from './compareConditions';

const node = (id: string, x: number, extra: Partial<DiagramNode> = {}): DiagramNode => ({ id, type: 'BACKEND_API', x, y: 50, ...extra });
const edge = (id: string, source: string, target: string, extra: Partial<DiagramEdge> = {}): DiagramEdge => ({
  id,
  source,
  target,
  auth: 'None',
  network: 'Internet',
  encryption: 'TLS',
  ...extra,
});
const internal: DiagramBoundary = { id: 'z1', type: 'RECT', x: 400, y: 0, width: 800, height: 300, trustLevel: 'Internal' };

function layer(extra: Partial<LayerData> = {}): LayerData {
  return {
    // ext は境界の外（Internet）、api / db は内側
    nodes: [node('ext', 0, { type: 'USER' }), node('api', 500, { attackSurface: { hasGlobalIp: true } }), node('db', 800, { type: 'DATABASE' })],
    edges: [edge('e1', 'ext', 'api', { auth: 'ApiKey' }), edge('e2', 'api', 'db', { auth: 'Password', network: 'VPC' })],
    boundaries: [internal],
    annotations: [],
    ...extra,
  };
}

const finding = (extra: Partial<Finding> = {}): Finding => ({
  id: 'x:1',
  source: { format: 'security-audit', product: 'x', importedAt: 'now' },
  externalId: '1',
  identifiers: [],
  severity: 'High',
  canonicalIds: [],
  subject: { layer: 'L1', nodeId: 'api' },
  conditions: [
    { kind: 'reachability', text: 'public' },
    { kind: 'authentication', text: 'any user' },
    { kind: 'authorization', text: 'role' },
    { kind: 'configuration', text: 'flag' },
    { kind: 'user-interaction', text: 'click' },
    { kind: 'other', text: 'timing' },
  ],
  openQuestions: ['q1'],
  ...extra,
});

describe('compareConditions', () => {
  it('reachability → ノードの境界・入る接続の相手の境界・経路・攻撃面属性を並べる', () => {
    const r = compareConditions(finding(), layer());
    const facts = r.conditions[0].diagramFacts;
    expect(facts).toContainEqual({ key: 'reachability.nodeTrust', params: { trust: 'Internal' } });
    expect(facts).toContainEqual({ key: 'reachability.peerTrust', params: { trust: 'Internet', count: 1 } });
    expect(facts).toContainEqual({ key: 'reachability.edgeNetwork', params: { network: 'Internet', count: 1 } });
    expect(facts).toContainEqual({ key: 'reachability.attackSurface', params: { name: 'hasGlobalIp', value: true } });
    expect(facts).toContainEqual({ key: 'reachability.attackSurfaceUnset', params: { name: 'hasWafProtection' } });
  });

  it('authentication → ノードへ入る接続の認証ごとの本数（出ていく接続は数えない）', () => {
    const r = compareConditions(finding(), layer());
    expect(r.conditions[1].diagramFacts).toEqual([{ key: 'authentication.edgeAuth', params: { auth: 'ApiKey', count: 1 } }]);
  });

  it('dataFlow が inbound の接続は向きを逆にして数える', () => {
    const l = layer({ edges: [edge('e1', 'api', 'ext', { dataFlow: 'inbound', auth: 'Token' })] });
    expect(compareConditions(finding(), l).conditions[1].diagramFacts).toEqual([
      { key: 'authentication.edgeAuth', params: { auth: 'Token', count: 1 } },
    ]);
  });

  it('入る接続が無い → edge.noIncoming', () => {
    const l = layer({ edges: [] });
    expect(compareConditions(finding(), l).conditions[1].diagramFacts).toEqual([{ key: 'edge.noIncoming' }]);
  });

  it('authorization・configuration → 運用状況の入力済みの値、無ければ posture.none', () => {
    const withPosture = layer({ nodes: [node('api', 500, { posture: { encryptionAtRest: 'None' } })] });
    const r = compareConditions(finding(), withPosture);
    expect(r.conditions[2].diagramFacts).toEqual([{ key: 'posture.value', params: { name: 'encryptionAtRest', value: 'None' } }]);
    expect(r.conditions[3].diagramFacts).toEqual(r.conditions[2].diagramFacts);
    expect(compareConditions(finding(), layer()).conditions[2].diagramFacts).toEqual([{ key: 'posture.none' }]);
  });

  it('user-interaction・other → 図の事実なし。openQuestions は文だけ', () => {
    const r = compareConditions(finding(), layer());
    expect(r.conditions[4].diagramFacts).toEqual([]);
    expect(r.conditions[5].diagramFacts).toEqual([]);
    expect(r.openQuestions).toEqual([{ kind: 'other', text: 'q1', diagramFacts: [] }]);
  });

  it('ノードに結びついていない・図に無い → その旨の事実だけ（判定語は出さない）', () => {
    const unlinked = compareConditions(finding({ subject: undefined }), layer());
    expect(unlinked.conditions[0].diagramFacts).toEqual([{ key: 'node.unlinked' }]);
    const missing = compareConditions(finding({ subject: { layer: 'L1', nodeId: 'gone' } }), layer());
    expect(missing.conditions[0].diagramFacts).toEqual([{ key: 'node.notFound' }]);
    expect(compareConditions(finding(), undefined).conditions[0].diagramFacts).toEqual([{ key: 'node.notFound' }]);
  });

  it('conditions・openQuestions が無い指摘 → 空', () => {
    expect(compareConditions(finding({ conditions: undefined, openQuestions: undefined }), layer())).toEqual({ conditions: [], openQuestions: [] });
  });
});
