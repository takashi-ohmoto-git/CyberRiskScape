import { describe, expect, it } from 'vitest';
import { analyzeCryptoPath } from './analyzeCryptoPath';
import {
  BUNDLED_ALGORITHM_TABLE,
  BUNDLED_TERMINATION_BEHAVIORS,
} from '../../crypto-behavior/bundled';
import type {
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  EdgeCrypto,
  NodeCrypto,
} from '../../core/model/types';

const node = (id: string, type: string, crypto?: NodeCrypto, x = 0): DiagramNode => ({
  id,
  type,
  x,
  y: 0,
  ...(crypto ? { crypto } : {}),
});
const edge = (
  id: string,
  source: string,
  target: string,
  extra: Partial<DiagramEdge> = {},
  crypto?: EdgeCrypto,
): DiagramEdge => ({
  id,
  source,
  target,
  auth: 'None',
  network: 'VPC',
  encryption: 'TLS',
  ...extra,
  ...(crypto ? { crypto } : {}),
});
/** 全ノードを含む Internal 境界（low を作るため）。 */
const internalBoundary: DiagramBoundary = {
  id: 'b-int',
  type: 'RECT',
  x: -1000,
  y: -1000,
  width: 5000,
  height: 5000,
  trustLevel: 'Internal',
};

const run = (
  nodes: DiagramNode[],
  edges: DiagramEdge[],
  sourceId: string,
  targetId: string,
  boundaries: DiagramBoundary[] = [internalBoundary],
) =>
  analyzeCryptoPath({
    nodes,
    edges,
    boundaries,
    sourceId,
    targetId,
    behaviors: BUNDLED_TERMINATION_BEHAVIORS,
    algorithms: BUNDLED_ALGORITHM_TABLE,
  });

const chain = (ids: string[], extra: Partial<DiagramEdge> = {}) =>
  ids.slice(0, -1).map((id, i) => edge(`e${i + 1}`, id, ids[i + 1], extra));

describe('analyzeCryptoPath', () => {
  it('1. L2 スイッチは透過で区間は 1（via に入る）', () => {
    const r = run(
      [node('c', 'PROCESS'), node('sw', 'L2_SWITCH'), node('s', 'PROCESS')],
      chain(['c', 'sw', 's']),
      'c',
      's',
    );
    expect(r.routes).toHaveLength(1);
    expect(r.uniqueSegments).toHaveLength(1);
    expect(r.uniqueSegments[0]).toMatchObject({
      fromNodeId: 'c',
      toNodeId: 's',
      viaNodeIds: ['sw'],
      edgeIds: ['e1', 'e2'],
      startTermination: { value: 'endpoint', confidence: 'endpoint' },
    });
  });

  it('2. CDN→WAF→LB→L2→Web は 4 区間。最後の Plain 区間は plain', () => {
    const ids = ['c', 'cdn', 'waf', 'lb', 'sw', 'web'];
    const types = ['PROCESS', 'CDN', 'WAF', 'LOAD_BALANCER', 'L2_SWITCH', 'PROCESS'];
    const nodes = ids.map((id, i) => node(id, types[i]));
    const edges = chain(ids);
    edges[4] = { ...edges[4], encryption: 'Plain' };
    const r = run(nodes, edges, 'c', 'web');
    const segs = r.routes[0].segments;
    expect(segs).toHaveLength(4);
    expect(segs[3]).toMatchObject({ fromNodeId: 'lb', toNodeId: 'web', viaNodeIds: ['sw'] });
    expect(segs[3].pqc).toBe('plain');
  });

  it('3. LB を passthrough に上書きすると区間が減り、confidence が confirmed になる', () => {
    const mk = (crypto?: NodeCrypto) =>
      run(
        [node('c', 'PROCESS'), node('lb', 'LOAD_BALANCER', crypto), node('s', 'PROCESS')],
        chain(['c', 'lb', 's']),
        'c',
        's',
      );
    const base = mk();
    expect(base.uniqueSegments).toHaveLength(2);
    expect(base.uniqueSegments[1].startTermination).toEqual({
      value: 'terminate',
      confidence: 'default',
    });
    const over = mk({ termination: 'passthrough' });
    expect(over.uniqueSegments).toHaveLength(1);
    expect(over.uniqueSegments[0].viaNodeIds).toEqual(['lb']);
  });

  it('3b. 上書きした終端は confirmed', () => {
    const r = run(
      [node('c', 'PROCESS'), node('lb', 'LOAD_BALANCER', { termination: 'terminate' }), node('s', 'PROCESS')],
      chain(['c', 'lb', 's']),
      'c',
      's',
    );
    expect(r.uniqueSegments[1].startTermination.confidence).toBe('confirmed');
  });

  it('4. FIREWALL を inspect にすると切れて inspect-resign が付く', () => {
    const r = run(
      [
        node('c', 'PROCESS'),
        node('fw', 'FIREWALL', { termination: 'inspect' }),
        node('s', 'PROCESS'),
      ],
      chain(['c', 'fw', 's']),
      'c',
      's',
    );
    expect(r.uniqueSegments).toHaveLength(2);
    expect(r.uniqueSegments[0].warnings).not.toContain('inspect-resign');
    expect(r.uniqueSegments[1].startTermination).toEqual({
      value: 'inspect',
      confidence: 'confirmed',
    });
    expect(r.uniqueSegments[1].warnings).toContain('inspect-resign');
  });

  it('5. WAF を passive-decrypt にすると切れずに警告が付く', () => {
    const r = run(
      [
        node('c', 'PROCESS'),
        node('waf', 'WAF', { termination: 'passive-decrypt' }),
        node('s', 'PROCESS'),
      ],
      chain(['c', 'waf', 's']),
      'c',
      's',
    );
    expect(r.uniqueSegments).toHaveLength(1);
    expect(r.uniqueSegments[0].warnings).toContain('passive-decrypt');
  });

  it('6. VPN_GATEWAY（tunnel）は切れずに outer-tunnel が付く', () => {
    const r = run(
      [node('c', 'PROCESS'), node('vpn', 'VPN_GATEWAY'), node('s', 'PROCESS')],
      chain(['c', 'vpn', 's']),
      'c',
      's',
    );
    expect(r.uniqueSegments).toHaveLength(1);
    expect(r.uniqueSegments[0].viaNodeIds).toEqual(['vpn']);
    expect(r.uniqueSegments[0].warnings).toContain('outer-tunnel');
  });

  it('7. 前後が両方 E2EE なら終端ノードでも切れない', () => {
    const nodes = [node('c', 'PROCESS'), node('lb', 'LOAD_BALANCER'), node('s', 'PROCESS')];
    const both = run(nodes, chain(['c', 'lb', 's'], { encryption: 'E2EE' }), 'c', 's');
    expect(both.uniqueSegments).toHaveLength(1);
    expect(both.uniqueSegments[0].viaNodeIds).toEqual(['lb']);
    const edges = chain(['c', 'lb', 's'], { encryption: 'E2EE' });
    edges[1] = { ...edges[1], encryption: 'TLS' };
    expect(run(nodes, edges, 'c', 's').uniqueSegments).toHaveLength(2);
  });

  it('8. YAML に無い型が途中に来ると unknown として切れる', () => {
    const r = run(
      [node('c', 'PROCESS'), node('db', 'DB'), node('s', 'PROCESS')],
      chain(['c', 'db', 's']),
      'c',
      's',
    );
    expect(r.uniqueSegments).toHaveLength(2);
    expect(r.uniqueSegments[1].startTermination).toEqual({
      value: 'unknown',
      confidence: 'unknown',
    });
  });

  it('9. kex の判定と、混在時は最悪側', () => {
    const nodes = [node('a', 'PROCESS'), node('b', 'PROCESS')];
    const seg = (crypto?: EdgeCrypto) =>
      run(nodes, [edge('e1', 'a', 'b', {}, crypto)], 'a', 'b').uniqueSegments[0];
    expect(seg({ kex: 'X25519MLKEM768' }).pqc).toBe('pqc');
    expect(seg({ kex: 'ECDHE P-256' }).pqc).toBe('vulnerable');
    expect(seg().pqc).toBe('unknown');
    const mixed = run(
      [node('a', 'PROCESS'), node('sw', 'L2_SWITCH'), node('b', 'PROCESS')],
      [
        edge('e1', 'a', 'sw', {}, { kex: 'X25519MLKEM768' }),
        edge('e2', 'sw', 'b', {}, { kex: 'ECDHE P-256' }),
      ],
      'a',
      'b',
    ).uniqueSegments[0];
    expect(mixed.pqc).toBe('vulnerable');
    expect(mixed.kex).toEqual(['X25519MLKEM768', 'ECDHE P-256']);
  });

  it('9b. 署名は edge と終点ノードを集約し、無ければ unknown。混在は警告', () => {
    const edges = [edge('e1', 'a', 'b', {}, { signature: 'ML-DSA-65' })];
    const r = run(
      [node('a', 'PROCESS'), node('b', 'PROCESS', { signature: 'RSA 2048' })],
      edges,
      'a',
      'b',
    );
    expect(r.uniqueSegments[0].signatureClass).toBe('vulnerable');
    expect(r.uniqueSegments[0].signatures).toEqual(['ML-DSA-65']);
    const none = run([node('a', 'PROCESS'), node('b', 'PROCESS')], [edge('e1', 'a', 'b')], 'a', 'b');
    expect(none.uniqueSegments[0].signatureClass).toBe('unknown');
    const mixed = run(
      [node('a', 'PROCESS'), node('sw', 'L2_SWITCH'), node('b', 'PROCESS')],
      [edge('e1', 'a', 'sw'), edge('e2', 'sw', 'b', { encryption: 'Plain' })],
      'a',
      'b',
    );
    expect(mixed.uniqueSegments[0].warnings).toContain('mixed-channel');
    expect(mixed.uniqueSegments[0].protocols).toEqual(['TLS', 'Plain']);
  });

  it('10. probability（Internet 境界 high / Partner medium / Internal low）', () => {
    type T = 'Internet' | 'Partner' | 'Internal';
    const box = (id: string, x: number, trustLevel: T): DiagramBoundary => ({
      id,
      type: 'RECT',
      x,
      y: -200,
      width: 400,
      height: 400,
      trustLevel,
    });
    const nodes = [node('a', 'PROCESS', undefined, 0), node('b', 'PROCESS', undefined, 1000)];
    const edges = [edge('e1', 'a', 'b')];
    const p = (ta: T, tb: T) =>
      run(nodes, edges, 'a', 'b', [box('ba', -100, ta), box('bb', 900, tb)]).uniqueSegments[0]
        .probability;
    expect(p('Internet', 'Internal')).toBe('high');
    expect(p('Internal', 'Partner')).toBe('medium');
    expect(p('Internal', 'Internal')).toBe('low');
    // edge が Internet なら両端 Internal でも high
    const viaNet = run(nodes, [edge('e1', 'a', 'b', { network: 'Internet' })], 'a', 'b', [
      box('ba', -100, 'Internal'),
      box('bb', 900, 'Internal'),
    ]);
    expect(viaNet.uniqueSegments[0].probability).toBe('high');
  });

  it('11. providerManaged は区間の両端のどちらかが provider', () => {
    const mk = (managedBy?: 'self' | 'provider') =>
      run(
        [
          node('a', 'PROCESS'),
          node('lb', 'LOAD_BALANCER', managedBy ? { managedBy } : undefined),
          node('b', 'PROCESS'),
        ],
        chain(['a', 'lb', 'b']),
        'a',
        'b',
      ).uniqueSegments.map((s) => s.providerManaged);
    expect(mk('provider')).toEqual([true, true]);
    expect(mk('self')).toEqual([false, false]);
    expect(mk()).toEqual([false, false]);
  });

  it('12. 逆向きの edge しか無いときは undirectedFallback', () => {
    const nodes = [node('a', 'PROCESS'), node('b', 'PROCESS')];
    const r = run(nodes, [edge('e1', 'b', 'a')], 'a', 'b');
    expect(r.undirectedFallback).toBe(true);
    expect(r.routes).toHaveLength(1);
    expect(run(nodes, [edge('e1', 'a', 'b')], 'a', 'b').undirectedFallback).toBe(false);
  });

  it('13. 並行 edge は 2 経路。同じ区間は uniqueSegments で重複排除される', () => {
    const r = run(
      [node('a', 'PROCESS'), node('lb', 'LOAD_BALANCER'), node('b', 'PROCESS')],
      [edge('e1', 'a', 'lb'), edge('e2', 'a', 'lb'), edge('e3', 'lb', 'b')],
      'a',
      'b',
    );
    expect(r.routes).toHaveLength(2);
    // a→lb は edge ごとに 2 区間、lb→b は共通で 1 区間
    expect(r.uniqueSegments).toHaveLength(3);
  });

  it('14. 送信元と送信先が同一、または存在しない場合は空', () => {
    const nodes = [node('a', 'PROCESS'), node('b', 'PROCESS')];
    const edges = [edge('e1', 'a', 'b')];
    for (const [s, t] of [
      ['a', 'a'],
      ['a', 'zz'],
      ['zz', 'b'],
    ]) {
      expect(run(nodes, edges, s, t)).toEqual({
        routes: [],
        uniqueSegments: [],
        undirectedFallback: false,
        truncated: false,
      });
    }
    expect(run(nodes, [], 'a', 'b').routes).toEqual([]);
  });
});
