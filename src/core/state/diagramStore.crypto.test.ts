import { beforeEach, describe, expect, it } from 'vitest';
import { useDiagramStore } from './diagramStore';
import { EMPTY_LAYER, type LayerData } from '../model/types';

const PQC: LayerData = {
  nodes: [
    { id: 'a', seq: 1, type: 'USER', x: 0, y: 0 },
    { id: 'lb', seq: 2, type: 'LOAD_BALANCER', x: 10, y: 0, crypto: { termination: 'passthrough' } },
    { id: 'c', seq: 3, type: 'DB', x: 20, y: 0 },
  ],
  edges: [
    {
      id: 'e1',
      seq: 1,
      source: 'a',
      target: 'lb',
      auth: 'None',
      network: 'Internet',
      encryption: 'TLS',
      crypto: { protocol: 'TLS', kex: 'X25519MLKEM768' },
    },
  ],
  boundaries: [],
  annotations: [],
  cryptoFlows: [
    { id: 'f1', sourceId: 'a', targetId: 'c', label: '利用者→DB' },
    { id: 'f2', sourceId: 'a', targetId: 'lb' },
  ],
};

beforeEach(() => {
  useDiagramStore.setState({
    layers: { L0: EMPTY_LAYER, L1: EMPTY_LAYER, L2: EMPTY_LAYER, L3: EMPTY_LAYER, PQC },
    activeLayer: 'PQC',
    idCounters: {
      L0: { node: 0, edge: 0, boundary: 0 },
      L1: { node: 0, edge: 0, boundary: 0 },
      L2: { node: 0, edge: 0, boundary: 0 },
      L3: { node: 0, edge: 0, boundary: 0 },
      PQC: { node: 3, edge: 1, boundary: 0 },
    },
    manualThreats: { L0: [], L1: [], L2: [], L3: [], PQC: [] },
    suppressions: {},
    past: [],
    future: [],
    _commitTag: null,
  });
});

const st = () => useDiagramStore.getState();

describe('暗号属性（PQC）のストア操作', () => {
  it('updateNode / updateEdge の汎用更新で crypto を設定・削除できる', () => {
    st().updateNode('a', 'crypto', { managedBy: 'provider' });
    expect(st().layers.PQC.nodes[0].crypto).toEqual({ managedBy: 'provider' });
    st().updateNode('a', 'crypto', undefined);
    expect(st().layers.PQC.nodes[0].crypto).toBeUndefined();
    st().updateEdge('e1', 'crypto', { kex: 'ECDHE P-256' });
    expect(st().layers.PQC.edges[0].crypto).toEqual({ kex: 'ECDHE P-256' });
  });

  it('addCryptoFlow / removeCryptoFlow', () => {
    st().addCryptoFlow({ sourceId: 'lb', targetId: 'c' });
    const flows = st().layers.PQC.cryptoFlows ?? [];
    expect(flows).toHaveLength(3);
    const added = flows[2];
    expect(added.id).toBeTruthy();
    st().removeCryptoFlow(added.id);
    expect(st().layers.PQC.cryptoFlows).toHaveLength(2);
  });

  it('deleteNode は、そのノードを端点とする cryptoFlows を消す', () => {
    st().deleteNode('c');
    expect(st().layers.PQC.cryptoFlows?.map((f) => f.id)).toEqual(['f2']);
    st().deleteNode('lb');
    expect(st().layers.PQC.cryptoFlows).toEqual([]);
  });

  it('copyLayer は cryptoFlows の端点を新しい id へ付け替え、crypto 属性も保つ', () => {
    st().copyLayer('PQC', 'L1');
    const dst = st().layers.L1;
    const [a, lb, c] = dst.nodes;
    expect(dst.cryptoFlows).toHaveLength(2);
    expect(dst.cryptoFlows?.[0]).toMatchObject({ sourceId: a.id, targetId: c.id, label: '利用者→DB' });
    expect(dst.cryptoFlows?.[1]).toMatchObject({ sourceId: a.id, targetId: lb.id });
    expect(dst.cryptoFlows?.map((f) => f.id)).not.toContain('f1');
    expect(lb.crypto).toEqual({ termination: 'passthrough' });
    expect(dst.edges[0].crypto).toEqual({ protocol: 'TLS', kex: 'X25519MLKEM768' });
  });

  it('copyLayer は参照先が無いフローを落とし、フローが無ければ cryptoFlows を持たない', () => {
    useDiagramStore.setState((s) => ({
      layers: {
        ...s.layers,
        PQC: { ...PQC, cryptoFlows: [{ id: 'bad', sourceId: 'a', targetId: 'ghost' }] },
      },
    }));
    st().copyLayer('PQC', 'L1');
    expect(st().layers.L1.cryptoFlows).toBeUndefined();
  });

  it('importTemplateToActiveLayer はレイヤーを置換するので cryptoFlows は残らない（ノード crypto は引き継ぐ）', () => {
    st().importTemplateToActiveLayer({
      nodes: [{ id: 'x', type: 'LOAD_BALANCER', x: 0, y: 0, crypto: { termination: 'terminate' } }],
      edges: [],
      boundaries: [],
      annotations: [],
    });
    expect(st().layers.PQC.cryptoFlows).toBeUndefined();
    expect(st().layers.PQC.nodes[0].crypto).toEqual({ termination: 'terminate' });
  });
});
