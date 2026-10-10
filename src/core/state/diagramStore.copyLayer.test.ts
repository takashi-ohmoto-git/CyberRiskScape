import { beforeEach, describe, expect, it } from 'vitest';
import { useDiagramStore } from './diagramStore';
import { EMPTY_LAYER, type LayerData } from '../model/types';

const SRC: LayerData = {
  nodes: [
    { id: 'a', seq: 3, type: 'USER', x: 0, y: 0, authProviderId: 'idp' },
    { id: 'idp', seq: 4, type: 'IDP', x: 10, y: 0, label: 'IdP', parentId: 'a' },
    { id: 'c', seq: 7, type: 'LLM', x: 20, y: 0, attackObjectiveId: 'a' },
  ],
  edges: [
    {
      id: 'e1',
      seq: 2,
      source: 'a',
      target: 'c',
      auth: 'Password',
      network: 'VPC',
      encryption: 'TLS',
      authProviderId: 'idp',
    },
  ],
  boundaries: [
    { id: 'b1', seq: 5, type: 'RECT', x: 0, y: 0, width: 100, height: 100, trustLevel: 'Internal' },
  ],
  annotations: [{ id: 'ann1', kind: 'callout', x: 1, y: 1, text: 't', targetNodeId: 'c' }],
};

beforeEach(() => {
  useDiagramStore.setState({
    layers: { L0: EMPTY_LAYER, L1: SRC, L2: EMPTY_LAYER, L3: EMPTY_LAYER, PQC: EMPTY_LAYER },
    activeLayer: 'L1',
    idCounters: {
      L0: { node: 0, edge: 0, boundary: 0 },
      L1: { node: 7, edge: 2, boundary: 5 },
      L2: { node: 0, edge: 0, boundary: 0 },
      L3: { node: 0, edge: 0, boundary: 0 },
      PQC: { node: 10, edge: 1, boundary: 0 },
    },
    manualThreats: { L0: [], L1: [], L2: [], L3: [], PQC: [] },
    suppressions: {},
    past: [],
    future: [],
    _commitTag: null,
  });
});

const st = () => useDiagramStore.getState();

describe('copyLayer', () => {
  it('複製先を置き換え、アクティブレイヤーを複製先へ切り替える', () => {
    st().copyLayer('L1', 'PQC');
    const dst = st().layers.PQC;
    expect(dst.nodes).toHaveLength(3);
    expect(dst.edges).toHaveLength(1);
    expect(dst.boundaries).toHaveLength(1);
    expect(dst.annotations).toHaveLength(1);
    expect(st().activeLayer).toBe('PQC');
  });

  it('既存の複製先は丸ごと置き換わる', () => {
    useDiagramStore.setState((s) => ({
      layers: {
        ...s.layers,
        PQC: { ...EMPTY_LAYER, nodes: [{ id: 'old', seq: 1, type: 'DB', x: 0, y: 0 }] },
      },
    }));
    st().copyLayer('L1', 'PQC');
    expect(st().layers.PQC.nodes.some((n) => n.id === 'old')).toBe(false);
  });

  it('seq と全フィールドが保たれる', () => {
    st().copyLayer('L1', 'PQC');
    const dst = st().layers.PQC;
    expect(dst.nodes.map((n) => n.seq)).toEqual([3, 4, 7]);
    expect(dst.nodes[1].label).toBe('IdP');
    expect(dst.edges[0].seq).toBe(2);
    expect(dst.edges[0].encryption).toBe('TLS');
    expect(dst.boundaries[0].seq).toBe(5);
    expect(dst.boundaries[0].width).toBe(100);
  });

  it('カウンタは種別ごとに複製元と複製先の大きいほう', () => {
    st().copyLayer('L1', 'PQC');
    expect(st().idCounters.PQC).toEqual({ node: 10, edge: 2, boundary: 5 });
    expect(st().idCounters.L1).toEqual({ node: 7, edge: 2, boundary: 5 });
  });

  it('内部 id を振り直し、参照が複製先の中で一貫して付け替わる', () => {
    st().copyLayer('L1', 'PQC');
    const dst = st().layers.PQC;
    const [a, idp, c] = dst.nodes;
    const srcIds = new Set(['a', 'idp', 'c', 'e1', 'b1', 'ann1']);
    for (const x of [...dst.nodes, ...dst.edges, ...dst.boundaries, ...dst.annotations]) {
      expect(srcIds.has(x.id)).toBe(false);
    }
    expect(a.authProviderId).toBe(idp.id);
    expect(idp.parentId).toBe(a.id);
    expect(c.attackObjectiveId).toBe(a.id);
    expect(dst.edges[0].source).toBe(a.id);
    expect(dst.edges[0].target).toBe(c.id);
    expect(dst.edges[0].authProviderId).toBe(idp.id);
    expect(dst.annotations[0].targetNodeId).toBe(c.id);
  });

  it('複製元は変わらず、ディープコピーで互いに影響しない', () => {
    st().copyLayer('L1', 'PQC');
    expect(st().layers.L1).toEqual(SRC);
    st().updateNode(st().layers.PQC.nodes[0].id, 'label', 'changed');
    expect(st().layers.L1.nodes[0].label).toBeUndefined();
  });

  it('手動脅威は複製されない（抑制状態も複製先へ漏れない）', () => {
    useDiagramStore.setState((s) => ({
      manualThreats: { ...s.manualThreats, L1: [{ id: 'm1' } as never] },
      suppressions: { 'R-a': { status: 'accepted' } as never },
    }));
    st().copyLayer('L1', 'PQC');
    expect(st().manualThreats.PQC).toEqual([]);
    expect(Object.keys(st().suppressions)).toEqual(['R-a']);
    expect(st().layers.PQC.nodes.some((n) => n.id === 'a')).toBe(false);
  });

  it('undo で元に戻る', () => {
    st().copyLayer('L1', 'PQC');
    st().undo();
    expect(st().layers.PQC).toEqual(EMPTY_LAYER);
  });

  it('from === to では何もしない', () => {
    st().copyLayer('L1', 'L1');
    expect(st().layers.L1).toBe(SRC);
    expect(st().past).toHaveLength(0);
  });
});
