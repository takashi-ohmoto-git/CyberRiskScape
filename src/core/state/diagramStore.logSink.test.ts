import { beforeEach, describe, expect, it } from 'vitest';
import { selectActiveNodes, useDiagramStore } from './diagramStore';
import { EMPTY_LAYER, type LayerData } from '../model/types';

const SRC: LayerData = {
  nodes: [
    { id: 'pc', seq: 1, type: 'PC', x: 0, y: 0, logSinkId: 'siem' },
    { id: 'siem', seq: 2, type: 'SIEM', x: 100, y: 0 },
    { id: 'srv', seq: 3, type: 'PROCESS', x: 200, y: 0, logSinkId: 'siem' },
  ],
  edges: [],
  boundaries: [],
  annotations: [],
};

beforeEach(() => {
  useDiagramStore.setState({
    layers: { L0: EMPTY_LAYER, L1: SRC, L2: EMPTY_LAYER, L3: EMPTY_LAYER, PQC: EMPTY_LAYER },
    activeLayer: 'L1',
    idCounters: {
      L0: { node: 0, edge: 0, boundary: 0 },
      L1: { node: 3, edge: 0, boundary: 0 },
      L2: { node: 0, edge: 0, boundary: 0 },
      L3: { node: 0, edge: 0, boundary: 0 },
      PQC: { node: 0, edge: 0, boundary: 0 },
    },
    manualThreats: { L0: [], L1: [], L2: [], L3: [], PQC: [] },
    suppressions: {},
    selectedNodeIds: [],
    selectedEdgeId: null,
    selectedBoundaryIds: [],
    past: [],
    future: [],
    _dragArmed: false,
    _commitTag: null,
  });
});

const st = () => useDiagramStore.getState();

describe('logSinkId の参照整合性', () => {
  it('送信先の SIEM を削除すると送り元の logSinkId が解除される', () => {
    st().deleteNode('siem');
    const nodes = selectActiveNodes(st());
    expect(nodes).toHaveLength(2);
    for (const n of nodes) expect(n.logSinkId).toBeUndefined();
  });

  it('無関係なノードの削除では logSinkId を保持する', () => {
    st().deleteNode('srv');
    expect(selectActiveNodes(st()).find((n) => n.id === 'pc')?.logSinkId).toBe('siem');
  });

  it('copyLayer で logSinkId が複製先の新しい id に付け替わる', () => {
    st().copyLayer('L1', 'PQC');
    const dst = st().layers.PQC.nodes;
    const siem = dst.find((n) => n.type === 'SIEM')!;
    expect(siem.id).not.toBe('siem');
    for (const n of dst.filter((x) => x.type !== 'SIEM')) expect(n.logSinkId).toBe(siem.id);
  });

  it('importTemplateToActiveLayer で logSinkId を付け替え、テンプレート外の参照は解除する', () => {
    const tpl: LayerData = {
      ...SRC,
      nodes: [...SRC.nodes, { id: 'x', seq: 4, type: 'PC', x: 0, y: 0, logSinkId: 'outside' }],
    };
    st().importTemplateToActiveLayer(tpl);
    const nodes = selectActiveNodes(st());
    const siem = nodes.find((n) => n.type === 'SIEM')!;
    const pcs = nodes.filter((n) => n.type === 'PC');
    expect(pcs.map((n) => n.logSinkId)).toContain(siem.id);
    expect(pcs.map((n) => n.logSinkId)).toContain(undefined);
    expect(nodes.find((n) => n.type === 'PROCESS')!.logSinkId).toBe(siem.id);
  });
});
