import { beforeEach, describe, expect, it } from 'vitest';
import {
  selectActiveBoundaries,
  selectActiveEdges,
  selectActiveNodes,
  useDiagramStore,
} from './diagramStore';
import { EMPTY_LAYER } from '../model/types';

/** 各テスト前に空レイヤー + カウンタ 0 の既知状態へリセット（module singleton 対策）。 */
beforeEach(() => {
  useDiagramStore.setState({
    layers: {
      L0: EMPTY_LAYER,
      L1: { nodes: [], edges: [], boundaries: [] },
      L2: { nodes: [], edges: [], boundaries: [] },
      L3: EMPTY_LAYER,
    },
    activeLayer: 'L1',
    idCounters: {
      L0: { node: 0, edge: 0, boundary: 0 },
      L1: { node: 0, edge: 0, boundary: 0 },
      L2: { node: 0, edge: 0, boundary: 0 },
      L3: { node: 0, edge: 0, boundary: 0 },
    },
    selectedNodeIds: [],
    selectedEdgeId: null,
    selectedBoundaryIds: [],
    linkingFromId: null,
    past: [],
    future: [],
    _dragArmed: false,
    _commitTag: null,
  });
});

const nodes = () => selectActiveNodes(useDiagramStore.getState());
const edges = () => selectActiveEdges(useDiagramStore.getState());
const boundaries = () => selectActiveBoundaries(useDiagramStore.getState());

describe('diagramStore ElementalID 採番（seq）', () => {
  it('addNode は 1 から連番で seq を割り当てる', () => {
    const s = useDiagramStore.getState();
    s.addNode('LLM');
    s.addNode('DB');
    expect(nodes().map((n) => n.seq)).toEqual([1, 2]);
  });

  it('削除しても番号を再利用しない（単調増加）', () => {
    const s = useDiagramStore.getState();
    s.addNode('LLM');
    s.addNode('DB');
    const secondId = nodes()[1].id;
    useDiagramStore.getState().deleteNode(secondId);
    useDiagramStore.getState().addNode('USER');
    // 残るのは seq 1 と、再利用されない seq 3
    expect(nodes().map((n) => n.seq)).toEqual([1, 3]);
  });

  it('addBoundary は boundary 種別の連番で seq を割り当てる', () => {
    const s = useDiagramStore.getState();
    s.addBoundary('RECT');
    s.addBoundary('ROUNDED');
    expect(boundaries().map((b) => b.seq)).toEqual([1, 2]);
  });

  it('リンク作成したエッジに edge 種別の連番 seq を割り当てる', () => {
    const s = useDiagramStore.getState();
    s.addNode('USER');
    s.addNode('LLM');
    const [a, b] = nodes();
    useDiagramStore.getState().setLinkingFromId(a.id);
    useDiagramStore.getState().beginNodeInteraction(b.id, 0, 0);
    expect(edges()).toHaveLength(1);
    expect(edges()[0].seq).toBe(1);
  });

  it('採番はレイヤーごとに独立する', () => {
    const s = useDiagramStore.getState();
    s.addNode('LLM'); // L1: seq 1
    useDiagramStore.getState().setActiveLayer('L2');
    useDiagramStore.getState().addNode('DB'); // L2: seq 1
    expect(nodes().map((n) => n.seq)).toEqual([1]);
  });
});

describe('diagramStore renumberElementalIds（ID 振り直し）', () => {
  it('欠番を詰めて 1..n に振り直し、カウンタも要素数にリセットする', () => {
    const s = useDiagramStore.getState();
    s.addNode('LLM'); // seq 1
    s.addNode('DB'); // seq 2
    s.addNode('USER'); // seq 3
    useDiagramStore.getState().deleteNode(nodes()[1].id); // seq 2 を削除 → [1, 3]
    useDiagramStore.getState().renumberElementalIds();
    expect(nodes().map((n) => n.seq)).toEqual([1, 2]);
    expect(useDiagramStore.getState().idCounters.L1.node).toBe(2);
    // 振り直し後の追加は続きの連番になる
    useDiagramStore.getState().addNode('GATEWAY');
    expect(nodes().map((n) => n.seq)).toEqual([1, 2, 3]);
  });

  it('現 seq 順を保って振り直し、内部 id は変えない', () => {
    const s = useDiagramStore.getState();
    s.addNode('LLM');
    s.addNode('DB');
    s.addNode('USER');
    const [first, , third] = nodes();
    useDiagramStore.getState().deleteNode(first.id); // 残り seq [2, 3]
    useDiagramStore.getState().renumberElementalIds();
    expect(nodes().map((n) => n.seq)).toEqual([1, 2]);
    expect(nodes()[1].id).toBe(third.id);
  });

  it('全レイヤー・全種別を一括で振り直す', () => {
    const s = useDiagramStore.getState();
    s.addBoundary('RECT');
    s.addBoundary('ROUNDED');
    useDiagramStore.getState().deleteBoundary(boundaries()[0].id); // 残り seq [2]
    useDiagramStore.getState().setActiveLayer('L2');
    useDiagramStore.getState().addNode('LLM');
    useDiagramStore.getState().addNode('DB');
    useDiagramStore.getState().deleteNode(nodes()[0].id); // 残り seq [2]
    useDiagramStore.getState().renumberElementalIds();
    expect(nodes().map((n) => n.seq)).toEqual([1]); // L2 node
    useDiagramStore.getState().setActiveLayer('L1');
    expect(boundaries().map((b) => b.seq)).toEqual([1]); // L1 boundary
  });

  it('Undo/Redo 履歴をクリアする（旧 seq の復活によるカウンタ不整合を防ぐ）', () => {
    const s = useDiagramStore.getState();
    s.addNode('LLM');
    s.addNode('DB');
    useDiagramStore.getState().deleteNode(nodes()[1].id);
    expect(useDiagramStore.getState().past.length).toBeGreaterThan(0);
    useDiagramStore.getState().renumberElementalIds();
    expect(useDiagramStore.getState().past).toEqual([]);
    expect(useDiagramStore.getState().future).toEqual([]);
  });
});
