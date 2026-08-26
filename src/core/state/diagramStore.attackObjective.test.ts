import { beforeEach, describe, expect, it } from 'vitest';
import { selectActiveNodes, useDiagramStore } from './diagramStore';
import { EMPTY_LAYER, type LayerData } from '../model/types';

/** 各テスト前に空レイヤー + カウンタ 0 の既知状態へリセット（module singleton 対策）。 */
beforeEach(() => {
  useDiagramStore.setState({
    layers: {
      L0: EMPTY_LAYER,
      L1: { nodes: [], edges: [], boundaries: [] },
      L2: EMPTY_LAYER,
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

describe('attackObjectiveId の参照整合性', () => {
  it('標的ノードを削除すると攻撃者の attackObjectiveId が解除される', () => {
    const s = useDiagramStore.getState();
    s.addNode('THREAT_ACTOR');
    s.addNode('DATA_STORE');
    const [attacker, target] = nodes();
    useDiagramStore.getState().updateNode(attacker.id, 'attackObjectiveId', target.id);
    expect(nodes()[0].attackObjectiveId).toBe(target.id);

    useDiagramStore.getState().deleteNode(target.id);
    expect(nodes()).toHaveLength(1);
    expect(nodes()[0].attackObjectiveId).toBeUndefined();
  });

  it('攻撃者ノード自身の削除は他ノードに影響しない', () => {
    const s = useDiagramStore.getState();
    s.addNode('THREAT_ACTOR');
    s.addNode('DATA_STORE');
    const [attacker, target] = nodes();
    useDiagramStore.getState().updateNode(attacker.id, 'attackObjectiveId', target.id);

    useDiagramStore.getState().deleteNode(attacker.id);
    expect(nodes()).toHaveLength(1);
    expect(nodes()[0].id).toBe(target.id);
  });

  it('テンプレート取込時に attackObjectiveId を新 ID へ付け替える', () => {
    const template: LayerData = {
      nodes: [
        { id: 'old-attacker', type: 'THREAT_ACTOR', x: 0, y: 0, attackObjectiveId: 'old-target' },
        { id: 'old-target', type: 'DATA_STORE', x: 200, y: 0 },
      ],
      edges: [],
      boundaries: [],
    };
    useDiagramStore.getState().importTemplateToActiveLayer(template);
    const imported = nodes();
    const attacker = imported.find((n) => n.type === 'THREAT_ACTOR');
    const target = imported.find((n) => n.type === 'DATA_STORE');
    expect(attacker?.attackObjectiveId).toBe(target?.id);
    expect(attacker?.attackObjectiveId).not.toBe('old-target');
  });

  it('テンプレート外を指す attackObjectiveId は取込時に解除される', () => {
    const template: LayerData = {
      nodes: [
        { id: 'old-attacker', type: 'THREAT_ACTOR', x: 0, y: 0, attackObjectiveId: 'not-in-template' },
      ],
      edges: [],
      boundaries: [],
    };
    useDiagramStore.getState().importTemplateToActiveLayer(template);
    expect(nodes()[0].attackObjectiveId).toBeUndefined();
  });
});
