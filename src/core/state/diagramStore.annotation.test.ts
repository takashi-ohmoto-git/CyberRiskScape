import { beforeEach, describe, expect, it } from 'vitest';
import { selectActiveAnnotations, selectActiveNodes, useDiagramStore } from './diagramStore';
import { EMPTY_LAYER, type LayerData } from '../model/types';

/** 各テスト前に空レイヤー + カウンタ 0 の既知状態へリセット（module singleton 対策）。 */
beforeEach(() => {
  useDiagramStore.setState({
    layers: {
      L0: EMPTY_LAYER,
      L1: { nodes: [], edges: [], boundaries: [], annotations: [] },
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
    selectedAnnotationId: null,
    draggingAnnotation: null,
    linkingFromId: null,
    past: [],
    future: [],
    _dragArmed: false,
    _commitTag: null,
  });
});

const nodes = () => selectActiveNodes(useDiagramStore.getState());
const annotations = () => selectActiveAnnotations(useDiagramStore.getState());

describe('キャンバス注釈（[[plan]] §2.48）', () => {
  it('addAnnotation(label) はテキストラベルを既定文言で追加する', () => {
    useDiagramStore.getState().addAnnotation('label');
    const list = annotations();
    expect(list).toHaveLength(1);
    expect(list[0].kind).toBe('label');
    expect(list[0].text.length).toBeGreaterThan(0);
    expect(list[0].targetNodeId).toBeUndefined();
    // ElementalID（seq）は振らない
    expect('seq' in list[0]).toBe(false);
  });

  it('addAnnotation(callout) は吹き出しを既定文言で追加する', () => {
    useDiagramStore.getState().addAnnotation('callout');
    const list = annotations();
    expect(list).toHaveLength(1);
    expect(list[0].kind).toBe('callout');
  });

  it('updateAnnotation で本文とリンク先ノードを更新できる', () => {
    useDiagramStore.getState().addNode('LLM');
    useDiagramStore.getState().addAnnotation('callout');
    const [node] = nodes();
    const [ann] = annotations();

    useDiagramStore.getState().updateAnnotation(ann.id, 'text', 'この部分は決済フロー');
    useDiagramStore.getState().updateAnnotation(ann.id, 'targetNodeId', node.id);

    const updated = annotations()[0];
    expect(updated.text).toBe('この部分は決済フロー');
    expect(updated.targetNodeId).toBe(node.id);
  });

  it('deleteAnnotation は注釈を削除し、選択中なら選択も解除する', () => {
    useDiagramStore.getState().addAnnotation('label');
    const [ann] = annotations();
    useDiagramStore.getState().selectAnnotation(ann.id);
    expect(useDiagramStore.getState().selectedAnnotationId).toBe(ann.id);

    useDiagramStore.getState().deleteAnnotation(ann.id);
    expect(annotations()).toHaveLength(0);
    expect(useDiagramStore.getState().selectedAnnotationId).toBeNull();
  });

  it('selectAnnotation は他の選択（ノード/エッジ/境界）と排他', () => {
    useDiagramStore.getState().addNode('LLM');
    const [node] = nodes();
    useDiagramStore.getState().selectNode(node.id);
    expect(useDiagramStore.getState().selectedNodeIds).toEqual([node.id]);

    useDiagramStore.getState().addAnnotation('label');
    const [ann] = annotations();
    useDiagramStore.getState().selectAnnotation(ann.id);

    const s = useDiagramStore.getState();
    expect(s.selectedAnnotationId).toBe(ann.id);
    expect(s.selectedNodeIds).toEqual([]);
    expect(s.selectedBoundaryIds).toEqual([]);
    expect(s.selectedEdgeId).toBeNull();
  });

  it('selectNode は注釈選択をクリアする（逆方向の排他）', () => {
    useDiagramStore.getState().addNode('LLM');
    useDiagramStore.getState().addAnnotation('label');
    const [node] = nodes();
    const [ann] = annotations();
    useDiagramStore.getState().selectAnnotation(ann.id);
    expect(useDiagramStore.getState().selectedAnnotationId).toBe(ann.id);

    useDiagramStore.getState().selectNode(node.id);
    expect(useDiagramStore.getState().selectedAnnotationId).toBeNull();
  });

  it('beginAnnotationInteraction はドラッグを開始し、他の選択をクリアする', () => {
    useDiagramStore.getState().addAnnotation('label');
    const [ann] = annotations();
    useDiagramStore.getState().beginAnnotationInteraction(ann.id, 100, 100);

    const s = useDiagramStore.getState();
    expect(s.selectedAnnotationId).toBe(ann.id);
    expect(s.draggingAnnotation).toEqual({
      id: ann.id,
      startClientX: 100,
      startClientY: 100,
      origX: ann.x,
      origY: ann.y,
    });
  });

  it('setAnnotationPosition はドラッグ中の座標を更新する', () => {
    useDiagramStore.getState().addAnnotation('label');
    const [ann] = annotations();
    useDiagramStore.getState().setAnnotationPosition(ann.id, 999, 888);
    expect(annotations()[0].x).toBe(999);
    expect(annotations()[0].y).toBe(888);
  });

  it('deleteNode はリンク先だった注釈の targetNodeId を解除するが注釈自体は残す', () => {
    useDiagramStore.getState().addNode('LLM');
    const [node] = nodes();
    useDiagramStore.getState().addAnnotation('callout');
    const [ann] = annotations();
    useDiagramStore.getState().updateAnnotation(ann.id, 'targetNodeId', node.id);
    expect(annotations()[0].targetNodeId).toBe(node.id);

    useDiagramStore.getState().deleteNode(node.id);

    const after = annotations();
    expect(after).toHaveLength(1);
    expect(after[0].id).toBe(ann.id);
    expect(after[0].targetNodeId).toBeUndefined();
  });

  it('undo で注釈の追加が取り消され、redo でやり直せる', () => {
    useDiagramStore.getState().addAnnotation('label');
    expect(annotations()).toHaveLength(1);

    useDiagramStore.getState().undo();
    expect(annotations()).toHaveLength(0);

    useDiagramStore.getState().redo();
    expect(annotations()).toHaveLength(1);
  });

  it('importTemplateToActiveLayer は既存の注釈を空にする（テンプレートは注釈を持たない）', () => {
    useDiagramStore.getState().addAnnotation('label');
    expect(annotations()).toHaveLength(1);

    const template: LayerData = {
      nodes: [{ id: 'tn1', type: 'USER', x: 0, y: 0 }],
      edges: [],
      boundaries: [],
      annotations: [],
    };
    useDiagramStore.getState().importTemplateToActiveLayer(template);

    expect(annotations()).toHaveLength(0);
    expect(useDiagramStore.getState().selectedAnnotationId).toBeNull();
  });
});
