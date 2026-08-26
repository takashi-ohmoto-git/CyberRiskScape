import { beforeEach, describe, expect, it } from 'vitest';
import { selectActiveNodes, useDiagramStore } from './diagramStore';
import { EMPTY_LAYER, EMPTY_PROJECT_META } from '../model/types';

/** 各テスト前に既知状態へリセット（module singleton 対策）。 */
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
    projectMeta: EMPTY_PROJECT_META,
    suppressions: {},
    dreadScores: {},
    controlStatuses: {},
    isNewProjectConfirmOpen: false,
    selectedNodeIds: [],
    selectedEdgeId: null,
    selectedBoundaryIds: [],
    past: [],
    future: [],
    _dragArmed: false,
    _commitTag: null,
  });
});

describe('diagramStore newProject（新規プロジェクト作成）', () => {
  it('全レイヤー・メタ・採番カウンタ・履歴をまっさらに戻す', () => {
    const s = useDiagramStore.getState();
    s.addNode('LLM');
    s.addNode('DB');
    useDiagramStore.getState().setProjectMeta({
      ...EMPTY_PROJECT_META,
      name: '旧プロジェクト',
    });
    useDiagramStore.getState().setSuppression('t1', 'accepted', 'memo');
    expect(selectActiveNodes(useDiagramStore.getState())).toHaveLength(2);

    useDiagramStore.getState().newProject();

    const after = useDiagramStore.getState();
    for (const key of ['L0', 'L1', 'L2', 'L3'] as const) {
      expect(after.layers[key]).toEqual(EMPTY_LAYER);
      expect(after.idCounters[key]).toEqual({ node: 0, edge: 0, boundary: 0 });
    }
    expect(after.projectMeta).toEqual(EMPTY_PROJECT_META);
    expect(after.suppressions).toEqual({});
    expect(after.past).toEqual([]);
    expect(after.future).toEqual([]);
  });

  it('確認モーダルを閉じ、次の採番は 1 から始まる', () => {
    const s = useDiagramStore.getState();
    s.addNode('LLM');
    useDiagramStore.getState().openNewProjectConfirm();
    expect(useDiagramStore.getState().isNewProjectConfirmOpen).toBe(true);

    useDiagramStore.getState().newProject();
    expect(useDiagramStore.getState().isNewProjectConfirmOpen).toBe(false);

    useDiagramStore.getState().addNode('USER');
    expect(selectActiveNodes(useDiagramStore.getState()).map((n) => n.seq)).toEqual([1]);
  });
});
