import { beforeEach, describe, expect, it } from 'vitest';
import {
  selectActiveNodes,
  selectCanRedo,
  selectCanUndo,
  useDiagramStore,
} from './diagramStore';
import { EMPTY_LAYER } from '../model/types';

/** 各テスト前に最小の既知状態へリセット（store は module singleton のため）。 */
beforeEach(() => {
  useDiagramStore.setState({
    layers: {
      L0: EMPTY_LAYER,
      L1: { nodes: [], edges: [], boundaries: [] },
      L2: EMPTY_LAYER,
      L3: EMPTY_LAYER,
    },
    activeLayer: 'L1',
    manualThreats: { L0: [], L1: [], L2: [], L3: [] },
    suppressions: {},
    dreadScores: {},
    controlStatuses: {},
    selectedNodeIds: [],
    selectedEdgeId: null,
    selectedBoundaryIds: [],
    past: [],
    future: [],
    _dragArmed: false,
    _commitTag: null,
  });
});

const nodes = () => selectActiveNodes(useDiagramStore.getState());

describe('diagramStore Undo/Redo', () => {
  it('addNode を undo / redo できる', () => {
    const s = useDiagramStore.getState();
    expect(nodes()).toHaveLength(0);

    s.addNode('LLM');
    expect(nodes()).toHaveLength(1);
    expect(selectCanUndo(useDiagramStore.getState())).toBe(true);

    useDiagramStore.getState().undo();
    expect(nodes()).toHaveLength(0);
    expect(selectCanUndo(useDiagramStore.getState())).toBe(false);
    expect(selectCanRedo(useDiagramStore.getState())).toBe(true);

    useDiagramStore.getState().redo();
    expect(nodes()).toHaveLength(1);
  });

  it('新しい編集で redo スタック（future）がクリアされる', () => {
    const s = useDiagramStore.getState();
    s.addNode('LLM');
    useDiagramStore.getState().undo();
    expect(selectCanRedo(useDiagramStore.getState())).toBe(true);

    useDiagramStore.getState().addNode('DB');
    expect(selectCanRedo(useDiagramStore.getState())).toBe(false);
  });

  it('同一ノード・同一フィールドの連続編集は 1 ステップに合体する', () => {
    const s = useDiagramStore.getState();
    s.addNode('LLM');
    const id = nodes()[0].id;
    const before = useDiagramStore.getState().past.length;

    const upd = useDiagramStore.getState().updateNode;
    upd(id, 'label', 'a');
    upd(id, 'label', 'ab');
    upd(id, 'label', 'abc');

    // 連続する同フィールド編集はまとめて 1 履歴のみ追加
    expect(useDiagramStore.getState().past.length).toBe(before + 1);

    useDiagramStore.getState().undo();
    expect(nodes()[0].label).toBeUndefined();
  });

  it('異なるフィールドの編集は別ステップになる', () => {
    const s = useDiagramStore.getState();
    s.addNode('LLM');
    const id = nodes()[0].id;
    const before = useDiagramStore.getState().past.length;

    const upd = useDiagramStore.getState().updateNode;
    upd(id, 'label', 'x');
    upd(id, 'description', 'y');

    expect(useDiagramStore.getState().past.length).toBe(before + 2);
  });

  it('選択変更を挟むと合体グループが切れる', () => {
    const s = useDiagramStore.getState();
    s.addNode('LLM');
    const id = nodes()[0].id;
    const before = useDiagramStore.getState().past.length;

    const st = () => useDiagramStore.getState();
    st().updateNode(id, 'label', 'a');
    st().selectNode(id); // フォーカス相当の選択イベント
    st().updateNode(id, 'label', 'ab');

    expect(st().past.length).toBe(before + 2);
  });

  it('ドラッグ移動は複数フレームでも 1 履歴だけ記録する', () => {
    const s = useDiagramStore.getState();
    s.addNode('LLM');
    const id = nodes()[0].id;
    const before = useDiagramStore.getState().past.length;

    // ドラッグ開始を模擬（_dragArmed を立てる）
    useDiagramStore.setState({ _dragArmed: true });
    const st = () => useDiagramStore.getState();
    st().setNodePosition(id, 10, 10);
    st().setNodePosition(id, 20, 20);
    st().setNodePosition(id, 30, 30);

    expect(st().past.length).toBe(before + 1);
    expect(nodes()[0]).toMatchObject({ x: 30, y: 30 });

    st().undo();
    // 移動前の座標（addNode 既定の 300,300）へ戻る
    expect(nodes()[0]).toMatchObject({ x: 300, y: 300 });
  });

  it('移動のないクリック（_dragArmed のまま endInteraction）は履歴を残さない', () => {
    const s = useDiagramStore.getState();
    s.addNode('LLM');
    const before = useDiagramStore.getState().past.length;

    useDiagramStore.setState({ _dragArmed: true });
    useDiagramStore.getState().endInteraction();

    expect(useDiagramStore.getState().past.length).toBe(before);
    expect(useDiagramStore.getState()._dragArmed).toBe(false);
  });

  it('履歴は MAX_HISTORY (50) 段で頭から捨てられる', () => {
    const s = useDiagramStore.getState();
    for (let i = 0; i < 60; i++) s.addNode('LLM');
    expect(useDiagramStore.getState().past.length).toBe(50);
  });

  it('setDreadScore / clearDreadScore は undo で巻き戻せる', () => {
    const score = {
      damage: 3,
      reproducibility: 2,
      exploitability: 1,
      affectedUsers: 2,
      discoverability: 1,
    } as const;
    const st = () => useDiagramStore.getState();

    st().setDreadScore('rule-x-n1', score);
    expect(st().dreadScores['rule-x-n1']).toMatchObject(score);

    st().undo();
    expect(st().dreadScores['rule-x-n1']).toBeUndefined();

    st().redo();
    expect(st().dreadScores['rule-x-n1']).toMatchObject(score);

    st().clearDreadScore('rule-x-n1');
    expect(st().dreadScores['rule-x-n1']).toBeUndefined();
    st().undo();
    expect(st().dreadScores['rule-x-n1']).toMatchObject(score);
  });

  it('clearDreadScore は未評価の脅威 id では履歴を残さない', () => {
    const before = useDiagramStore.getState().past.length;
    useDiagramStore.getState().clearDreadScore('unknown');
    expect(useDiagramStore.getState().past.length).toBe(before);
  });

  it('setControlStatus / clearControlStatus は undo で巻き戻せる', () => {
    const st = () => useDiagramStore.getState();

    st().setControlStatus('rule-x-n1', 'implemented', 'WAF で対処済み');
    expect(st().controlStatuses['rule-x-n1']).toMatchObject({
      status: 'implemented',
      note: 'WAF で対処済み',
    });

    st().undo();
    expect(st().controlStatuses['rule-x-n1']).toBeUndefined();

    st().redo();
    expect(st().controlStatuses['rule-x-n1']?.status).toBe('implemented');

    st().clearControlStatus('rule-x-n1');
    expect(st().controlStatuses['rule-x-n1']).toBeUndefined();
    st().undo();
    expect(st().controlStatuses['rule-x-n1']?.status).toBe('implemented');
  });

  it('setControlStatus は note 省略時 note を持たない', () => {
    const st = () => useDiagramStore.getState();
    st().setControlStatus('rule-y-n1', 'required');
    expect(st().controlStatuses['rule-y-n1'].status).toBe('required');
    expect(st().controlStatuses['rule-y-n1'].note).toBeUndefined();
  });

  it('clearControlStatus は未登録の脅威 id では履歴を残さない', () => {
    const before = useDiagramStore.getState().past.length;
    useDiagramStore.getState().clearControlStatus('unknown');
    expect(useDiagramStore.getState().past.length).toBe(before);
  });
});
