import { beforeEach, describe, expect, it } from 'vitest';
import { useDiagramStore } from './diagramStore';

const NEW_ID = 'model-theft::node:n1';
const LEGACY = ['rule-a-n1', 'rule-b-n1'];
const RISK = { damage: 3, affectedUsers: 2, reproducibility: 1, exploitability: 2 } as const;

beforeEach(() => {
  useDiagramStore.setState({
    suppressions: { 'rule-a-n1': { status: 'accepted', at: 1 }, 'other-n9': { status: 'reduce', at: 1 } },
    riskScores: { 'rule-a-n1': { ...RISK, at: 1 } },
    controlStatuses: { 'rule-b-n1': { status: 'required', at: 1 } },
    past: [],
    future: [],
  });
});

describe('diagramStore 判断のキー（旧形式の id の片付け）', () => {
  it('setSuppression: 現行の id で書き、旧形式の id のエントリを消す。無関係なエントリは残す', () => {
    useDiagramStore.getState().setSuppression(NEW_ID, 'reduce', undefined, LEGACY);
    const { suppressions } = useDiagramStore.getState();
    expect(suppressions[NEW_ID]?.status).toBe('reduce');
    expect('rule-a-n1' in suppressions).toBe(false);
    expect(suppressions['other-n9']?.status).toBe('reduce');
  });

  it('clearSuppression: 旧形式の id にしか無い判断も消す（消したはずの判断が復活しない）', () => {
    useDiagramStore.getState().clearSuppression(NEW_ID, LEGACY);
    const { suppressions } = useDiagramStore.getState();
    expect(NEW_ID in suppressions).toBe(false);
    expect('rule-a-n1' in suppressions).toBe(false);
    expect('other-n9' in suppressions).toBe(true);
  });

  it('setRiskScore / clearRiskScore: 旧形式の id のエントリを片付ける', () => {
    useDiagramStore.getState().setRiskScore(NEW_ID, { ...RISK, damage: 1 }, LEGACY);
    expect(useDiagramStore.getState().riskScores).toEqual({ [NEW_ID]: expect.objectContaining({ damage: 1 }) });
    useDiagramStore.getState().clearRiskScore(NEW_ID, LEGACY);
    expect(useDiagramStore.getState().riskScores).toEqual({});
  });

  it('setControlStatus / clearControlStatus: 旧形式の id のエントリを片付ける', () => {
    useDiagramStore.getState().setControlStatus(NEW_ID, 'implemented', undefined, LEGACY);
    expect(Object.keys(useDiagramStore.getState().controlStatuses)).toEqual([NEW_ID]);
    useDiagramStore.getState().clearControlStatus(NEW_ID, LEGACY);
    expect(useDiagramStore.getState().controlStatuses).toEqual({});
  });

  it('legacyIds を渡さない呼び出しは従来どおり（その id だけを書く・消す）', () => {
    useDiagramStore.getState().setSuppression('rule-a-n1', 'avoid');
    expect(useDiagramStore.getState().suppressions['rule-a-n1']?.status).toBe('avoid');
    useDiagramStore.getState().clearSuppression('rule-a-n1');
    expect('rule-a-n1' in useDiagramStore.getState().suppressions).toBe(false);
  });

  it('旧形式の id を片付けた書き込みは Undo で元に戻る', () => {
    useDiagramStore.getState().setSuppression(NEW_ID, 'reduce', undefined, LEGACY);
    useDiagramStore.getState().undo();
    const { suppressions } = useDiagramStore.getState();
    expect(NEW_ID in suppressions).toBe(false);
    expect(suppressions['rule-a-n1']?.status).toBe('accepted');
  });
});

describe('diagramStore discardJudgements', () => {
  it('キーに付いた 3 種の判断をまとめて消し、ほかのキーは残す。Undo 1 回で戻る', () => {
    useDiagramStore.setState({
      controlStatuses: { 'rule-a-n1': { status: 'required', at: 1 }, 'rule-b-n1': { status: 'required', at: 1 } },
    });
    useDiagramStore.getState().discardJudgements('rule-a-n1');
    const after = useDiagramStore.getState();
    expect(after.suppressions).toEqual({ 'other-n9': { status: 'reduce', at: 1 } });
    expect(after.riskScores).toEqual({});
    expect(Object.keys(after.controlStatuses)).toEqual(['rule-b-n1']);
    expect(after.past).toHaveLength(1);

    after.undo();
    const undone = useDiagramStore.getState();
    expect('rule-a-n1' in undone.suppressions).toBe(true);
    expect('rule-a-n1' in undone.riskScores).toBe(true);
    expect('rule-a-n1' in undone.controlStatuses).toBe(true);
  });

  it('どの記録にも無いキーなら何もしない（履歴も積まない）', () => {
    useDiagramStore.getState().discardJudgements('no-such-key');
    expect(useDiagramStore.getState().past).toHaveLength(0);
  });
});
