import { describe, expect, it } from 'vitest';
import { findOrphanedJudgements } from './orphanedJudgements';
import { buildThreatViews } from './buildThreatViews';
import { detectThreats } from './detectThreats';
import { getThreatLibrary } from '../../threat-library/loader/bundledLibrary';
import type { DiagramNode, ManualThreat, SuppressionState } from '../model/types';

const rules = getThreatLibrary('ja').rules;
const accepted: SuppressionState = { status: 'accepted', at: 1 };

const llm: DiagramNode = { id: 'n1', type: 'LLM', x: 0, y: 0 };
const layerOf = (nodes: DiagramNode[]) => ({ nodes, edges: [], boundaries: [] });

/** LLM 1 個の図で実際に出る脅威を 1 件取る（判断を付ける相手）。 */
function firstThreatOnLlm() {
  const [v] = buildThreatViews({
    detected: detectThreats({ nodes: [llm], edges: [], framework: 'ALL', rules }),
    manualThreats: [],
    nodes: [llm],
    framework: 'ALL',
    suppressions: {},
  });
  return v;
}

function find(
  nodes: DiagramNode[],
  suppressions: Record<string, SuppressionState>,
  manual: ManualThreat[] = [],
) {
  return findOrphanedJudgements({
    layers: [layerOf(nodes)],
    manualThreats: [manual],
    rules,
    suppressions,
  });
}

describe('findOrphanedJudgements', () => {
  it('判断が 1 件も無ければ空', () => {
    expect(find([llm], {})).toEqual([]);
  });

  it('出ている脅威に付いた判断は拾わない（現行の id・旧形式の id とも）', () => {
    const v = firstThreatOnLlm();
    expect(find([llm], { [v.id]: accepted })).toEqual([]);
    expect(find([llm], { [v.legacyIds![0]]: accepted })).toEqual([]);
  });

  it('部品を消すと element-removed になる（現行の id）', () => {
    const v = firstThreatOnLlm();
    expect(find([], { [v.id]: accepted })).toEqual([
      { key: v.id, reason: 'element-removed', suppression: accepted },
    ]);
  });

  it('部品を消すと element-removed になる（旧形式の id）', () => {
    const v = firstThreatOnLlm();
    expect(find([], { [v.legacyIds![0]]: accepted })[0].reason).toBe('element-removed');
  });

  it('部品も分類もあるのに脅威が出ていなければ not-detected になる', () => {
    const v = firstThreatOnLlm();
    // 同じ id の部品を、そのルールが当たらない型に変える
    const other: DiagramNode = { id: 'n1', type: 'USER', x: 0, y: 0 };
    const stillFires = buildThreatViews({
      detected: detectThreats({ nodes: [other], edges: [], framework: 'ALL', rules }),
      manualThreats: [],
      nodes: [other],
      framework: 'ALL',
      suppressions: {},
    }).some((x) => x.id === v.id);
    expect(stillFires).toBe(false);
    expect(find([other], { [v.id]: accepted })[0].reason).toBe('not-detected');
  });

  it('分類・ルールが無ければ source-removed になる', () => {
    expect(find([llm], { 'no-such-classification::node:n1': accepted })[0].reason).toBe('source-removed');
    expect(find([llm], { 'no-such-rule-001-n1': accepted })[0].reason).toBe('source-removed');
    expect(find([llm], { 'something-unknown': accepted })[0].reason).toBe('source-removed');
  });

  it('手動脅威：在れば拾わず、対象の部品が消えたら element-removed', () => {
    const manual: ManualThreat = {
      id: 'manual-1',
      nodeId: 'n1',
      framework: 'STRIDE',
      category: 'x',
      severity: 'High',
      description: 'd',
    };
    expect(find([llm], { 'manual-1': accepted }, [manual])).toEqual([]);
    const typed: ManualThreat = { ...manual, id: 'manual-2', nodeId: undefined, targetType: 'LLM' };
    expect(find([llm], { 'manual-2-n1': accepted }, [typed])).toEqual([]);
    expect(find([], { 'manual-2-n1': accepted }, [typed])[0].reason).toBe('element-removed');
  });

  it('別のレイヤーで出ている脅威の判断は拾わない', () => {
    const v = firstThreatOnLlm();
    const result = findOrphanedJudgements({
      layers: [layerOf([]), layerOf([llm])],
      manualThreats: [[], []],
      rules,
      suppressions: { [v.id]: accepted },
    });
    expect(result).toEqual([]);
  });

  it('リスク評価・対策実装状況だけの記録も拾う', () => {
    const result = findOrphanedJudgements({
      layers: [layerOf([])],
      manualThreats: [[]],
      rules,
      riskScores: { 'gone::node:n9': { damage: 3, affectedUsers: 2, reproducibility: 1, exploitability: 2, at: 1 } },
      controlStatuses: { 'gone::node:n9': { status: 'implemented', at: 2 } },
    });
    expect(result).toHaveLength(1);
    expect(result[0].risk?.damage).toBe(3);
    expect(result[0].controlStatus?.status).toBe('implemented');
    expect(result[0].suppression).toBeUndefined();
  });
});
