import { describe, expect, it } from 'vitest';
import { buildThreatViews, judgementOf } from './buildThreatViews';
import type { DetectedThreat, DiagramNode, SuppressionState } from '../model/types';

const NODES: DiagramNode[] = [{ id: 'n1', type: 'LLM', x: 0, y: 0 }];

/** 同じ canonicalId（model-theft）を持つ、出典の違う 2 本のルールの検出結果。 */
const fromRuleA: DetectedThreat = {
  id: 'rule-a-n1',
  ruleId: 'rule-a',
  canonicalId: 'model-theft',
  subject: { kind: 'node', id: 'n1' },
  nodeId: 'n1',
  framework: 'AI',
  category: 'モデルの窃取',
  severity: 'High',
  description: 'A',
};
const fromRuleB: DetectedThreat = { ...fromRuleA, id: 'rule-b-n1', ruleId: 'rule-b', framework: 'STRIDE', description: 'B' };

const accepted: SuppressionState = { status: 'accepted', at: 1 };

function views(detected: DetectedThreat[], suppressions: Record<string, SuppressionState> = {}) {
  return buildThreatViews({ detected, manualThreats: [], nodes: NODES, framework: 'ALL', suppressions });
}

describe('buildThreatViews（id の安定）', () => {
  it('canonicalId を持つ検出脅威は、当たったルールが 1 件でも canonicalId::kind:要素 id になる', () => {
    const [v] = views([fromRuleA]);
    expect(v.id).toBe('model-theft::node:n1');
    expect(v.legacyIds).toEqual(['rule-a-n1']);
    expect(v.ruleId).toBe('rule-a');
    expect(v.corroboration).toBeUndefined();
  });

  it('当たるルールが 1 件でも 2 件でも、同じ脅威は同じ id になる', () => {
    const one = views([fromRuleA]);
    const two = views([fromRuleA, fromRuleB]);
    expect(two).toHaveLength(1);
    expect(two[0].id).toBe(one[0].id);
    expect(two[0].legacyIds).toEqual(['rule-a-n1', 'rule-b-n1']);
    expect(two[0].corroboration?.ruleIds).toEqual(['rule-a-n1', 'rule-b-n1']);
  });

  it('canonicalId を持たない検出脅威は、従来どおりルール id-要素 id のまま', () => {
    const [v] = views([{ ...fromRuleA, canonicalId: undefined }]);
    expect(v.id).toBe('rule-a-n1');
    expect(v.legacyIds).toBeUndefined();
  });

  it('旧形式の id で保存された判断を、1 件だけ当たっているときも読める', () => {
    expect(views([fromRuleA], { 'rule-a-n1': accepted })[0].suppression).toEqual(accepted);
  });

  it('1 件のときに付けた判断が、2 本目のルールが当たるようになっても外れない', () => {
    expect(views([fromRuleA, fromRuleB], { 'rule-a-n1': accepted })[0].suppression).toEqual(accepted);
  });

  it('2 件のときに付けた判断が、1 件だけになっても外れない', () => {
    expect(views([fromRuleB], { 'model-theft::node:n1': accepted })[0].suppression).toEqual(accepted);
  });

  it('現行の id と旧形式の id の両方に判断があれば、現行の id を優先する', () => {
    const reduced: SuppressionState = { status: 'reduce', at: 2 };
    const [v] = views([fromRuleA], { 'rule-a-n1': accepted, 'model-theft::node:n1': reduced });
    expect(v.suppression).toEqual(reduced);
  });

  it('リスク評価・対策実装状況も旧形式の id で読める', () => {
    const [v] = buildThreatViews({
      detected: [fromRuleA],
      manualThreats: [],
      nodes: NODES,
      framework: 'ALL',
      suppressions: {},
      riskScores: { 'rule-a-n1': { damage: 3, affectedUsers: 2, reproducibility: 1, exploitability: 2, at: 1 } },
      controlStatuses: { 'rule-a-n1': { status: 'implemented', at: 1 } },
    });
    expect(v.risk?.damage).toBe(3);
    expect(v.controlStatus?.status).toBe('implemented');
  });
});

describe('judgementOf', () => {
  it('記録が無ければ undefined', () => {
    expect(judgementOf(undefined, { id: 'a' })).toBeUndefined();
    expect(judgementOf({}, { id: 'a', legacyIds: ['b'] })).toBeUndefined();
  });
});
