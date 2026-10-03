import { describe, expect, it } from 'vitest';
import { computeLayerThreats } from './layerThreats';
import { useDiagramStore } from '../../core/state/diagramStore';
import { detectThreats } from '../../core/threat-engine/detectThreats';
import { buildThreatViews } from '../../core/threat-engine/buildThreatViews';
import { getThreatLibrary } from '../../threat-library/loader/bundledLibrary';
import { mergeThreatRules } from '../custom-rules/mergeRules';

const merged = mergeThreatRules(getThreatLibrary('ja').rules, []);

describe('computeLayerThreats', () => {
  it('アクティブレイヤーは App.tsx と同じ経路の結果（脅威 id）と一致する', () => {
    const s = useDiagramStore.getState();
    const { nodes, edges, boundaries } = s.layers[s.activeLayer];
    const expected = buildThreatViews({
      detected: detectThreats({ nodes, edges, framework: s.activeFramework, rules: merged.rules, boundaries }),
      manualThreats: s.manualThreats[s.activeLayer],
      nodes,
      framework: s.activeFramework,
      suppressions: s.suppressions,
      riskScores: s.riskScores,
      controlStatuses: s.controlStatuses,
      customRuleIds: merged.customRuleIds,
    });
    const [got] = computeLayerThreats(s, merged, [s.activeLayer]);
    expect(expected.length).toBeGreaterThan(0);
    expect(got.threats.map((t) => t.id)).toEqual(expected.map((t) => t.id));
    expect(got.input.layer).toBe(s.activeLayer);
    expect(got.input.threats).toBe(got.threats);
  });

  it('非アクティブレイヤーも算出でき、空レイヤーは脅威 0 件', () => {
    const s = useDiagramStore.getState();
    const active = s.activeLayer;
    const other = active === 'L2' ? 'L3' : 'L2';
    const state = { ...s, layers: { ...s.layers, [other]: s.layers[active] } };
    const [a, b] = computeLayerThreats(state, merged, [active, other]);
    expect(b.layer).toBe(other);
    expect(b.threats.map((t) => t.ruleId)).toEqual(a.threats.map((t) => t.ruleId));
    const empty = (['L0', 'L1', 'L2', 'L3'] as const).find((k) => state.layers[k].nodes.length === 0);
    if (empty) expect(computeLayerThreats(state, merged, [empty])[0].threats).toEqual([]);
  });
});
