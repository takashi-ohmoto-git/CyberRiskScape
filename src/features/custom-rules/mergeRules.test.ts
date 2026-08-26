import { describe, expect, it } from 'vitest';
import { mergeThreatRules } from './mergeRules';
import type { CustomRuleLibrary } from './schema';
import type { ThreatRule } from '../../threat-library/schema/threatRule';

const bundled: ThreatRule[] = [
  {
    id: 'bundled-001',
    framework: 'STRIDE',
    category: 'X',
    severity: 'High',
    description: 'bundled rule',
    appliesTo: { kind: 'node', nodeType: 'LLM', connection: { required: false } },
  },
];

function lib(over: Partial<CustomRuleLibrary>): CustomRuleLibrary {
  return {
    id: 'lib1',
    name: 'My Lib',
    schemaVersion: 1,
    enabled: true,
    rules: [],
    updatedAt: 0,
    ...over,
  };
}

const customRule: ThreatRule = {
  id: 'custom-001',
  framework: 'AgenticAI',
  category: 'Agent',
  severity: 'Critical',
  description: 'custom rule',
  appliesTo: { kind: 'node', nodeType: 'AGENT', connection: { required: false } },
};

describe('mergeThreatRules', () => {
  it('有効なカスタムライブラリのルールを bundled に追加する', () => {
    const { rules, customRuleIds, droppedIds } = mergeThreatRules(bundled, [
      lib({ rules: [customRule] }),
    ]);
    expect(rules.map((r) => r.id)).toEqual(['bundled-001', 'custom-001']);
    expect([...customRuleIds]).toEqual(['custom-001']);
    expect(droppedIds).toEqual([]);
  });

  it('customRuleIds には bundled も dropped も含めない', () => {
    const clash: ThreatRule = { ...customRule, id: 'bundled-001' };
    const { customRuleIds } = mergeThreatRules(bundled, [
      lib({ rules: [clash, customRule] }),
    ]);
    // clash は bundled と衝突して drop、bundled-001 は bundled 由来 → どちらも customRuleIds 外
    expect([...customRuleIds]).toEqual(['custom-001']);
  });

  it('無効なライブラリのルールは合流しない', () => {
    const { rules } = mergeThreatRules(bundled, [lib({ enabled: false, rules: [customRule] })]);
    expect(rules.map((r) => r.id)).toEqual(['bundled-001']);
  });

  it('bundled と id 衝突するカスタムルールは除外し droppedIds に記録（bundled 優先）', () => {
    const clash: ThreatRule = { ...customRule, id: 'bundled-001' };
    const { rules, droppedIds } = mergeThreatRules(bundled, [lib({ rules: [clash] })]);
    expect(rules.map((r) => r.id)).toEqual(['bundled-001']);
    // bundled 側が残る（custom が落ちる）
    expect(rules[0].description).toBe('bundled rule');
    expect(droppedIds).toEqual(['bundled-001']);
  });

  it('カスタム同士の id 衝突は先勝ち', () => {
    const a = lib({ id: 'libA', rules: [customRule] });
    const b = lib({ id: 'libB', rules: [{ ...customRule, description: 'later' }] });
    const { rules, droppedIds } = mergeThreatRules([], [a, b]);
    expect(rules).toHaveLength(1);
    expect(rules[0].description).toBe('custom rule');
    expect(droppedIds).toEqual(['custom-001']);
  });

  it('入力配列をミューテートしない', () => {
    const snapshot = JSON.parse(JSON.stringify(bundled));
    mergeThreatRules(bundled, [lib({ rules: [customRule] })]);
    expect(bundled).toEqual(snapshot);
  });
});
