import { useMemo } from 'react';
import type { ThreatRule } from '../../threat-library/schema/threatRule';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';
import { selectCustomLibraries, useCustomRulesStore } from '../../features/custom-rules/store';
import { mergeThreatRules } from '../../features/custom-rules/mergeRules';
import { useT } from '../../i18n';

/**
 * ThreatCard の「検出根拠」表示用に、ruleId からルール定義とソース（定義元）を
 * 逆引きするフック。App.tsx と同じ `mergeThreatRules` パターンで出荷ルール＋
 * 有効なカスタムルールを合流する。
 */
export function useRuleLookup(): {
  getRule(ruleId: string): ThreatRule | undefined;
  getSource(ruleId: string): string | undefined;
} {
  const t = useT();
  const customLibraries = useCustomRulesStore(selectCustomLibraries);

  const merged = useMemo(
    () => mergeThreatRules(BUNDLED_THREAT_LIBRARY.rules, customLibraries),
    [customLibraries],
  );

  const ruleMap = useMemo(() => {
    const map = new Map<string, ThreatRule>();
    for (const rule of merged.rules) map.set(rule.id, rule);
    return map;
  }, [merged.rules]);

  /** カスタムルール由来の ruleId → 所属ライブラリ名の逆引き。 */
  const customSourceMap = useMemo(() => {
    const map = new Map<string, string>();
    for (const lib of customLibraries) {
      if (!lib.enabled) continue;
      for (const rule of lib.rules) map.set(rule.id, lib.name);
    }
    return map;
  }, [customLibraries]);

  function getRule(ruleId: string): ThreatRule | undefined {
    return ruleMap.get(ruleId);
  }

  function getSource(ruleId: string): string | undefined {
    const bundledSource = BUNDLED_THREAT_LIBRARY.ruleSources[ruleId];
    if (bundledSource) return bundledSource;
    if (!merged.customRuleIds.has(ruleId)) return undefined;
    return customSourceMap.get(ruleId) ?? t('threatCard.detectionBasis.customRuleFallback');
  }

  return { getRule, getSource };
}
