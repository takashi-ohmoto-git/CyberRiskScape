import type { ThreatRule } from '../../threat-library/schema/threatRule';
import type { CustomRuleLibrary } from './schema';

export interface MergedRules {
  rules: ThreatRule[];
  /** 合流に採用されたカスタムルールの id 集合（"Custom" バッジ判定用）。 */
  customRuleIds: Set<string>;
  /** id 衝突等で除外されたカスタムルール id（診断用）。 */
  droppedIds: string[];
}

/**
 * 出荷ルール（bundled）と有効なカスタムライブラリのルールを合流する純粋関数。
 *
 * - `enabled === false` のライブラリは無視する。
 * - id 衝突は **bundled 優先**で除外（重複 id は detectThreats の出力 id を衝突させ、
 *   React キー重複・表示破綻を招くため）。カスタム同士も先勝ち。
 * - 入力配列はミューテートしない。
 */
export function mergeThreatRules(
  bundled: readonly ThreatRule[],
  libraries: readonly CustomRuleLibrary[],
): MergedRules {
  const seen = new Set(bundled.map((r) => r.id));
  const rules: ThreatRule[] = [...bundled];
  const customRuleIds = new Set<string>();
  const droppedIds: string[] = [];

  for (const lib of libraries) {
    if (!lib.enabled) continue;
    for (const rule of lib.rules) {
      if (seen.has(rule.id)) {
        droppedIds.push(rule.id);
        continue;
      }
      seen.add(rule.id);
      customRuleIds.add(rule.id);
      rules.push(rule);
    }
  }

  return { rules, customRuleIds, droppedIds };
}
