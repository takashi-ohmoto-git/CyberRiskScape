import { parse as parseYaml } from 'yaml';
import {
  ThreatLibraryOverlayFileSchema,
  type ThreatRuleOverlayMap,
} from '../schema/threatRuleOverlay';
import type { ThreatRule } from '../schema/threatRule';
import { ThreatLibraryLoadError, type RawYamlFile } from './loadThreatLibrary';
import { parseMitigationTiers } from './parseMitigationTiers';

/**
 * 脅威ルールの翻訳オーバーレイを読み込み、原本へ被せる。
 *
 * 原本（日本語）は常に完全なので、オーバーレイ側の欠落は**原文へフォールバック**する。
 * これにより「訳が追いついていないルールがある」状態でも安全に出荷できる。
 */

/** オーバーレイ YAML 1 本をパース＋検証して `ThreatRuleOverlayMap` を返す。 */
export function parseThreatLibraryOverlayFile(
  yamlText: string,
  source: string,
): ThreatRuleOverlayMap {
  let parsed: unknown;
  try {
    parsed = parseYaml(yamlText);
  } catch (e) {
    throw new ThreatLibraryLoadError(
      `YAML parse error in overlay "${source}": ${(e as Error).message}`,
      source,
      e,
    );
  }

  const result = ThreatLibraryOverlayFileSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new ThreatLibraryLoadError(
      `Overlay schema validation failed for "${source}":\n${issues}`,
      source,
      result.error,
    );
  }

  return result.data.rules;
}

/**
 * 同一ロケールの複数オーバーレイファイルを 1 つのマップへ統合する。
 * オーバーレイは原本ファイルと 1:1 対応させる運用なので、id 重複は設定ミスとして落とす。
 */
export function loadThreatLibraryOverlay(files: RawYamlFile[]): ThreatRuleOverlayMap {
  const merged: ThreatRuleOverlayMap = {};
  const seenIn: Record<string, string> = {};

  for (const file of files) {
    const rules = parseThreatLibraryOverlayFile(file.text, file.source);
    for (const [ruleId, overlay] of Object.entries(rules)) {
      const previous = seenIn[ruleId];
      if (previous !== undefined) {
        throw new ThreatLibraryLoadError(
          `Duplicate overlay entry for rule "${ruleId}" in "${file.source}" (already defined in "${previous}")`,
          file.source,
        );
      }
      seenIn[ruleId] = file.source;
      merged[ruleId] = overlay;
    }
  }

  return merged;
}

/**
 * オーバーレイにあるが原本に存在しないルール id を返す（診断用）。
 * ルール削除時にオーバーレイが取り残されても起動は止めず、warn に留めるための材料。
 */
export function findOrphanOverlayIds(
  rules: readonly ThreatRule[],
  overlay: ThreatRuleOverlayMap,
): string[] {
  const known = new Set(rules.map((r) => r.id));
  return Object.keys(overlay).filter((id) => !known.has(id));
}

/** 原本のルールのうち、オーバーレイに訳が無いものの id を返す（診断用）。 */
export function findUntranslatedRuleIds(
  rules: readonly ThreatRule[],
  overlay: ThreatRuleOverlayMap,
): string[] {
  return rules.filter((r) => overlay[r.id] === undefined).map((r) => r.id);
}

/**
 * ルール集合へ訳文を適用する。指定の無いフィールドは原文のまま残す。
 *
 * `mitigation` を上書きした場合は `mitigationTiers` を**訳文から再計算**する
 * （tier markup は訳文側にも保持する運用。markup が無ければ tiers は落ちる）。
 */
export function localizeRules(
  rules: readonly ThreatRule[],
  overlay: ThreatRuleOverlayMap,
): ThreatRule[] {
  return rules.map((rule) => {
    const t = overlay[rule.id];
    if (!t) return rule;

    const localized: ThreatRule = { ...rule };
    if (t.name !== undefined) localized.name = t.name;
    if (t.category !== undefined) localized.category = t.category;
    if (t.description !== undefined) localized.description = t.description;

    if (t.mitigation !== undefined) {
      localized.mitigation = t.mitigation;
      const tiers = parseMitigationTiers(t.mitigation, rule.id);
      if (tiers) {
        localized.mitigationTiers = tiers;
      } else {
        delete localized.mitigationTiers;
      }
    }

    if (t.references && rule.references) {
      const references = rule.references.map((ref, i) => {
        const title = t.references?.[String(i)]?.title;
        return title === undefined ? ref : { ...ref, title };
      });
      // map は非空タプル型を保てないため、要素数不変であることを根拠に元の型へ戻す。
      localized.references = references as typeof rule.references;
    }

    // 条件別記述は `appliesTo.conditions` に置かれる。node / edge の双方が持つ
    // （ノード側は [[plan]] §2.41 で追加）。要素の形は違うが description の差し替えは同じ。
    const appliesTo = localized.appliesTo;
    if (t.conditions && appliesTo.conditions) {
      const conditions = (appliesTo.conditions as { description?: string }[]).map((c, i) => {
        const description = t.conditions?.[i]?.description;
        return description === undefined ? c : { ...c, description };
      });
      // map は非空タプル型を保てないため、要素数不変であることを根拠に元の型へ戻す。
      localized.appliesTo = { ...appliesTo, conditions } as typeof appliesTo;
    }

    return localized;
  });
}
