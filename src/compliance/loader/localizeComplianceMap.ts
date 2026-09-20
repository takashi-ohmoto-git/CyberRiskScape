import { parse as parseYaml } from 'yaml';
import {
  ComplianceOverlayFileSchema,
  type ComplianceOverlayMap,
} from '../schema/complianceOverlay';
import type { ComplianceItem, StandardId } from '../schema/complianceItem';
import {
  ComplianceMapLoadError,
  makeComplianceKey,
  type ComplianceKey,
  type LoadedComplianceMap,
  type RawYamlFile,
} from './loadComplianceMap';

/**
 * コンプライアンスマッピングの翻訳オーバーレイを読み込み、原本へ被せる。
 *
 * 原本（日本語）は常に完全なので、オーバーレイ側の欠落は**原文へフォールバック**する。
 * 脅威ライブラリ・コンポーネントライブラリの localize* と同じ設計。
 */

/** オーバーレイ YAML 1 本をパース＋検証する。 */
export function parseComplianceOverlayFile(
  yamlText: string,
  source: string,
): {
  standard: StandardId;
  title?: string;
  license?: string;
  disclaimer?: string;
  refLabels?: Record<string, string>;
  items?: Record<string, { title?: string; summary?: string }>;
} {
  let parsed: unknown;
  try {
    parsed = parseYaml(yamlText);
  } catch (e) {
    throw new ComplianceMapLoadError(
      `YAML parse error in overlay "${source}": ${(e as Error).message}`,
      source,
      e,
    );
  }

  const result = ComplianceOverlayFileSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new ComplianceMapLoadError(
      `Overlay schema validation failed for "${source}":\n${issues}`,
      source,
      result.error,
    );
  }

  const { standard, title, license, disclaimer, refLabels, items } = result.data;
  return { standard, title, license, disclaimer, refLabels, items };
}

/**
 * 同一ロケールの複数オーバーレイファイルを 1 つのマップへ統合する。
 * 1 ファイル = 1 規格の運用なので、規格 ID の重複は設定ミスとして落とす。
 */
export function loadComplianceOverlay(files: readonly RawYamlFile[]): ComplianceOverlayMap {
  const merged: ComplianceOverlayMap = {};
  const seenIn: Record<string, string> = {};

  for (const file of files) {
    const { standard, title, license, disclaimer, refLabels, items } =
      parseComplianceOverlayFile(file.text, file.source);
    const previous = seenIn[standard];
    if (previous !== undefined) {
      throw new ComplianceMapLoadError(
        `Duplicate overlay entry for standard "${standard}" in "${file.source}" (already defined in "${previous}")`,
        file.source,
      );
    }
    seenIn[standard] = file.source;
    merged[standard] = { title, license, disclaimer, refLabels, items };
  }

  return merged;
}

/**
 * 原本に存在しない ref を訳している箇所を返す（診断用）。
 * 規格の改訂で項目が消えてもオーバーレイが取り残されるだけで起動は止めない。
 */
export function findOrphanOverlayRefs(
  map: LoadedComplianceMap,
  overlay: ComplianceOverlayMap,
): string[] {
  const orphans: string[] = [];
  for (const [standard, entry] of Object.entries(overlay)) {
    if (!map.standards.has(standard as StandardId)) {
      orphans.push(standard);
      continue;
    }
    const refs = new Set([
      ...Object.keys(entry.refLabels ?? {}),
      ...Object.keys(entry.items ?? {}),
    ]);
    for (const ref of refs) {
      if (!map.index.has(makeComplianceKey(standard as StandardId, ref))) {
        orphans.push(`${standard} / ${ref}`);
      }
    }
  }
  return orphans;
}

/**
 * ロード結果へ訳文を適用する。指定の無いものは原文のまま残す。
 *
 * 項目本文（`title` / `summary`）の解決順：
 *   1. オーバーレイの訳
 *   2. 原本の `text`（パブリックドメイン規格の英語原文。summary のみ）
 *   3. 原文（日本語）
 *
 * 2 があるのは NIST CSF 2.0 Implementation Examples で、`summary` はその日本語要約に
 * あたる。英語原文が既にデータにあるものを訳し直す必要はないので、そのまま使う。
 */
export function localizeComplianceMap(
  map: LoadedComplianceMap,
  overlay: ComplianceOverlayMap,
): LoadedComplianceMap {
  const standards = new Map(map.standards);
  const refLabels = new Map<ComplianceKey, string>();

  for (const [standardId, entry] of Object.entries(overlay)) {
    const id = standardId as StandardId;
    const original = standards.get(id);
    if (original) {
      standards.set(id, {
        ...original,
        ...(entry.title !== undefined && { title: entry.title }),
        ...(entry.license !== undefined && { license: entry.license }),
        ...(entry.disclaimer !== undefined && { disclaimer: entry.disclaimer }),
      });
    }
    for (const [ref, label] of Object.entries(entry.refLabels ?? {})) {
      refLabels.set(makeComplianceKey(id, ref), label);
    }
  }

  const localizeItem = (standardId: StandardId, item: ComplianceItem): ComplianceItem => {
    const t = overlay[standardId]?.items?.[item.ref];
    const title = t?.title ?? item.title;
    const summary = t?.summary ?? item.text ?? item.summary;
    if (title === item.title && summary === item.summary) return item;
    return { ...item, title, summary };
  };

  const itemsByStandard = new Map<StandardId, readonly ComplianceItem[]>();
  const index = new Map<ComplianceKey, ComplianceItem>();
  for (const [standardId, items] of map.itemsByStandard) {
    const localized = items.map((item) => localizeItem(standardId, item));
    itemsByStandard.set(standardId, localized);
    for (const item of localized) {
      index.set(makeComplianceKey(standardId, item.ref), item);
    }
  }

  return { ...map, standards, refLabels, itemsByStandard, index };
}
