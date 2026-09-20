import { parse as parseYaml } from 'yaml';
import {
  ComplianceOverlayFileSchema,
  type ComplianceOverlayMap,
} from '../schema/complianceOverlay';
import type { StandardId } from '../schema/complianceItem';
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
): { standard: StandardId; title?: string; refLabels?: Record<string, string> } {
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

  const { standard, title, refLabels } = result.data;
  return { standard, title, refLabels };
}

/**
 * 同一ロケールの複数オーバーレイファイルを 1 つのマップへ統合する。
 * 1 ファイル = 1 規格の運用なので、規格 ID の重複は設定ミスとして落とす。
 */
export function loadComplianceOverlay(files: readonly RawYamlFile[]): ComplianceOverlayMap {
  const merged: ComplianceOverlayMap = {};
  const seenIn: Record<string, string> = {};

  for (const file of files) {
    const { standard, title, refLabels } = parseComplianceOverlayFile(file.text, file.source);
    const previous = seenIn[standard];
    if (previous !== undefined) {
      throw new ComplianceMapLoadError(
        `Duplicate overlay entry for standard "${standard}" in "${file.source}" (already defined in "${previous}")`,
        file.source,
      );
    }
    seenIn[standard] = file.source;
    merged[standard] = { title, refLabels };
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
    for (const ref of Object.keys(entry.refLabels ?? {})) {
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
 * `items` の `title` / `summary` は対象外（規格本文の要約であり、訳すなら別途
 * 全 597 項目の作業になる）。ここで扱うのは**脅威カードのチップに出る**
 * 規格名と ref の表示ラベルのみ。
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
    if (original && entry.title !== undefined) {
      standards.set(id, { ...original, title: entry.title });
    }
    for (const [ref, label] of Object.entries(entry.refLabels ?? {})) {
      refLabels.set(makeComplianceKey(id, ref), label);
    }
  }

  return { ...map, standards, refLabels };
}
