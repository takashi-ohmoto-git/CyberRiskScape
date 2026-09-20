import { parse as parseYaml } from 'yaml';
import {
  ComponentLibraryOverlayFileSchema,
  type ComponentOverlayMap,
} from '../schema/componentOverlay';
import type { ComponentDefinition } from '../schema/component';
import { ComponentLibraryLoadError, type LoadResult, type RawYamlFile } from './loadComponentLibrary';

/**
 * コンポーネント型の翻訳オーバーレイを読み込み、原本へ被せる。
 *
 * 原本（日本語）は常に完全なので、オーバーレイ側の欠落は**原文へフォールバック**する。
 * 脅威ライブラリの `localizeThreatLibrary.ts` と同じ設計。
 */

/** オーバーレイ YAML 1 本をパース＋検証して `ComponentOverlayMap` を返す。 */
export function parseComponentOverlayFile(
  yamlText: string,
  source: string,
): ComponentOverlayMap {
  let parsed: unknown;
  try {
    parsed = parseYaml(yamlText);
  } catch (e) {
    throw new ComponentLibraryLoadError(
      `YAML parse error in overlay "${source}": ${(e as Error).message}`,
      source,
      e,
    );
  }

  const result = ComponentLibraryOverlayFileSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new ComponentLibraryLoadError(
      `Overlay schema validation failed for "${source}":\n${issues}`,
      source,
      result.error,
    );
  }

  return result.data.components;
}

/**
 * 同一ロケールの複数オーバーレイファイルを 1 つのマップへ統合する。
 * オーバーレイは原本ファイルと 1:1 対応させる運用なので、id 重複は設定ミスとして落とす。
 */
export function loadComponentOverlay(files: readonly RawYamlFile[]): ComponentOverlayMap {
  const merged: ComponentOverlayMap = {};
  const seenIn: Record<string, string> = {};

  for (const file of files) {
    const components = parseComponentOverlayFile(file.text, file.source);
    for (const [componentId, overlay] of Object.entries(components)) {
      const previous = seenIn[componentId];
      if (previous !== undefined) {
        throw new ComponentLibraryLoadError(
          `Duplicate overlay entry for component "${componentId}" in "${file.source}" (already defined in "${previous}")`,
          file.source,
        );
      }
      seenIn[componentId] = file.source;
      merged[componentId] = overlay;
    }
  }

  return merged;
}

/**
 * オーバーレイにあるが原本に存在しないコンポーネント型 ID を返す（診断用）。
 * 型を消したときにオーバーレイが取り残されても起動は止めず、warn に留めるための材料。
 */
export function findOrphanOverlayIds(
  components: readonly ComponentDefinition[],
  overlay: ComponentOverlayMap,
): string[] {
  const known = new Set(components.map((c) => c.id));
  return Object.keys(overlay).filter((id) => !known.has(id));
}

/** 原本のコンポーネントのうち、オーバーレイに訳が無いものの ID を返す（診断用）。 */
export function findUntranslatedComponentIds(
  components: readonly ComponentDefinition[],
  overlay: ComponentOverlayMap,
): string[] {
  return components.filter((c) => overlay[c.id] === undefined).map((c) => c.id);
}

/**
 * ロード結果へ訳文を適用する。指定の無いフィールドは原文のまま残す。
 *
 * `libraries` / `categories` / `componentToLibrary` / `warnings` は言語非依存
 * （`categories[].label` は原本が既に英語）なので、そのまま引き継ぐ。
 */
export function localizeComponents(load: LoadResult, overlay: ComponentOverlayMap): LoadResult {
  return {
    ...load,
    components: load.components.map((comp) => {
      const t = overlay[comp.id];
      if (!t || (t.label === undefined && t.description === undefined)) return comp;

      const localized: ComponentDefinition = { ...comp };
      if (t.label !== undefined) localized.label = t.label;
      if (t.description !== undefined) localized.description = t.description;
      return localized;
    }),
  };
}
