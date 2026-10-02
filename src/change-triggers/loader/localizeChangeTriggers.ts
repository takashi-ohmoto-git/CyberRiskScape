import { parse as parseYaml } from 'yaml';
import {
  ChangeTriggerLibraryOverlayFileSchema,
  type ChangeTriggerOverlayMap,
} from '../schema/triggerOverlay';
import type { ChangeTrigger } from '../schema/trigger';
import { ChangeTriggerLoadError, type RawYamlFile } from './loadChangeTriggers';

/**
 * 実行トリガーの翻訳オーバーレイを読み込み、原本へ被せる。
 *
 * `threat-library/loader/localizeThreatLibrary.ts` と同じ設計。原本（日本語）は常に完全なので、
 * オーバーレイ側の欠落は**原文へフォールバック**する。
 */

/** オーバーレイ YAML 1 本をパース＋検証して `ChangeTriggerOverlayMap` を返す。 */
export function parseChangeTriggerOverlayFile(
  yamlText: string,
  source: string,
): ChangeTriggerOverlayMap {
  let parsed: unknown;
  try {
    parsed = parseYaml(yamlText);
  } catch (e) {
    throw new ChangeTriggerLoadError(
      `YAML parse error in overlay "${source}": ${(e as Error).message}`,
      source,
      e,
    );
  }

  const result = ChangeTriggerLibraryOverlayFileSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new ChangeTriggerLoadError(
      `Overlay schema validation failed for "${source}":\n${issues}`,
      source,
      result.error,
    );
  }

  return result.data.triggers;
}

/**
 * 同一ロケールの複数オーバーレイファイルを 1 つのマップへ統合する。
 * オーバーレイは原本ファイルと 1:1 対応させる運用なので、id 重複は設定ミスとして落とす。
 */
export function loadChangeTriggerOverlay(files: RawYamlFile[]): ChangeTriggerOverlayMap {
  const merged: ChangeTriggerOverlayMap = {};
  const seenIn: Record<string, string> = {};

  for (const file of files) {
    const triggers = parseChangeTriggerOverlayFile(file.text, file.source);
    for (const [triggerId, overlay] of Object.entries(triggers)) {
      const previous = seenIn[triggerId];
      if (previous !== undefined) {
        throw new ChangeTriggerLoadError(
          `Duplicate overlay entry for trigger "${triggerId}" in "${file.source}" (already defined in "${previous}")`,
          file.source,
        );
      }
      seenIn[triggerId] = file.source;
      merged[triggerId] = overlay;
    }
  }

  return merged;
}

/** オーバーレイにあるが原本に存在しないトリガー id を返す（診断用）。 */
export function findOrphanOverlayIds(
  triggers: readonly ChangeTrigger[],
  overlay: ChangeTriggerOverlayMap,
): string[] {
  const known = new Set(triggers.map((t) => t.id));
  return Object.keys(overlay).filter((id) => !known.has(id));
}

/** 原本のトリガーのうち、オーバーレイに訳が無いものの id を返す（診断用）。 */
export function findUntranslatedTriggerIds(
  triggers: readonly ChangeTrigger[],
  overlay: ChangeTriggerOverlayMap,
): string[] {
  return triggers.filter((t) => overlay[t.id] === undefined).map((t) => t.id);
}

/** トリガー集合へ訳文を適用する。指定の無いフィールドは原文のまま残す。 */
export function localizeTriggers(
  triggers: readonly ChangeTrigger[],
  overlay: ChangeTriggerOverlayMap,
): ChangeTrigger[] {
  return triggers.map((trigger) => {
    const t = overlay[trigger.id];
    if (!t) return trigger;

    const localized: ChangeTrigger = { ...trigger };
    if (t.title !== undefined) localized.title = t.title;
    if (t.checkpoint !== undefined) localized.checkpoint = t.checkpoint;
    return localized;
  });
}
