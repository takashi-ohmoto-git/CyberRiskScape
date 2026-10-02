import { loadChangeTriggers, type LoadResult, type RawYamlFile } from './loadChangeTriggers';
import {
  findOrphanOverlayIds,
  findUntranslatedTriggerIds,
  loadChangeTriggerOverlay,
  localizeTriggers,
} from './localizeChangeTriggers';
import type { ChangeTriggerOverlayMap } from '../schema/triggerOverlay';
import type { Locale } from '../../i18n';
import { componentRegistry } from '../../component-library/defaultRegistry';

/**
 * `data/change-triggers/*.yaml` をビルド時にバンドルし、起動時にロードする。
 *
 * `threat-library/loader/bundledLibrary.ts` と同じ設計（Vite の `import.meta.glob` で
 * raw 文字列として取り込み、共通ローダーに通す）。
 */
const yamlModules = import.meta.glob<string>('../../../data/change-triggers/*.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

const files: RawYamlFile[] = Object.entries(yamlModules).map(([path, text]) => ({
  source: path.split('/').pop() ?? path,
  text,
}));

export const BUNDLED_CHANGE_TRIGGERS: LoadResult = loadChangeTriggers(files);

// トリガーの detect が参照する nodeTypes / categories が ComponentRegistry に
// 登録済みかを起動時に検証。dangling は warn のみで実行は止めない。
const categoryIds = new Set(componentRegistry.getCategories().map((c) => c.id));
for (const trigger of BUNDLED_CHANGE_TRIGGERS.triggers) {
  for (const detector of trigger.detect) {
    if (detector.kind !== 'node-added' && detector.kind !== 'node-changed') continue;
    for (const nodeType of detector.nodeTypes ?? []) {
      if (!componentRegistry.has(nodeType)) {
        console.warn(
          `[change-triggers] Trigger "${trigger.id}" references unknown component type "${nodeType}". This detector will never fire until a component library declares this type.`,
        );
      }
    }
    for (const category of detector.categories ?? []) {
      if (!categoryIds.has(category)) {
        console.warn(
          `[change-triggers] Trigger "${trigger.id}" references unknown category "${category}".`,
        );
      }
    }
  }
}

/**
 * 翻訳オーバーレイ（`data/change-triggers/i18n/<locale>/*.yaml`）。
 * 原本（日本語）とは別ファイルに置き、`ChangeTrigger` のスキーマは変更しない。
 */
const overlayModules = import.meta.glob<string>('../../../data/change-triggers/i18n/*/*.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

const overlayFilesByLocale: Record<string, RawYamlFile[]> = {};
for (const [path, text] of Object.entries(overlayModules)) {
  const segments = path.split('/');
  const fileName = segments[segments.length - 1] ?? path;
  const locale = segments[segments.length - 2] ?? '';
  (overlayFilesByLocale[locale] ??= []).push({ source: `${locale}/${fileName}`, text });
}

const OVERLAYS: Record<string, ChangeTriggerOverlayMap> = Object.fromEntries(
  Object.entries(overlayFilesByLocale).map(([locale, files]) => [
    locale,
    loadChangeTriggerOverlay(files),
  ]),
);

// 訳が原本と食い違っていないかを起動時に診断（warn のみ。実行は止めない）。
for (const [locale, overlay] of Object.entries(OVERLAYS)) {
  const orphans = findOrphanOverlayIds(BUNDLED_CHANGE_TRIGGERS.triggers, overlay);
  if (orphans.length > 0) {
    console.warn(
      `[change-triggers] Overlay "${locale}" translates ${orphans.length} trigger(s) that no longer exist: ${orphans.join(', ')}`,
    );
  }
  const untranslated = findUntranslatedTriggerIds(BUNDLED_CHANGE_TRIGGERS.triggers, overlay);
  if (untranslated.length > 0) {
    console.warn(
      `[change-triggers] Overlay "${locale}" is missing ${untranslated.length} of ${BUNDLED_CHANGE_TRIGGERS.triggers.length} triggers; those fall back to the original text.`,
    );
  }
}

const localizedCache = new Map<string, LoadResult>();

/**
 * 指定ロケールの実行トリガーを返す。訳が無いトリガー・フィールドは原文のまま。
 * `ja` は原本そのものを返す（コピーもマージも発生しない）。
 */
export function getChangeTriggers(locale: Locale): LoadResult {
  if (locale === 'ja') return BUNDLED_CHANGE_TRIGGERS;

  const cached = localizedCache.get(locale);
  if (cached) return cached;

  const overlay = OVERLAYS[locale];
  const result: LoadResult = overlay
    ? {
        ...BUNDLED_CHANGE_TRIGGERS,
        triggers: localizeTriggers(BUNDLED_CHANGE_TRIGGERS.triggers, overlay),
      }
    : BUNDLED_CHANGE_TRIGGERS;

  localizedCache.set(locale, result);
  return result;
}
