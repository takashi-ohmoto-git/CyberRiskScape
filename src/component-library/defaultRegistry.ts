import { BUNDLED_COMPONENT_LIBRARY } from './loader/bundledComponentLibrary';
import { BUNDLED_COMPONENT_OVERLAYS } from './loader/bundledComponentOverlay';
import {
  findOrphanOverlayIds,
  findUntranslatedComponentIds,
  localizeComponents,
} from './loader/localizeComponentLibrary';
import { ComponentRegistry } from './registry';
import { isKnownBuiltinIcon } from './iconRegistry';
import type { Locale } from '../i18n';

/**
 * アプリ起動時に確定するコンポーネントレジストリ。
 * ノード描画・パレット表示・脅威ルール整合性検証で共通利用する singleton。
 *
 * これは**原本（日本語）** のレジストリ。型 ID・shape・canContain など
 * 言語非依存の照会はこれをそのまま使ってよい。表示名を出す箇所は
 * `getComponentRegistry(locale)` を使うこと。
 */
export const componentRegistry = new ComponentRegistry(BUNDLED_COMPONENT_LIBRARY);

// アイコン名の不整合検出（warn のみ・実行は止めない）
for (const comp of BUNDLED_COMPONENT_LIBRARY.components) {
  if (comp.icon.kind === 'builtin' && !isKnownBuiltinIcon(comp.icon.name)) {
    console.warn(
      `[component-library] Component "${comp.id}" uses unknown builtin icon "${comp.icon.name}" — will fall back to HelpCircle. Add it to BUILTIN_ICONS in iconRegistry.tsx.`,
    );
  }
}

// 訳が原本と食い違っていないかを起動時に診断（warn のみ。実行は止めない）。
for (const [locale, overlay] of Object.entries(BUNDLED_COMPONENT_OVERLAYS)) {
  const orphans = findOrphanOverlayIds(BUNDLED_COMPONENT_LIBRARY.components, overlay);
  if (orphans.length > 0) {
    console.warn(
      `[component-library] Overlay "${locale}" translates ${orphans.length} component type(s) that no longer exist: ${orphans.join(', ')}`,
    );
  }
  const untranslated = findUntranslatedComponentIds(BUNDLED_COMPONENT_LIBRARY.components, overlay);
  if (untranslated.length > 0) {
    console.warn(
      `[component-library] Overlay "${locale}" is missing ${untranslated.length} of ${BUNDLED_COMPONENT_LIBRARY.components.length} component types; those fall back to the original text.`,
    );
  }
}

const localizedRegistries = new Map<string, ComponentRegistry>();

/**
 * 指定ロケールのコンポーネントレジストリを返す。訳が無い型・フィールドは原文のまま。
 *
 * `ja` は原本のレジストリをそのまま返す（コピーもマージも発生しない）。
 * 他ロケールは初回呼び出し時にだけ合成し、以降はキャッシュを返す
 * （脅威ライブラリの `getThreatLibrary(locale)` と同じ設計）。
 */
export function getComponentRegistry(locale: Locale): ComponentRegistry {
  if (locale === 'ja') return componentRegistry;

  const cached = localizedRegistries.get(locale);
  if (cached) return cached;

  const overlay = BUNDLED_COMPONENT_OVERLAYS[locale];
  const registry = overlay
    ? new ComponentRegistry(localizeComponents(BUNDLED_COMPONENT_LIBRARY, overlay))
    : componentRegistry;

  localizedRegistries.set(locale, registry);
  return registry;
}
