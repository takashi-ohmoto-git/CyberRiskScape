/**
 * 軽量な自前 i18n 基盤。外部ライブラリ非依存（最小依存方針）。
 *
 * - デフォルトは日本語（ja）。未定義キーは ja にフォールバック。
 * - locale 状態はモジュールレベルで保持し、useSyncExternalStore で購読する。
 *   永続化はしない（必要になったら IndexedDB 経由で。localStorage は禁止）。
 * - 文言の定義は locales/ja.ts（真実）と locales/en.ts（部分上書き）。
 */
import { useCallback, useSyncExternalStore } from 'react';
import { ja, type TranslationKey } from './locales/ja';
import { en } from './locales/en';

export type Locale = 'ja' | 'en';
export type { TranslationKey };

const DICTS: Record<Locale, Partial<Record<TranslationKey, string>>> = { ja, en };

/** `{name}` 形式のプレースホルダを params で置換する。 */
type Params = Record<string, string | number>;
function interpolate(template: string, params?: Params): string {
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (match, key) =>
    key in params ? String(params[key]) : match,
  );
}

/**
 * 翻訳を解決する（React 外でも使える純関数）。
 * 指定 locale に無ければ ja にフォールバックする。
 */
export function translate(
  key: TranslationKey,
  locale: Locale,
  params?: Params,
): string {
  const raw = DICTS[locale]?.[key] ?? ja[key];
  return interpolate(raw, params);
}

// --- locale 状態（モジュールレベルの簡易ストア） ---
let currentLocale: Locale = 'ja';
const listeners = new Set<() => void>();

export function getLocale(): Locale {
  return currentLocale;
}

export function setLocale(locale: Locale): void {
  if (locale === currentLocale) return;
  currentLocale = locale;
  listeners.forEach((fn) => fn());
}

function subscribe(onChange: () => void): () => void {
  listeners.add(onChange);
  return () => listeners.delete(onChange);
}

/** 現在の locale を購読する。locale 変更で再レンダーされる。 */
export function useLocale(): [Locale, (locale: Locale) => void] {
  const locale = useSyncExternalStore(subscribe, getLocale, getLocale);
  return [locale, setLocale];
}

/** 翻訳関数 t を返すフック。locale 変更時に t も更新される。 */
export function useT(): (key: TranslationKey, params?: Params) => string {
  const [locale] = useLocale();
  return useCallback(
    (key: TranslationKey, params?: Params) => translate(key, locale, params),
    [locale],
  );
}
