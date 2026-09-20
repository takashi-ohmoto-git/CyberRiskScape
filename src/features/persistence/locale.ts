import { SETTINGS_STORE, getDb } from './db';
import type { Locale } from '../../i18n';

/**
 * UI ロケールの永続化。`localStorage` は使用禁止のため IndexedDB に置く。
 *
 * 保存値は外部から書き換わり得る永続データなので、読み出し時に
 * 既知の Locale かどうかを検証し、未知の値は null として扱う。
 */

const LOCALE_KEY = 'locale';
const KNOWN_LOCALES: readonly Locale[] = ['ja', 'en'];

export async function getSavedLocale(): Promise<Locale | null> {
  const db = await getDb();
  const value = await db.get(SETTINGS_STORE, LOCALE_KEY);
  return KNOWN_LOCALES.includes(value as Locale) ? (value as Locale) : null;
}

export async function setSavedLocale(locale: Locale): Promise<void> {
  const db = await getDb();
  await db.put(SETTINGS_STORE, locale, LOCALE_KEY);
}
