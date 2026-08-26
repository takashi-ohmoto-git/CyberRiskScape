import type { Severity } from './types';

/**
 * 重大度の配色（単一の真実）。Canvas を基準に統一する：
 * Critical=rose（赤）/ High=orange / Medium=blue / Low=sky（淡い青）。
 *
 * Tailwind JIT はソース中のリテラルクラス名のみを検出するため、各バリアントは
 * テンプレート合成せずフルクラス文字列で列挙する（`bg-${hue}-600` は purge される）。
 */

/** 単色背景のみ（アイコンバッジ等）。Canvas の脅威バッジで使用。 */
export const SEVERITY_BG: Record<Severity, string> = {
  Critical: 'bg-rose-600',
  High: 'bg-orange-500',
  Medium: 'bg-blue-500',
  Low: 'bg-sky-500',
};

/** 単色バッジ（白文字）。脅威リストの severity バッジ。 */
export const SEVERITY_BADGE_SOLID: Record<Severity, string> = {
  Critical: 'bg-rose-600 text-white',
  High: 'bg-orange-500 text-white',
  Medium: 'bg-blue-600 text-white',
  Low: 'bg-sky-600 text-white',
};

/** カード枠（淡い背景 + 枠線）。脅威カードのコンテナ。 */
export const SEVERITY_CONTAINER: Record<Severity, string> = {
  Critical: 'bg-rose-500/5 border-rose-500',
  High: 'bg-orange-500/5 border-orange-500',
  Medium: 'bg-blue-500/5 border-blue-500',
  Low: 'bg-sky-500/5 border-sky-500',
};

/** 控えめバッジ（淡い背景 + 文字色 + 枠）。Analytics の severity バッジ。 */
export const SEVERITY_BADGE_SUBTLE: Record<Severity, string> = {
  Critical: 'bg-rose-500/15 text-rose-300 border-rose-500/40',
  High: 'bg-orange-500/15 text-orange-300 border-orange-500/40',
  Medium: 'bg-blue-500/15 text-blue-300 border-blue-500/40',
  Low: 'bg-sky-500/15 text-sky-300 border-sky-500/40',
};

/** 重大度ドット（小円）。Analytics の対策一覧・ツリー。 */
export const SEVERITY_DOT: Record<Severity, string> = {
  Critical: 'bg-rose-400',
  High: 'bg-orange-400',
  Medium: 'bg-blue-400',
  Low: 'bg-sky-400',
};
