/**
 * 実行環境のタイムゾーンでの日付 `YYYY-MM-DD`。ファイル名・文書の作成日に使う。
 * `toISOString()` は UTC のため、日本時間の 0〜9 時に前日の日付になる。
 */
export function formatLocalDate(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}
