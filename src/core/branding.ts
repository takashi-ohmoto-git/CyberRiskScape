/**
 * プロダクト名・ブランド名の単一の真実（single source of truth）。
 * CLAUDE.md 絶対制約：ブランド名を各所に直書きせず、必ずここを参照する。
 *
 * 注：index.html の <title> は React 起動前の静的メタデータのため例外的に
 * 文字列を持つ。アプリコード内（UI・メッセージ）では本モジュールを使う。
 */
export const BRANDING = {
  /** プロダクト名。 */
  name: 'CyberRiskScape',
  /** 短い説明（タグライン）。 */
  tagline: 'AI脅威モデリング',
  /** ブラウザタイトル等で使うフルタイトル。 */
  fullTitle: 'CyberRiskScape — AI脅威モデリング',
} as const;
