/**
 * 脅威・指摘への対応のイベントログ（docs/log §2.136）で共有する型。
 * 履歴の読み取り（CLI の gitHistory）とイベントの組み立て（純粋関数）の境界。
 */

/** モデル JSON の 1 版（git の 1 コミット分）。 */
export interface ModelSnapshot {
  /** 版の識別子（git のコミットハッシュ）。 */
  revision: string;
  /** 版の時刻（ISO 8601。git のコミット時刻）。 */
  time: string;
  /** 版を作った人（git のコミットの作者名）。 */
  author?: string;
  /** コミットメッセージの 1 行目。 */
  message?: string;
  /** プロジェクト JSON（未検証）。 */
  raw: unknown;
}
