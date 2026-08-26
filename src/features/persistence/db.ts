import { openDB, type IDBPDatabase } from 'idb';

/**
 * IndexedDB 接続を遅延初期化する薄いラッパー。
 *
 * - DB 名 / ストア名 / バージョンは将来のマイグレーション余地として定数化。
 * - `projects` ストアにプロジェクトレコードを `id: string` をキーとして格納。
 *   Phase 1 では単一プロジェクト `DEFAULT_PROJECT_KEY` のみ使用する。
 */

const DB_NAME = 'cyberriskscape';
const DB_VERSION = 3;
export const PROJECTS_STORE = 'projects';
export const DEFAULT_PROJECT_KEY = 'default';
/**
 * カスタム脅威ルールライブラリのストア（v2 で追加）。
 * 単一プロジェクト（`PROJECTS_STORE`）と異なり、全プロジェクト共通で
 * ライブラリ `id` をキーに複数レコードを格納する。
 */
export const CUSTOM_RULE_LIBRARIES_STORE = 'customRuleLibraries';
/**
 * File System Access API のディレクトリハンドルを永続化するストア（v3 で追加）。
 * `FileSystemDirectoryHandle` は構造化複製可能なため、ユーザーが一度選んだ
 * 「保存先フォルダ」をリロードを跨いで記憶できる（権限は再アクセス時に再取得）。
 */
export const FS_HANDLES_STORE = 'fsHandles';

let dbPromise: Promise<IDBPDatabase> | null = null;

export function getDb(): Promise<IDBPDatabase> {
  if (!dbPromise) {
    dbPromise = openDB(DB_NAME, DB_VERSION, {
      upgrade(db) {
        if (!db.objectStoreNames.contains(PROJECTS_STORE)) {
          db.createObjectStore(PROJECTS_STORE);
        }
        if (!db.objectStoreNames.contains(CUSTOM_RULE_LIBRARIES_STORE)) {
          db.createObjectStore(CUSTOM_RULE_LIBRARIES_STORE);
        }
        if (!db.objectStoreNames.contains(FS_HANDLES_STORE)) {
          db.createObjectStore(FS_HANDLES_STORE);
        }
      },
    });
  }
  return dbPromise;
}
