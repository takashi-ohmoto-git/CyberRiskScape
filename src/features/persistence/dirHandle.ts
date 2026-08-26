import { FS_HANDLES_STORE, getDb } from './db';

/**
 * ユーザーが選んだ「保存先フォルダ」の `FileSystemDirectoryHandle` を
 * IndexedDB に保存／復元する。Phase 1 では単一フォルダのみ扱うため固定キー。
 *
 * ハンドル自体は構造化複製で永続化できるが、**アクセス権限はセッションを
 * 跨ぐと失われる**ため、復元後に `ensurePermission`（[[fileSystem]]）で
 * 権限を取り直す必要がある。
 */

const SAVE_DIR_KEY = 'saveDirectory';

export async function getSavedDirectoryHandle(): Promise<FileSystemDirectoryHandle | null> {
  const db = await getDb();
  const handle = await db.get(FS_HANDLES_STORE, SAVE_DIR_KEY);
  return (handle as FileSystemDirectoryHandle | undefined) ?? null;
}

export async function setSavedDirectoryHandle(handle: FileSystemDirectoryHandle): Promise<void> {
  const db = await getDb();
  await db.put(FS_HANDLES_STORE, handle, SAVE_DIR_KEY);
}

export async function clearSavedDirectoryHandle(): Promise<void> {
  const db = await getDb();
  await db.delete(FS_HANDLES_STORE, SAVE_DIR_KEY);
}
