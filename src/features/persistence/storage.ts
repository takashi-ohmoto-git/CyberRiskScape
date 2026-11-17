/**
 * プロジェクトの保存先。
 *
 * 既定はブラウザの IndexedDB（このアプリは完全にローカルで動き、外へ送らない）。
 * アプリを別の画面に組み込む側は、アプリを起動する前に `setProjectStorage` で保存先を差し替えられる。
 * 読み込んだ値の検証と、保存形式への変換は呼ぶ側（`repository.ts`）が行う。保存先は値をそのまま受け渡すだけ。
 */
import { DEFAULT_PROJECT_KEY, getDb, PROJECTS_STORE } from './db';
import type { PersistedProject } from './schema';

/** 保存のきっかけ。auto＝編集のたびの自動保存、manual＝利用者が保存ボタンを押した。 */
export type SaveTrigger = 'auto' | 'manual';

export interface ProjectStorage {
  /** 保存してあるプロジェクト（検証の前の値）。無ければ undefined。 */
  load(): Promise<unknown>;
  /** 保存する。失敗したら例外を投げる（保存ボタンのときは、画面に失敗と出る）。 */
  save(project: PersistedProject, trigger: SaveTrigger): Promise<void>;
}

const indexedDbStorage: ProjectStorage = {
  async load() {
    const db = await getDb();
    return db.get(PROJECTS_STORE, DEFAULT_PROJECT_KEY);
  },
  async save(project) {
    const db = await getDb();
    await db.put(PROJECTS_STORE, project, DEFAULT_PROJECT_KEY);
  },
};

let current: ProjectStorage = indexedDbStorage;

export function getProjectStorage(): ProjectStorage {
  return current;
}

/** 保存先を差し替える。アプリを起動する（最初に読み込む）前に呼ぶ。 */
export function setProjectStorage(storage: ProjectStorage): void {
  current = storage;
}

/** 既定の保存先（IndexedDB）に戻す。 */
export function resetProjectStorage(): void {
  current = indexedDbStorage;
}
