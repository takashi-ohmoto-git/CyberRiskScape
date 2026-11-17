import { DEFAULT_PROJECT_KEY, getDb, PROJECTS_STORE } from './db';
import { deserializeProject, serializeProject, type SerializableState } from './serialize';
import type { PersistedProject } from './schema';
import { getProjectStorage, type SaveTrigger } from './storage';

/**
 * 単一プロジェクトの save / load / clear。
 *
 * 保存先は `storage.ts`（既定は IndexedDB の `DEFAULT_PROJECT_KEY`）。
 * ここでは保存形式への変換と、読み込んだ値の検証を行う。
 */

export async function saveProject(state: SerializableState, trigger: SaveTrigger = 'auto'): Promise<void> {
  await getProjectStorage().save(serializeProject(state), trigger);
}

export async function loadProject(): Promise<PersistedProject | null> {
  const raw = await getProjectStorage().load();
  if (raw === undefined || raw === null) return null;
  const project = deserializeProject(raw);
  if (project === null) {
    console.warn('[persistence] saved project failed schema validation; falling back to defaults');
  }
  return project;
}

export async function clearProject(key: string = DEFAULT_PROJECT_KEY): Promise<void> {
  const db = await getDb();
  await db.delete(PROJECTS_STORE, key);
}
