import { DEFAULT_PROJECT_KEY, getDb, PROJECTS_STORE } from './db';
import { deserializeProject, serializeProject, type SerializableState } from './serialize';
import type { PersistedProject } from './schema';

/**
 * 単一プロジェクトの save / load / clear。
 *
 * `key` を渡せばマルチプロジェクト化にも拡張できるが、Phase 1 では
 * `DEFAULT_PROJECT_KEY` 固定で auto-save 用途に限定する。
 */

export async function saveProject(
  state: SerializableState,
  key: string = DEFAULT_PROJECT_KEY,
): Promise<void> {
  const db = await getDb();
  await db.put(PROJECTS_STORE, serializeProject(state), key);
}

export async function loadProject(
  key: string = DEFAULT_PROJECT_KEY,
): Promise<PersistedProject | null> {
  const db = await getDb();
  const raw = await db.get(PROJECTS_STORE, key);
  if (raw === undefined) return null;
  const project = deserializeProject(raw);
  if (project === null) {
    console.warn(
      `[persistence] saved project "${key}" failed schema validation; falling back to defaults`,
    );
  }
  return project;
}

export async function clearProject(key: string = DEFAULT_PROJECT_KEY): Promise<void> {
  const db = await getDb();
  await db.delete(PROJECTS_STORE, key);
}
