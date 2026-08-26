import { CUSTOM_RULE_LIBRARIES_STORE, getDb } from '../persistence/db';
import { CustomRuleLibrarySchema, type CustomRuleLibrary } from './schema';

/**
 * カスタムルールライブラリの IndexedDB アクセス層（薄いラッパー）。
 * 保存形式は信頼境界外として扱い、ロード時に Zod 検証する。
 * 検証に失敗したレコードは破棄して warn（壊れたデータでアプリを止めない）。
 */

export async function listCustomRuleLibraries(): Promise<CustomRuleLibrary[]> {
  const db = await getDb();
  const raw = await db.getAll(CUSTOM_RULE_LIBRARIES_STORE);
  const out: CustomRuleLibrary[] = [];
  for (const r of raw) {
    const parsed = CustomRuleLibrarySchema.safeParse(r);
    if (parsed.success) out.push(parsed.data);
    else console.warn('[custom-rules] skipping invalid library record', parsed.error);
  }
  // 表示安定のため name でソート
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

export async function saveCustomRuleLibrary(lib: CustomRuleLibrary): Promise<void> {
  const db = await getDb();
  await db.put(CUSTOM_RULE_LIBRARIES_STORE, lib, lib.id);
}

export async function deleteCustomRuleLibrary(id: string): Promise<void> {
  const db = await getDb();
  await db.delete(CUSTOM_RULE_LIBRARIES_STORE, id);
}
