import { z } from 'zod';
import { ThreatRuleSchema } from '../../threat-library/schema/threatRule';
import { createEmptyLibrary, type CustomRuleLibrary } from './schema';

/**
 * カスタムルールライブラリの **可搬な** エクスポート形式（JSON）。
 *
 * インスタンス固有値（`id` / `enabled` / `updatedAt`）は含めない。インポート時は
 * 新しい id を採番し `enabled: true` で取り込む（別環境間で衝突しないため）。
 * `kind` マーカーは任意（手書き JSON も受理。存在する場合は一致を要求）。
 */
export const EXPORT_SCHEMA_VERSION = 1 as const;
export const EXPORT_KIND = 'cyberriskscape-rule-library' as const;

export const CustomRuleLibraryExportSchema = z
  .object({
    schemaVersion: z.literal(EXPORT_SCHEMA_VERSION),
    kind: z.literal(EXPORT_KIND).optional(),
    name: z.string().min(1).max(200),
    rules: z.array(ThreatRuleSchema),
  })
  .superRefine((data, ctx) => {
    const seen = new Set<string>();
    data.rules.forEach((r, i) => {
      if (seen.has(r.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `duplicate rule id "${r.id}"`,
          path: ['rules', i, 'id'],
        });
      }
      seen.add(r.id);
    });
  });

/** ライブラリを可搬な JSON 文字列に変換する（整形済み）。 */
export function serializeLibraryToJson(lib: CustomRuleLibrary): string {
  return JSON.stringify(
    {
      schemaVersion: EXPORT_SCHEMA_VERSION,
      kind: EXPORT_KIND,
      name: lib.name,
      rules: lib.rules,
    },
    null,
    2,
  );
}

export type ParseLibraryResult =
  | { ok: true; library: CustomRuleLibrary }
  | { ok: false; error: string };

/**
 * JSON 文字列を検証し、取り込み可能な `CustomRuleLibrary` を生成する。
 * 失敗時はユーザー表示用のエラーメッセージを返す（throw しない）。
 */
export function parseLibraryFromJson(text: string): ParseLibraryResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return { ok: false, error: `JSON 構文エラー: ${(e as Error).message}` };
  }

  const result = CustomRuleLibraryExportSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('; ');
    return { ok: false, error: `検証エラー: ${issues}` };
  }

  const library: CustomRuleLibrary = {
    ...createEmptyLibrary(result.data.name),
    rules: result.data.rules,
  };
  return { ok: true, library };
}
