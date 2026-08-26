import { z } from 'zod';
import { ThreatRuleSchema } from '../../threat-library/schema/threatRule';

/**
 * ユーザーが作成するカスタム脅威ルールライブラリ。
 *
 * - bundled YAML（出荷物・ビルド時バンドル）とは別系統の**ユーザーデータ**で、
 *   IndexedDB の `customRuleLibraries` ストアに**全プロジェクト共通**で保存する。
 * - ルールの形は出荷ライブラリと同一（`ThreatRuleSchema` を唯一の真実源として共有）。
 * - `enabled` でライブラリ単位の有効/無効を切り替える。無効ライブラリはエンジンに渡さない。
 */
export const CUSTOM_RULE_LIBRARY_SCHEMA_VERSION = 1 as const;

export const CustomRuleLibrarySchema = z
  .object({
    id: z.string().min(1),
    name: z.string().min(1).max(200),
    schemaVersion: z.literal(CUSTOM_RULE_LIBRARY_SCHEMA_VERSION),
    enabled: z.boolean(),
    rules: z.array(ThreatRuleSchema),
    updatedAt: z.number().int().nonnegative(),
  })
  .superRefine((lib, ctx) => {
    // ライブラリ内のルール id は一意（detectThreats の出力 id 安定性のため）。
    const seen = new Set<string>();
    lib.rules.forEach((r, i) => {
      if (seen.has(r.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `duplicate rule id "${r.id}" within library`,
          path: ['rules', i, 'id'],
        });
      }
      seen.add(r.id);
    });
  });

export type CustomRuleLibrary = z.infer<typeof CustomRuleLibrarySchema>;

/** 新規ライブラリ用の id を生成する。 */
export function newLibraryId(): string {
  return `lib-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
}

/** 空のカスタムルールライブラリを生成する。 */
export function createEmptyLibrary(name: string): CustomRuleLibrary {
  return {
    id: newLibraryId(),
    name,
    schemaVersion: CUSTOM_RULE_LIBRARY_SCHEMA_VERSION,
    enabled: true,
    rules: [],
    updatedAt: Date.now(),
  };
}
