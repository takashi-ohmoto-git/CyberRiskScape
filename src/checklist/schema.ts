import { z } from 'zod';

/**
 * 注意喚起チェックリスト（`data/checklists/<id>.yaml`）のスキーマ。
 * 設計は docs/posture-checklist.md §6。項目の知識（対象の型・関連する脅威ルール・確かめ方）は
 * すべて YAML に置き、コードには持たない。
 */

const ChecklistItemSchema = z
  .object({
    id: z.string().min(1),
    title: z.string().min(1),
    howTo: z.string().min(1),
    /** 図にこの型のノードが 1 つも無ければ「対象なし」。 */
    targetTypes: z.array(z.string().min(1)).min(1),
    ruleIds: z.array(z.string().min(1)).min(1),
  })
  .strict();

const ChecklistGroupSchema = z
  .object({
    id: z.string().min(1),
    title: z.string().min(1),
    items: z.array(ChecklistItemSchema).min(1),
  })
  .strict();

const SourceSchema = z
  .object({
    publisher: z.string().min(1),
    title: z.string().min(1),
    url: z.string().url(),
    publishedAt: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  })
  .strict();

export const ChecklistFileSchema = z
  .object({
    schemaVersion: z.literal(1),
    checklist: z
      .object({
        id: z.string().min(1),
        title: z.string().min(1),
        source: SourceSchema,
        /** 最終点検日がこれより古いノードを「点検が古い」として一覧に出す。 */
        staleDays: z.number().int().positive(),
      })
      .strict(),
    groups: z.array(ChecklistGroupSchema).min(1),
  })
  .strict();

/** 翻訳オーバーレイ。タイトルと確かめ方のみ。グループ・項目は id を鍵にする。 */
export const ChecklistOverlayFileSchema = z
  .object({
    schemaVersion: z.literal(1),
    locale: z.string().min(2),
    checklist: z
      .object({
        title: z.string().min(1).optional(),
        source: z
          .object({ publisher: z.string().min(1).optional(), title: z.string().min(1).optional() })
          .strict()
          .optional(),
      })
      .strict()
      .optional(),
    groups: z.record(
      z.string(),
      z
        .object({
          title: z.string().min(1).optional(),
          items: z
            .record(
              z.string(),
              z
                .object({ title: z.string().min(1).optional(), howTo: z.string().min(1).optional() })
                .strict(),
            )
            .optional(),
        })
        .strict(),
    ),
  })
  .strict();

export type ChecklistFile = z.infer<typeof ChecklistFileSchema>;
export type ChecklistOverlayFile = z.infer<typeof ChecklistOverlayFileSchema>;
export type ChecklistItem = z.infer<typeof ChecklistItemSchema>;
export type ChecklistGroup = z.infer<typeof ChecklistGroupSchema>;
/** 検証済みのチェックリスト 1 件（`ChecklistFile` と同形）。 */
export type Checklist = ChecklistFile;
