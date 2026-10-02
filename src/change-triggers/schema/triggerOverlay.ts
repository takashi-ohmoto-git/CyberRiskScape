import { z } from 'zod';

/**
 * 実行トリガーの翻訳オーバーレイのスキーマ。
 *
 * `threat-library/schema/threatRuleOverlay.ts` と同じ翻訳オーバーレイ方式：原本
 * （`data/change-triggers/triggers.yaml`）は日本語を「真実」として保持し、他言語は
 * `data/change-triggers/i18n/<locale>/triggers.yaml` に **トリガー id を鍵とする差分**として置く。
 * `title` / `checkpoint` のみ翻訳対象（`detect` は判定ロジックなので翻訳しない）。
 *
 * 全フィールドが optional で、欠けているものは原文へフォールバックする。
 */
export const ChangeTriggerOverlaySchema = z
  .object({
    title: z.string().min(1).optional(),
    checkpoint: z.string().min(1).optional(),
  })
  .strict();

/** オーバーレイファイル 1 本の形。 */
export const ChangeTriggerLibraryOverlayFileSchema = z
  .object({
    schemaVersion: z.literal(1),
    /** ロケール識別子（例 `en`）。ディレクトリ名との一致はローダーが検証する。 */
    locale: z.string().min(2),
    triggers: z.record(z.string(), ChangeTriggerOverlaySchema),
  })
  .strict();

export type ChangeTriggerOverlay = z.infer<typeof ChangeTriggerOverlaySchema>;
export type ChangeTriggerLibraryOverlayFile = z.infer<typeof ChangeTriggerLibraryOverlayFileSchema>;

/** トリガー id → 訳文。複数ファイル分をマージしたもの。 */
export type ChangeTriggerOverlayMap = Record<string, ChangeTriggerOverlay>;
