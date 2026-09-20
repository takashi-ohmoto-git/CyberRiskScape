import { z } from 'zod';

/**
 * 脅威ルールの翻訳オーバーレイのスキーマ。
 *
 * 原本（`data/threat-library/*.yaml`）は日本語を「真実」として保持し、
 * 他言語は `data/threat-library/i18n/<locale>/<source>.yaml` に
 * **ルール id を鍵とする差分**として置く。`ThreatRule` 本体のスキーマは変更しない。
 *
 * 全フィールドが optional で、欠けているものは原文へフォールバックする。
 * 部分翻訳のまま出荷できることを設計の前提とする。
 */

/** 1 ルール分の訳文。指定されたフィールドだけを上書きする。 */
export const ThreatRuleOverlaySchema = z
  .object({
    name: z.string().min(1).optional(),
    category: z.string().min(1).optional(),
    description: z.string().min(1).optional(),
    /**
     * 緩和策。原文と同じく `[Foundation]` / `[Enterprise]` / `[Advanced]` の
     * tier markup を保持すること（`mitigationTiers` は訳文から再計算される）。
     */
    mitigation: z.string().min(1).optional(),
    /**
     * 動的ルールの条件別記述（原本の `appliesTo.conditions`、edge ルールのみ）。
     * **原本と同じ並び順**で対応させる
     * （添字が一致しないものは適用しない）。
     */
    conditions: z
      .array(z.object({ description: z.string().min(1) }).strict())
      .nonempty()
      .optional(),
    /**
     * 出典の表題（原本の `references[].title`）。**添字を鍵とする疎なマップ**。
     *
     * 出典は大半が英語の標準名で、訳が要るのは末尾に付く日本語注記だけなので、
     * `conditions` のような全要素の配列にすると未訳の要素まで原文を書き写す必要が
     * 生じ、原本を直したときに写しが取り残される。訳す要素だけを指定できる形にする。
     * `url` は言語非依存のため対象外。原本に無い添字は無視する。
     */
    references: z
      .record(
        z.string().regex(/^\d+$/, 'reference key must be the index in the original array'),
        z.object({ title: z.string().min(1) }).strict(),
      )
      .optional(),
  })
  .strict();

/** オーバーレイファイル 1 本の形。 */
export const ThreatLibraryOverlayFileSchema = z
  .object({
    schemaVersion: z.literal(1),
    /** ロケール識別子（例 `en`）。ディレクトリ名との一致はローダーが検証する。 */
    locale: z.string().min(2),
    rules: z.record(z.string(), ThreatRuleOverlaySchema),
  })
  .strict();

export type ThreatRuleOverlay = z.infer<typeof ThreatRuleOverlaySchema>;
export type ThreatLibraryOverlayFile = z.infer<typeof ThreatLibraryOverlayFileSchema>;

/** ルール id → 訳文。複数ファイル分をマージしたもの。 */
export type ThreatRuleOverlayMap = Record<string, ThreatRuleOverlay>;
