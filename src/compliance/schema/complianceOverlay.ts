import { z } from 'zod';
import { StandardIdSchema } from './complianceItem';

/**
 * コンプライアンスマッピングの翻訳オーバーレイのスキーマ。
 *
 * 原本（`data/compliance/*.yaml`）は日本語を「真実」として保持し、他言語は
 * `data/compliance/i18n/<locale>/<standard>.yaml` に差分として置く。
 * `ComplianceItem` / `ComplianceStandard` のスキーマは変更しない
 * （脅威ライブラリ・コンポーネントライブラリと同方式）。
 *
 * `ref`（`(standard, ref)` の逆引きキー）は**置換しない**。訳すのは表示だけなので、
 * 別立ての `refLabels`（ref → 表示文字列）で被せる。キーを訳すと脅威ルール側の
 * `complianceRefs.ref` との対応が壊れる。
 */
export const ComplianceOverlayFileSchema = z
  .object({
    schemaVersion: z.literal(1),
    /** ロケール識別子（例 `en`）。ディレクトリ名との一致はローダーが検証する。 */
    locale: z.string().min(2),
    /** 対象の規格 ID。ファイル名ではなくこの値で原本と対応づける。 */
    standard: StandardIdSchema,
    /** 規格の正式名称の訳（任意）。 */
    title: z.string().min(1).optional(),
    /** 著作権・ライセンス区分の注記の訳（任意）。 */
    license: z.string().min(1).optional(),
    /** 引用条件・要約スタンスの注記の訳（任意）。 */
    disclaimer: z.string().min(1).optional(),
    /**
     * ref → 表示ラベル。日本語の節名を持つ規格向け。
     * 収録の無い ref は原本の `ref` をそのまま表示する。
     */
    refLabels: z.record(z.string(), z.string().min(1)).optional(),
    /**
     * ref → 項目本文の訳（コンプライアンス一覧モーダル用）。
     * `summary` は原本と同じく**独自要約**であること（規格本文の転載は不可）。
     * 原本が `text`（パブリックドメインの英語原文）を持つ項目は、訳を書かずとも
     * そちらが使われるため収録しなくてよい。
     */
    items: z
      .record(
        z.string(),
        z
          .object({
            title: z.string().min(1).optional(),
            summary: z.string().min(1).optional(),
          })
          .strict(),
      )
      .optional(),
  })
  .strict();

export type ComplianceOverlayFile = z.infer<typeof ComplianceOverlayFileSchema>;

/** 規格 ID → その規格の訳。複数ファイル分をマージしたもの。 */
export type ComplianceOverlayMap = Record<
  string,
  {
    title?: string;
    license?: string;
    disclaimer?: string;
    refLabels?: Record<string, string>;
    items?: Record<string, { title?: string; summary?: string }>;
  }
>;
