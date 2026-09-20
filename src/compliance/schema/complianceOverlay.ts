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
    /**
     * ref → 表示ラベル。日本語の節名を持つ規格向け。
     * 収録の無い ref は原本の `ref` をそのまま表示する。
     */
    refLabels: z.record(z.string(), z.string().min(1)).optional(),
  })
  .strict();

export type ComplianceOverlayFile = z.infer<typeof ComplianceOverlayFileSchema>;

/** 規格 ID → その規格の訳。複数ファイル分をマージしたもの。 */
export type ComplianceOverlayMap = Record<
  string,
  { title?: string; refLabels?: Record<string, string> }
>;
