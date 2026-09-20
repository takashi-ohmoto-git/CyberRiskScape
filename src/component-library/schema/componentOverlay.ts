import { z } from 'zod';

/**
 * コンポーネント型の翻訳オーバーレイのスキーマ。
 *
 * 原本（`data/component-library/*.yaml`）は日本語を「真実」として保持し、
 * 他言語は `data/component-library/i18n/<locale>/<source>.yaml` に
 * **コンポーネント型 ID を鍵とする差分**として置く。
 * `ComponentDefinition` 本体のスキーマは変更しない（脅威ライブラリと同方式）。
 *
 * 訳の対象は表示テキストのみ。`icon` / `shape` / `color` / `category` /
 * `canContain` は言語非依存なので対象外とする。
 */

/** コンポーネント 1 件分の訳文。指定されたフィールドだけを上書きする。 */
export const ComponentOverlaySchema = z
  .object({
    /** パレット・キャンバス・脅威本文の `{{nodeType}}` 展開先に出る表示名。 */
    label: z.string().min(1).optional(),
    /** パレット項目のツールチップ。 */
    description: z.string().min(1).optional(),
  })
  .strict();

/** オーバーレイファイル 1 本の形。 */
export const ComponentLibraryOverlayFileSchema = z
  .object({
    schemaVersion: z.literal(1),
    /** ロケール識別子（例 `en`）。ディレクトリ名との一致はローダーが検証する。 */
    locale: z.string().min(2),
    components: z.record(z.string(), ComponentOverlaySchema),
  })
  .strict();

export type ComponentOverlay = z.infer<typeof ComponentOverlaySchema>;
export type ComponentLibraryOverlayFile = z.infer<typeof ComponentLibraryOverlayFileSchema>;

/** コンポーネント型 ID → 訳文。複数ファイル分をマージしたもの。 */
export type ComponentOverlayMap = Record<string, ComponentOverlay>;
