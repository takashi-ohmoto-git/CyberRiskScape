import { z } from 'zod';

/**
 * コンポーネントライブラリの Zod スキーマ定義。
 *
 * 設計原則（[[plan]] §2.16）：
 * - コンポーネント型は **open string ID**（kebab/snake/SCREAMING_SNAKE いずれも可）。
 *   コード側は string として扱い、レジストリで動的に検証する。
 * - カテゴリはライブラリ YAML 内で宣言され、`components[].category` から参照される。
 *   ローダーが未宣言カテゴリ参照を拒否（fail-fast）。
 * - アイコンは builtin name（lucide-react）またはインライン SVG の hybrid。
 */

/**
 * コンポーネント型 ID。SCREAMING_SNAKE_CASE 推奨だが、第三者ライブラリの命名規則を
 * 過度に縛らないよう先頭英大文字始まりの英数字＋アンダースコアに緩める。
 * 例：`LLM`, `MCP_SERVER`, `VECTOR_DB_v2`
 */
export const ComponentTypeIdSchema = z
  .string()
  .min(1)
  .regex(/^[A-Z][A-Za-z0-9_]*$/, 'component id must start with uppercase letter (e.g. MCP_SERVER)');

/**
 * カテゴリ ID。コンポーネントと同様 string ID。
 */
export const CategoryIdSchema = z
  .string()
  .min(1)
  .regex(/^[A-Z][A-Za-z0-9_]*$/, 'category id must start with uppercase letter (e.g. AI)');

/**
 * 視覚形状。canvas の描画プリミティブと 1:1。新形状は描画側の対応とセットで追加する。
 */
export const ShapeKindSchema = z.enum([
  'rectangle',
  'circle',
  'data-store',
  'rounded',
  'connector',
]);

/**
 * アイコン仕様。
 * - `builtin`: lucide-react から名前で参照（iconRegistry でマップ）
 * - `svg`: インライン SVG。Step 3 でサニタイズ層を入れるまでビルトインライブラリでは使わない
 */
export const IconSpecSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('builtin'), name: z.string().min(1) }),
  z.object({ kind: z.literal('svg'), svg: z.string().min(1) }),
]);

/**
 * 単一コンポーネントの定義。
 */
export const ComponentDefinitionSchema = z.object({
  id: ComponentTypeIdSchema,
  label: z.string().min(1),
  /** 上で宣言したカテゴリ ID を参照。ローダーで未宣言は拒否される。 */
  category: CategoryIdSchema,
  icon: IconSpecSchema,
  shape: ShapeKindSchema,
  /** Tailwind class（例: "bg-purple-600"）。将来 hex 等への切替を見据え string で受ける。 */
  color: z.string().min(1),
  /** UI のツールチップ用補足説明（任意）。 */
  description: z.string().optional(),
  /**
   * このコンポーネントが内包できる子コンポーネントの型 ID 集合（ホワイトリスト）。
   * 例：DATA_STORE は `[PERSONAL_INFO, CONFIDENTIAL_INFO, ...]` を内包可。
   * 未指定または空配列なら内包不可（リーフ）。未宣言 ID 参照はローダーで拒否する。
   */
  canContain: z.array(ComponentTypeIdSchema).optional(),
});

/**
 * カテゴリ定義。同一 ID を複数ライブラリが宣言してよい（idempotent reuse）。
 * label / order が一致しない再宣言はローダーが warn ログを残し、先勝ちとする。
 */
export const CategoryDefinitionSchema = z.object({
  id: CategoryIdSchema,
  label: z.string().min(1),
  /** UI の並び順（昇順）。同値時は id の辞書順。 */
  order: z.number().int().nonnegative(),
});

/**
 * ライブラリ全体のメタデータ。
 */
export const LibraryMetaSchema = z.object({
  /** ライブラリ全体で一意の ID（kebab-case）。 */
  id: z
    .string()
    .min(1)
    .regex(/^[a-z0-9][a-z0-9-]*$/, 'library id must be kebab-case (lowercase alphanumeric + hyphen)'),
  title: z.string().min(1),
  version: z.string().min(1),
  license: z.string().min(1),
  /** ビルトイン（同梱）ライブラリの印。UI で無効化不可表示にする。 */
  builtin: z.boolean().optional(),
  description: z.string().optional(),
  maintainer: z.string().optional(),
  url: z.string().url().optional(),
});

/**
 * 1 YAML ファイルのスキーマ。`schemaVersion` で破壊的変更を管理する。
 */
export const ComponentLibraryFileSchema = z.object({
  schemaVersion: z.literal(1),
  library: LibraryMetaSchema,
  categories: z.array(CategoryDefinitionSchema).nonempty(),
  components: z.array(ComponentDefinitionSchema).nonempty(),
});

export type ComponentTypeId = z.infer<typeof ComponentTypeIdSchema>;
export type CategoryId = z.infer<typeof CategoryIdSchema>;
export type ShapeKind = z.infer<typeof ShapeKindSchema>;
export type IconSpec = z.infer<typeof IconSpecSchema>;
export type ComponentDefinition = z.infer<typeof ComponentDefinitionSchema>;
export type CategoryDefinition = z.infer<typeof CategoryDefinitionSchema>;
export type LibraryMeta = z.infer<typeof LibraryMetaSchema>;
export type ComponentLibraryFile = z.infer<typeof ComponentLibraryFileSchema>;

export const CURRENT_SCHEMA_VERSION = 1 as const;
