import { z } from 'zod';

/**
 * コンプライアンスマッピングの Zod スキーマ定義。
 *
 * 脅威ルール側 `complianceRefs: [{ standard, ref }]` に対する **逆引き辞書** を
 * 規格単位の YAML（`data/compliance/*.yaml`）として外部化する。
 *
 * 設計原則：
 * - 規格 ID（`standard.id`）は enum 化し、表記揺れを起動時に拒否する。
 * - 1 ファイル = 1 規格。`(standard.id, ref)` の組がライブラリ全体で一意。
 * - 規格本文の転載は行わず、独自要約（`summary`）と公式リンクで参照のみ示す。
 * - `relatedTo` で他規格との対応（クロスウォーク）を表現できる。
 */

export const StandardIdSchema = z.enum([
  'nist-ai-rmf',
  'jp-ai-business-guideline',
  'nist-csf-2.0',
  'nist-csf-2.0-examples',
]);

/**
 * 他規格 item への参照。`(standard, ref)` の組で対応関係を示す。
 * 参照先の実在検証はローダー側で行う（スキーマ単独では検証不可）。
 */
export const RelatedRefSchema = z.object({
  standard: StandardIdSchema,
  ref: z.string().min(1),
});

/**
 * 規格内の 1 項目（NIST AI RMF の subcategory、AI 事業者ガイドラインの個別指針 等）。
 */
export const ComplianceItemSchema = z.object({
  /** 当該規格内で一意なキー。脅威ルール側 `complianceRefs.ref` と一致させる。 */
  ref: z.string().min(1),
  /** 項目の正式タイトル（公式表記の短縮可）。 */
  title: z.string().min(1),
  /** 1〜2 行の独自要約。規格本文の転載は不可。 */
  summary: z.string().min(1),
  /** 当該項目への深リンク（任意）。 */
  url: z.string().url().optional(),
  /** 他規格との対応関係（任意）。 */
  relatedTo: z.array(RelatedRefSchema).nonempty().optional(),
});

/**
 * 規格メタ情報。
 */
export const ComplianceStandardSchema = z.object({
  /** 規格 ID。脅威ルール側 `complianceRefs.standard` と一致させる。 */
  id: StandardIdSchema,
  /** 規格の正式名称。 */
  title: z.string().min(1),
  /** バージョン表記（任意）。 */
  version: z.string().min(1).optional(),
  /** 公式情報の入口 URL。 */
  url: z.string().url(),
  /** 著作権・ライセンス区分の注記（任意）。 */
  license: z.string().min(1).optional(),
  /** 引用条件・要約スタンスに関する注記（任意）。 */
  disclaimer: z.string().min(1).optional(),
});

/**
 * 1 ファイル = 1 規格のスキーマ。
 */
export const ComplianceMapFileSchema = z.object({
  schemaVersion: z.literal(1),
  standard: ComplianceStandardSchema,
  items: z.array(ComplianceItemSchema).nonempty(),
});

export type StandardId = z.infer<typeof StandardIdSchema>;
export type RelatedRef = z.infer<typeof RelatedRefSchema>;
export type ComplianceItem = z.infer<typeof ComplianceItemSchema>;
export type ComplianceStandard = z.infer<typeof ComplianceStandardSchema>;
export type ComplianceMapFile = z.infer<typeof ComplianceMapFileSchema>;

/** 現行のスキーマバージョン。データファイル側と一致させる。 */
export const CURRENT_COMPLIANCE_SCHEMA_VERSION = 1 as const;
