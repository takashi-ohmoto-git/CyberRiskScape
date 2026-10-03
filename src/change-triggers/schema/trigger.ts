import { z } from 'zod';

/**
 * 実行トリガー（change-triggers）の Zod スキーマ定義。
 *
 * 「どの変更が脅威モデリングの再実行に値するか」の知識は YAML（`data/change-triggers/`）に置き、
 * 判定ロジックは固定の検出器（detector）の組み合わせに限定する（脅威ルールを
 * コードにハードコードしない方針を、変更トリガーにも適用）。
 *
 * 型・カテゴリ ID は `threat-library/schema/threatRule.ts` と同じ理由で独立に複製する
 * （スキーマ層を他機能のスキーマに結合させない）。実在性は `ComponentRegistry` でロード時に検証する。
 */

export const ComponentTypeIdSchema = z
  .string()
  .min(1)
  .regex(/^[A-Z][A-Za-z0-9_]*$/, 'component type id must start with uppercase letter');

export const CategoryIdSchema = z
  .string()
  .min(1)
  .regex(/^[A-Z][A-Za-z0-9_]*$/, 'category id must start with uppercase letter');

/** `src/core/model/types.ts` の `EdgeSemantic` の複製（schema 層の独立のため）。 */
export const EdgeSemanticSchema = z.enum([
  'data_flow',
  'tool_invocation',
  'delegation',
  'memory_read',
  'memory_write',
  'rag_retrieval',
  'directory_sync',
]);

/** `src/core/model/types.ts` の `TrustLevel` の複製。 */
export const TrustLevelSchema = z.enum(['Internal', 'Partner', 'Internet']);

/** ノード追加で成立する検出器。フィルタ未指定ならどのノード型でも成立する。 */
export const NodeAddedDetectorSchema = z.object({
  kind: z.literal('node-added'),
  nodeTypes: z.array(ComponentTypeIdSchema).nonempty().optional(),
  categories: z.array(CategoryIdSchema).nonempty().optional(),
});

/**
 * ノード変更で成立する検出器。base/head 双方に同一 id のノードがあり、`fields` のいずれかの値が
 * （深い比較で）異なるときに成立する。`fields` は 1 件以上必須。
 */
export const NodeChangedDetectorSchema = z.object({
  kind: z.literal('node-changed'),
  fields: z.array(z.string().min(1)).nonempty(),
  nodeTypes: z.array(ComponentTypeIdSchema).nonempty().optional(),
  categories: z.array(CategoryIdSchema).nonempty().optional(),
});

/**
 * エッジ追加で成立する検出器。
 * - `semantic`：エッジの意味論ラベル（未指定エッジは `data_flow` として判定）。
 * - `crossesTrust`：true 指定時、両端ノードの解決済み信頼レベルが異なるエッジのみ成立。
 * - `peerTrust`：いずれかの端のノードの解決済み信頼レベルが列挙のいずれかに一致すれば成立。
 */
export const EdgeAddedDetectorSchema = z.object({
  kind: z.literal('edge-added'),
  semantic: z.array(EdgeSemanticSchema).nonempty().optional(),
  crossesTrust: z.boolean().optional(),
  peerTrust: z.array(TrustLevelSchema).nonempty().optional(),
});

/** エッジ変更で成立する検出器。base/head 双方に同一 id のエッジがあり、`fields` のいずれかが異なる。 */
export const EdgeChangedDetectorSchema = z.object({
  kind: z.literal('edge-changed'),
  fields: z.array(z.string().min(1)).nonempty(),
});

/**
 * 既存ノードの解決済み信頼レベルが base と head で異なるときに成立する検出器。
 * ノードの移動と、境界の移動・リサイズ・削除のどちらで所属が変わっても拾う
 * （座標フィールドの変更そのものは、レイアウト調整で頻発するため対象にしない）。
 */
export const NodeTrustChangedDetectorSchema = z.object({
  kind: z.literal('node-trust-changed'),
});

/** 境界追加で成立する検出器。フィルタは持たない。 */
export const BoundaryAddedDetectorSchema = z.object({
  kind: z.literal('boundary-added'),
});

/** 境界変更で成立する検出器。base/head 双方に同一 id の境界があり、`fields` のいずれかが異なる。 */
export const BoundaryChangedDetectorSchema = z.object({
  kind: z.literal('boundary-changed'),
  fields: z.array(z.string().min(1)).nonempty(),
});

export const TriggerDetectorSchema = z.discriminatedUnion('kind', [
  NodeAddedDetectorSchema,
  NodeChangedDetectorSchema,
  EdgeAddedDetectorSchema,
  EdgeChangedDetectorSchema,
  NodeTrustChangedDetectorSchema,
  BoundaryAddedDetectorSchema,
  BoundaryChangedDetectorSchema,
]);

/**
 * 実行トリガー 1 件。`detect` が空配列のトリガー（例：T4「新しい技術またはランタイム」）は
 * モデル差分から自動判定できないことを意味し、常に「PR レビューで確認」として提示する。
 */
export const ChangeTriggerSchema = z.object({
  id: z.string().min(1).regex(/^T[0-9]+$/, 'id must look like "T1", "T2", ...'),
  title: z.string().min(1),
  checkpoint: z.string().min(1),
  detect: z.array(TriggerDetectorSchema),
});

/** YAML ファイル 1 本のスキーマ。`schemaVersion` で破壊的変更を管理する。 */
export const ChangeTriggerLibraryFileSchema = z.object({
  schemaVersion: z.literal(1),
  triggers: z.array(ChangeTriggerSchema),
});

export type ComponentTypeId = z.infer<typeof ComponentTypeIdSchema>;
export type TriggerDetector = z.infer<typeof TriggerDetectorSchema>;
export type ChangeTrigger = z.infer<typeof ChangeTriggerSchema>;
export type ChangeTriggerLibraryFile = z.infer<typeof ChangeTriggerLibraryFileSchema>;

/** 現行のスキーマバージョン。データファイル側と一致させる。 */
export const CURRENT_SCHEMA_VERSION = 1 as const;
