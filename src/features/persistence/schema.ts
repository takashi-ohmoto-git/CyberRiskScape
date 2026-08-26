import { z } from 'zod';
import {
  AgencyLevelSchema,
  AuthTypeSchema,
  BlastRadiusSchema,
  ComponentTypeIdSchema,
  DataFlowSchema,
  EdgeSemanticSchema,
  EncryptionTypeSchema,
  FrameworkSchema,
  IdentityTierSchema,
  ManagedStateSchema,
  NetworkTypeSchema,
  SeveritySchema,
  TrustLevelSchema,
  UserTrustAttributeSchema,
} from '../../threat-library/schema/threatRule';

/**
 * IndexedDB に保存するプロジェクトレコードの Zod スキーマ。
 *
 * 信頼境界外として扱い、ロード時に必ず検証する。スキーマ違反のレコードは
 * 破棄して初期状態で起動する（破損データを書き戻すよりも安全）。
 */

export const PERSISTED_PROJECT_SCHEMA_VERSION = 1 as const;

/**
 * `activeFramework`（ビュー選択値）用スキーマ。ルールの `framework`（=`FrameworkSchema`、
 * STRIDE / AI / AgenticAI）に加え、ビュー専用に `'ALL'` を許容する。
 * 旧値 `'STRIDE+AI'`→`'STRIDE'` / `'MAESTRO'`→`'AgenticAI'` は deserialize 前の
 * マイグレーション（[[serialize]]）で変換されるため、ここでは新 enum のみを受理する。
 */
const FrameworkViewSchema = z.enum(['STRIDE', 'AI', 'AgenticAI', 'ALL']);

const BoundaryTypeIdSchema = z.enum(['RECT', 'RECT_DASHED', 'ROUNDED', 'ROUNDED_DASHED']);

/**
 * クラウド属性（SAAS/IAAS/PAAS 用）。値の意味は `src/core/model/types.ts` の
 * `CloudSanctionStatus` / `CloudOwnership` を一次ソースとする。
 * 脅威ルール側はまだ参照しないため、ここにローカル定義する（参照が必要になったら
 * threatRule.ts へ移す）。
 */
const CloudSanctionStatusSchema = z.enum(['Sanctioned', 'Unsanctioned']);
const CloudOwnershipSchema = z.enum(['Company', 'ThirdParty', 'Personal']);

/** 攻撃者区分（THREAT_ACTOR 用）。一次ソースは `src/core/model/types.ts` の `ThreatActorType`。 */
const ThreatActorTypeSchema = z.enum([
  'CyberCriminals',
  'NationStateActors',
  'FinanciallyMotivatedActors',
  'Hacktivists',
  'ScriptKiddies',
]);

const PersistedAttackSurfaceSchema = z.object({
  hasGlobalIp: z.boolean().optional(),
  hasSourceIpRestriction: z.boolean().optional(),
  hasRemoteAccessRestriction: z.boolean().optional(),
  hasUserAuthentication: z.boolean().optional(),
  hasAccessLog: z.boolean().optional(),
  hasWafProtection: z.boolean().optional(),
  hasDdosProtection: z.boolean().optional(),
});

/** エージェント特有属性（[[plan]] §2.22 1.6b）。全フィールド optional、空オブジェクトも許容。 */
const PersistedAgentAttributesSchema = z.object({
  agency: AgencyLevelSchema.optional(),
  blastRadius: BlastRadiusSchema.optional(),
  identityTier: IdentityTierSchema.optional(),
});

const PersistedNodeSchema = z.object({
  id: z.string().min(1),
  /** ElementalID 採番（§2.26）。後方互換のため optional（旧データはロード時にマイグレ）。 */
  seq: z.number().int().positive().optional(),
  type: ComponentTypeIdSchema,
  x: z.number(),
  y: z.number(),
  /** 親ノード ID（内包時のみ）。未設定はトップレベルノード。後方互換のため optional。 */
  parentId: z.string().min(1).optional(),
  label: z.string().optional(),
  description: z.string().optional(),
  managedState: ManagedStateSchema.optional(),
  userTrustAttribute: UserTrustAttributeSchema.optional(),
  /** クラウド / アプリ属性（SAAS/IAAS/PAAS/CHAT/MAIL/CRM/OTHER_APP 用、後方互換のため optional） */
  cloudSanction: CloudSanctionStatusSchema.optional(),
  cloudOwnership: CloudOwnershipSchema.optional(),
  /** 攻撃者区分（THREAT_ACTOR 用、後方互換のため optional） */
  threatActorType: ThreatActorTypeSchema.optional(),
  /** 攻撃者の objective（標的ノード id 参照。Attacker 型用、後方互換のため optional） */
  attackObjectiveId: z.string().min(1).optional(),
  /** 攻撃面属性（FRONT_END_SERVER / GATEWAY 用、後方互換のため optional） */
  attackSurface: PersistedAttackSurfaceSchema.optional(),
  /** エージェント特有属性（AGENT/TOOL/CONNECTOR/USER 用、後方互換のため optional） */
  agentAttributes: PersistedAgentAttributesSchema.optional(),
});

const PersistedEdgeSchema = z.object({
  id: z.string().min(1),
  /** ElementalID 採番（§2.26）。後方互換のため optional。 */
  seq: z.number().int().positive().optional(),
  source: z.string().min(1),
  target: z.string().min(1),
  auth: AuthTypeSchema,
  network: NetworkTypeSchema,
  encryption: EncryptionTypeSchema,
  /** 通信方向。旧データ互換のため optional（未指定は 'outbound' 相当）。 */
  dataFlow: DataFlowSchema.optional(),
  /** エッジに付与する自由記述ラベル。空文字は許容しない（未設定として扱う）。 */
  dataFlowName: z.string().min(1).max(80).optional(),
  /** エッジ意味論ラベル（§2.22 1.6d、後方互換のため optional。未指定は 'data_flow' 相当）。 */
  semantic: EdgeSemanticSchema.optional(),
});

const MacroTrustAttributeSchema = z.enum(['Public Area', 'Office Area', 'Security Zone']);
const MicroTrustAttributeSchema = z.enum(['Development', 'Staging', 'Production']);
const MicroSegmentationStatusSchema = z.enum(['適用済み', '未適用']);
const SensitiveDataSchema = z.enum(['無し', '個人情報', '機密情報']);

const PersistedBoundarySchema = z.object({
  id: z.string().min(1),
  /** ElementalID 採番（§2.26）。後方互換のため optional。 */
  seq: z.number().int().positive().optional(),
  type: BoundaryTypeIdSchema,
  x: z.number(),
  y: z.number(),
  width: z.number().positive(),
  height: z.number().positive(),
  trustLevel: TrustLevelSchema,
  // ── ROUNDED（マクロセグメンテーション）専用属性（後方互換のため optional） ──
  macroTrust: MacroTrustAttributeSchema.optional(),
  vlanName: z.string().max(64).optional(),
  vlanId: z.number().int().min(0).max(4094).optional(),
  networkAddress: z.string().max(64).optional(),
  // ── ROUNDED_DASHED（マイクロセグメンテーション）専用属性（後方互換のため optional） ──
  microTrust: MicroTrustAttributeSchema.optional(),
  microSegmentationStatus: MicroSegmentationStatusSchema.optional(),
  sensitiveData: SensitiveDataSchema.optional(),
});

const PersistedProjectMetaSchema = z.object({
  name: z.string().max(200),
  systemName: z.string().max(200),
  purpose: z.string().max(2000),
  businessImpact: z.string().max(2000),
  /**
   * セキュリティ目標。後から追加したフィールドのため `.default('')` で旧データ
   * （この欄を持たない projectMeta）を後方互換に受理する（schemaVersion 据え置き）。
   */
  securityObjectives: z.string().max(2000).default(''),
});

export const PersistedLayerDataSchema = z.object({
  nodes: z.array(PersistedNodeSchema),
  edges: z.array(PersistedEdgeSchema),
  boundaries: z.array(PersistedBoundarySchema),
});

const PersistedLayersSchema = z.object({
  L0: PersistedLayerDataSchema,
  L1: PersistedLayerDataSchema,
  L2: PersistedLayerDataSchema,
  L3: PersistedLayerDataSchema,
});

const LayerKeySchema = z.enum(['L0', 'L1', 'L2', 'L3']);

/** ElementalID 採番カウンタ（§2.26）。種別ごとの直近割当 seq（0 = 未採番）。 */
const SeqCountersSchema = z.object({
  node: z.number().int().nonnegative(),
  edge: z.number().int().nonnegative(),
  boundary: z.number().int().nonnegative(),
});

const PersistedIdCountersSchema = z.object({
  L0: SeqCountersSchema,
  L1: SeqCountersSchema,
  L2: SeqCountersSchema,
  L3: SeqCountersSchema,
});

/**
 * 手動脅威シナリオ（プロジェクト固有データ）。脅威ライブラリのルールとは別系統。
 */
const PersistedManualThreatSchema = z.object({
  id: z.string().min(1),
  framework: FrameworkSchema,
  /** 対象ノード ID（任意）。`targetType` と排他。両方未指定は全体スコープ。 */
  nodeId: z.string().min(1).optional(),
  /** 対象コンポーネント型（任意・カスタム node ルール）。`nodeId` と排他。 */
  targetType: ComponentTypeIdSchema.optional(),
  category: z.string().min(1).max(200),
  severity: SeveritySchema,
  description: z.string().min(1).max(4000),
  mitigation: z.string().max(4000).optional(),
});

const PersistedManualThreatsSchema = z.object({
  L0: z.array(PersistedManualThreatSchema),
  L1: z.array(PersistedManualThreatSchema),
  L2: z.array(PersistedManualThreatSchema),
  L3: z.array(PersistedManualThreatSchema),
});

const SuppressionStatusSchema = z.enum(['avoid', 'reduce', 'transfer', 'accepted', 'false-positive']);

const PersistedSuppressionSchema = z.object({
  status: SuppressionStatusSchema,
  note: z.string().max(2000).optional(),
  at: z.number().int().nonnegative(),
});

const ControlStatusValueSchema = z.enum(['implemented', 'required', 'not-applicable', 'rejected']);

const PersistedControlStatusSchema = z.object({
  status: ControlStatusValueSchema,
  note: z.string().max(2000).optional(),
  at: z.number().int().nonnegative(),
});

/** DREAD 各項目の 3 段階スコア（[[plan]] §2.34）。 */
const DreadValueSchema = z.union([z.literal(1), z.literal(2), z.literal(3)]);

const PersistedDreadScoreSchema = z.object({
  damage: DreadValueSchema,
  reproducibility: DreadValueSchema,
  exploitability: DreadValueSchema,
  affectedUsers: DreadValueSchema,
  discoverability: DreadValueSchema,
  at: z.number().int().nonnegative(),
});

export const PersistedProjectSchema = z.object({
  schemaVersion: z.literal(PERSISTED_PROJECT_SCHEMA_VERSION),
  /**
   * 旧形式（深度レイヤー導入前）のトップレベルダイアグラム。後方互換のため optional。
   * `layers` が未指定なら deserialize 時にこれを L1 へマイグレートする。
   */
  nodes: z.array(PersistedNodeSchema).optional(),
  edges: z.array(PersistedEdgeSchema).optional(),
  boundaries: z.array(PersistedBoundarySchema).optional(),
  /**
   * 深度レイヤー L0〜L3（独立した 4 枚のキャンバス）。
   * schemaVersion は据え置き（旧 nodes/edges/boundaries との optional 共存）。
   */
  layers: PersistedLayersSchema.optional(),
  activeLayer: LayerKeySchema.optional(),
  /**
   * ElementalID 採番カウンタ（§2.26）。省略時は deserialize 後に各レイヤーの
   * 最大 seq から復元する（旧データは要素順で seq を採番）。後方互換のため optional。
   */
  idCounters: PersistedIdCountersSchema.optional(),
  activeFramework: FrameworkViewSchema,
  /**
   * 無効化中のコンポーネントライブラリ ID。省略時は全有効化扱い。
   * schemaVersion は据え置き（optional 追加は後方互換）。
   */
  disabledLibraryIds: z.array(z.string().min(1)).optional(),
  /**
   * プロジェクト概要メタデータ。省略時は空メタとして起動。
   * schemaVersion は据え置き（optional 追加は後方互換）。
   */
  projectMeta: PersistedProjectMetaSchema.optional(),
  /**
   * 手動脅威シナリオ（レイヤー別）。省略時は手動脅威なしとして起動。
   * schemaVersion は据え置き（optional 追加は後方互換）。
   */
  manualThreats: PersistedManualThreatsSchema.optional(),
  /**
   * 検出脅威の抑制注記（threatId キー）。省略時は抑制なしとして起動。
   * schemaVersion は据え置き（optional 追加は後方互換）。
   */
  suppressions: z.record(z.string().min(1), PersistedSuppressionSchema).optional(),
  /**
   * 脅威への DREAD 評価（threatId キー。[[plan]] §2.34）。省略時は評価なしとして起動。
   * schemaVersion は据え置き（optional 追加は後方互換）。
   */
  dreadScores: z.record(z.string().min(1), PersistedDreadScoreSchema).optional(),
  /**
   * 検出/手動脅威への対策実装状況（threatId キー）。省略時は未設定として起動。
   * schemaVersion は据え置き（optional 追加は後方互換）。
   */
  controlStatuses: z.record(z.string().min(1), PersistedControlStatusSchema).optional(),
  updatedAt: z.number().int().nonnegative(),
});

export type PersistedProject = z.infer<typeof PersistedProjectSchema>;
