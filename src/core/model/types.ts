/**
 * コンポーネント型 ID。コンポーネントライブラリ（YAML）で宣言された任意の文字列。
 * 妥当性は実行時に `ComponentRegistry` で動的に検証される（[[plan]] §2.16）。
 *
 * 慣例：先頭英大文字、英数字とアンダースコア（例：`LLM`, `MCP_SERVER`）。
 */
export type ComponentTypeId = string;

/**
 * ノードの視覚形状。コンポーネントライブラリ側 `ShapeKindSchema` の `infer` 結果と一致。
 * 描画プリミティブと 1:1 で対応するため Phase 1 では型の単一定義をここに置く。
 */
export type ShapeKind = 'rectangle' | 'circle' | 'data-store' | 'rounded' | 'connector';

export type BoundaryTypeId = 'RECT' | 'RECT_DASHED' | 'ROUNDED' | 'ROUNDED_DASHED';

export type Framework = 'STRIDE' | 'AI' | 'AgenticAI';

/**
 * CANVAS のフレームワーク切替タブの選択値。データ層の `Framework`（ルール・脅威・
 * YAML が持つ値）は不変のまま、ビュー選択専用に `'ALL'` を加えた擬似値。
 * `'ALL'` は両 framework を統合表示するビューで、ルールや脅威には決して載らない。
 */
export type FrameworkView = Framework | 'ALL';

export type Severity = 'Low' | 'Medium' | 'High' | 'Critical';

export type TrustLevel = 'Internal' | 'Partner' | 'Internet';

/** マクロセグメンテーション境界の TRUST ATTRIBUTE。 */
export type MacroTrustAttribute = 'Public Area' | 'Office Area' | 'Security Zone';

/** マイクロセグメンテーション境界の TRUST ATTRIBUTE。 */
export type MicroTrustAttribute = 'Development' | 'Staging' | 'Production';

/** マイクロセグメンテーション適用状態。 */
export type MicroSegmentationStatus = '適用済み' | '未適用';

/** 機密データ区分。 */
export type SensitiveData = '無し' | '個人情報' | '機密情報';

/**
 * 端末ノード（PC / SMARTPHONE / IOT）の管理状態。
 * - Managed: 組織管理下のデバイス（MDM 登録・パッチ統制・EDR 等）
 * - Unmanaged: BYOD / 持込・未管理デバイス。攻撃面が大きい
 */
export type ManagedState = 'Managed' | 'Unmanaged';

/**
 * USER ノードの信頼区分。
 * - Guest: 来訪者・未認証ユーザー（実質 Untrusted。managedState は 'Unmanaged' を派生）
 * - Employee: 正社員
 * - Contractor: 契約社員
 * - Partner: 取引先
 *
 * Employee/Contractor/Partner は組織統制下にある前提のため managedState は 'Managed' を派生する。
 */
export type UserTrustAttribute = 'Guest' | 'Employee' | 'Contractor' | 'Partner';

/**
 * クラウドサービス / 業務アプリの認可状況。
 * - Sanctioned: 組織が認可・統制しているサービス
 * - Unsanctioned: 未認可で利用されているサービス（シャドー IT 傾向）
 *
 * 適用対象ノード型は [[SANCTION_ATTRIBUTE_APPLICABLE]] を参照。
 */
export type CloudSanctionStatus = 'Sanctioned' | 'Unsanctioned';

/**
 * クラウドサービス / 業務アプリの所有状況。
 * - Company: 自社が契約・所有
 * - ThirdParty: 他社（取引先・委託先等）が所有
 * - Personal: 個人アカウントでの利用
 *
 * 適用対象ノード型は [[SANCTION_ATTRIBUTE_APPLICABLE]] を参照。
 */
export type CloudOwnership = 'Company' | 'ThirdParty' | 'Personal';

/**
 * THREAT_ACTOR ノードの攻撃者区分（Type 属性）。
 * - CyberCriminals: サイバー犯罪者
 * - NationStateActors: 国家支援型アクター
 * - FinanciallyMotivatedActors: 金銭目的のアクター
 * - Hacktivists: ハクティビスト（思想・主張目的）
 * - ScriptKiddies: スクリプトキディ（低スキル・既製ツール利用）
 */
export type ThreatActorType =
  | 'CyberCriminals'
  | 'NationStateActors'
  | 'FinanciallyMotivatedActors'
  | 'Hacktivists'
  | 'ScriptKiddies';

/**
 * Attack Surface Attribute。Web サーバー等の外部公開ポイントに付与する
 * 攻撃面の構成情報。すべて optional boolean で、未設定は「insecure baseline」
 * （hasGlobalIp=true, それ以外=false）として扱う。
 *
 * 適用対象：FRONT_END_SERVER / GATEWAY（UI 表示はこの 2 種のみ）。
 * 他のノード型では値があっても脅威エンジンは参照しない。
 */
export interface AttackSurfaceAttribute {
  /** Global IP の割り当て。true = 有り（インターネットから直接到達可能） */
  hasGlobalIp?: boolean;
  /** 送信元 IP アクセス制限（IP allowlist / ACL）。true = 有り */
  hasSourceIpRestriction?: boolean;
  /** リモートアクセス制限（VPN / 踏み台 / Zero Trust 等で管理面を守る）。true = 有り */
  hasRemoteAccessRestriction?: boolean;
  /** ユーザー認証。true = 有り */
  hasUserAuthentication?: boolean;
  /** アクセスログ取得。true = 有り */
  hasAccessLog?: boolean;
  /** WAF / WAP による保護。true = 有り */
  hasWafProtection?: boolean;
  /** DoS / DDoS 保護。true = 有り */
  hasDdosProtection?: boolean;
}

export type AttackSurfaceKey = keyof AttackSurfaceAttribute;

/**
 * エージェント自律度（OWASP "Least Agency" / Anthropic Excessive Agency 由来）。
 *
 * - None: エージェント性なし（人手のみ、ツール扱い）
 * - Advisory: 提案・要約のみ生成し、アクションは実行しない
 * - Bounded: 限定的な許可リスト内でアクション実行、機微操作は人手承認 (HITL)
 * - Autonomous: 複数ツール跨ぎで自律実行、人手介入は最小限
 *
 * 適用対象：AGENT / TOOL。他のノード型では未使用。
 * 未設定は脅威エンジン側で `Autonomous`（最悪）として評価される（1.6c で実装予定）。
 */
export type AgencyLevel = 'None' | 'Advisory' | 'Bounded' | 'Autonomous';

/**
 * 侵害時の影響範囲（Anthropic eBook の Blast Radius 概念）。
 *
 * - ReadOnly: 読取専用アクセスのみ
 * - Self: 自ノード内に閉じる
 * - Tenant: 同一テナント・同一プロジェクト内に波及
 * - CrossTenant: テナント / 顧客境界を越えて波及
 * - Admin: クラウド管理者 / インフラ全体に波及
 *
 * 全ノード型で有意味。未設定は脅威エンジン側で `Admin`（最悪）として評価される。
 */
export type BlastRadius = 'ReadOnly' | 'Self' | 'Tenant' | 'CrossTenant' | 'Admin';

/**
 * アイデンティティの根付き方（Anthropic 3 段階成熟度に対応）。
 *
 * - LabelOnly: ラベル / 文字列 ID のみ（攻撃者がなりすまし可能、Foundation 未満）
 * - Cryptographic: X.509 等の暗号学的アイデンティティ（Enterprise 水準）
 * - HardwareBound: HSM / TPM 由来の attestation 付き（Advanced 水準）
 *
 * 適用対象：AGENT / TOOL / CONNECTOR / USER。
 * 未設定は脅威エンジン側で `LabelOnly`（最弱）として評価される。
 */
export type IdentityTier = 'LabelOnly' | 'Cryptographic' | 'HardwareBound';

/**
 * エージェント特有のノード属性（[[plan]] §2.22 1.6b で追加）。
 *
 * 全フィールド optional。設計者が NodePanel から明示宣言する情報レイヤであり、
 * 自動推論はしない（説明可能性を保つ差別化要件）。
 * 1.6b 時点ではエンジン評価はせず、表示と永続化のみ。1.6c でルール条件に組み込む。
 */
export interface AgentAttributes {
  agency?: AgencyLevel;
  blastRadius?: BlastRadius;
  identityTier?: IdentityTier;
}

/** 属性ごとの適用対象ノード型（NodePanel と loader/engine で共有）。 */
export const AGENCY_APPLICABLE: ReadonlySet<ComponentTypeId> = new Set(['AGENT', 'TOOL']);
export const IDENTITY_TIER_APPLICABLE: ReadonlySet<ComponentTypeId> = new Set([
  'AGENT',
  'TOOL',
  'CONNECTOR',
  'USER',
]);
// blastRadius は全ノード型で有意味（applicable 制限なし）。

/**
 * 認可状況・所有状況属性（cloudSanction / cloudOwnership）の適用対象ノード型。
 * Cloud カテゴリ（SAAS/IAAS/PAAS）と App カテゴリ（CHAT/MAIL/CRM/OTHER_APP）。
 * SHADOW / SHADOW_APP は定義上「未把握」なので対象外。
 */
export const SANCTION_ATTRIBUTE_APPLICABLE: ReadonlySet<ComponentTypeId> = new Set([
  'SAAS',
  'IAAS',
  'PAAS',
  'CHAT',
  'MAIL',
  'CRM',
  'OTHER_APP',
]);

/** Type 属性（threatActorType）の適用対象ノード型。 */
export const THREAT_ACTOR_TYPE_APPLICABLE: ReadonlySet<ComponentTypeId> = new Set([
  'THREAT_ACTOR',
]);

/**
 * objective 属性（attackObjectiveId = 標的コンポーネント参照）の適用対象ノード型。
 * Attacker カテゴリの全型。
 */
export const ATTACK_OBJECTIVE_APPLICABLE: ReadonlySet<ComponentTypeId> = new Set([
  'THREAT_ACTOR',
  'INSIDER_THREAT',
  'AGENTIC_ATTACKER',
]);

/**
 * 深度レイヤーキー。1 プロジェクトは独立した 4 枚のキャンバスを保持できる。
 * - L0：ビジネスロジック中心（ビジネスサイドが記載）
 * - L1：詳細設計（セキュリティ担当者が記載、通常はここまで）
 * - L2：機密性が高い場合の追加詳細
 * - L3：更に厳密な内容
 *
 * レイヤー間に相関関係はなく、各々が独立したダイアグラム。
 */
export type LayerKey = 'L0' | 'L1' | 'L2' | 'L3';

export const LAYER_KEYS: readonly LayerKey[] = ['L0', 'L1', 'L2', 'L3'] as const;

/**
 * ElementalID の対象となる Canvas 要素の種別（[[plan]] §2.26）。
 * - node：コンポーネント（表示 ID `C{n}`）
 * - edge：データフロー（表示 ID `DF{n}`）
 * - boundary：トラスト境界 / ゾーン（表示 ID `Z{n}`）
 */
export type ElementKind = 'node' | 'edge' | 'boundary';

/**
 * Canvas 上の単一要素への参照（[[plan]] §2.26）。脅威を「どの要素由来か」で
 * 集約するための正準キー。`id` は要素の内部 `id`（不変キー）を指す。
 * 表示用の ElementalID（`C3` 等）は `seq` から `formatElementalId` で整形する。
 */
export interface ElementRef {
  kind: ElementKind;
  id: string;
}

/**
 * ElementalID 採番カウンタ（[[plan]] §2.26）。種別ごとの「直近に割り当てた seq」。
 * 次に割り当てる seq は `value + 1`。削除しても巻き戻さない（番号を再利用しない）。
 */
export type SeqCounters = Record<ElementKind, number>;

/** レイヤー別の採番カウンタ。各レイヤーが独立した連番空間を持つ。 */
export type LayerSeqCounters = Record<LayerKey, SeqCounters>;

/** 1 レイヤー分のダイアグラムデータ。 */
export interface LayerData {
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  boundaries: DiagramBoundary[];
}

export const EMPTY_LAYER: LayerData = { nodes: [], edges: [], boundaries: [] };

/**
 * プロジェクト概要メタデータ。`docs/strategy.md` の想定利用シナリオで
 * 「対象システムの目的・ビジネスインパクトを明示してから脅威モデリングに入る」
 * という前提を反映する。すべて空文字許容（未記入の状態を素直に表現）。
 */
export interface ProjectMeta {
  /** プロジェクト名（脅威モデリング案件名）。 */
  name: string;
  /** 対象システム名称。 */
  systemName: string;
  /** システム目的（何を解決するシステムか）。 */
  purpose: string;
  /** ビジネスインパクト（停止・侵害時の事業影響）。 */
  businessImpact: string;
  /**
   * セキュリティ目標（このシステムで守るべき機密性・完全性・可用性等の到達目標）。
   * 複数行記述。脅威の優先度付けの基準として記載し、Report 冒頭に転記する。
   */
  securityObjectives: string;
}

export const EMPTY_PROJECT_META: ProjectMeta = {
  name: '',
  systemName: '',
  purpose: '',
  businessImpact: '',
  securityObjectives: '',
};

export type AuthType = 'None' | 'Password' | 'MFA';

export type NetworkType = 'Internet' | 'VPN' | 'VPC';

export type EncryptionType = 'Plain' | 'TLS' | 'E2EE';

/**
 * エッジ上のデータ通信の向き。
 * - outbound: source → target（順方向）
 * - inbound:  target → source（逆方向）
 * - bidirectional: 双方向
 */
export type DataFlow = 'inbound' | 'outbound' | 'bidirectional';

/**
 * エッジの意味論ラベル（[[plan]] §2.22 1.6d）。
 *
 * - data_flow: 既定。通常のデータ転送（HTTP/SQL/メッセージング等）
 * - tool_invocation: エージェントからツール（外部 API / 関数）への呼出
 * - delegation: エージェント間のタスク委譲（multi-agent 協調）
 * - memory_read: エージェントメモリストアからの読取
 * - memory_write: エージェントメモリストアへの書込
 * - rag_retrieval: RAG 用ベクター DB からの取得
 *
 * 設計者が EdgePanel から明示宣言する情報。未指定エッジは脅威エンジンで
 * `data_flow` として評価される（既定値）。自動推論はしない。
 */
export type EdgeSemantic =
  | 'data_flow'
  | 'tool_invocation'
  | 'delegation'
  | 'memory_read'
  | 'memory_write'
  | 'rag_retrieval';

export interface DiagramNode {
  id: string;
  /**
   * レイヤー×種別で単調増加する採番（[[plan]] §2.26）。表示 ID は `C{seq}`。
   * 採番は store 側で行う（Step 2）。旧データは optional（ロード時にマイグレ）。
   */
  seq?: number;
  type: ComponentTypeId;
  x: number;
  y: number;
  /**
   * 親ノード ID。設定されている場合、このノードは親に内包される子として扱われ、
   * キャンバス本体には直接描画されず、親のバッジ等として表現される。
   * x/y は親内包時は未使用（描画位置は親に依存）。
   */
  parentId?: string;
  /** ユーザー定義の表示名（例: "与信判定サービス"）。未指定なら型名を使用。 */
  label?: string;
  /** 自由記述の説明（責務、業務ルール等）。 */
  description?: string;
  /**
   * 端末ノード（PC / SMARTPHONE / IOT）の管理状態。
   * USER ノードでは userTrustAttribute から派生して設定される。
   * それ以外の型では未使用。未指定は「不明」扱い。
   */
  managedState?: ManagedState;
  /**
   * USER ノードの信頼区分（Guest / Employee / Contractor / Partner）。
   * USER 以外の型では未使用。
   */
  userTrustAttribute?: UserTrustAttribute;
  /**
   * 攻撃面属性（FRONT_END_SERVER / GATEWAY 用）。
   * 未設定は insecure baseline（hasGlobalIp=true, 他=false）として脅威エンジンが扱う。
   */
  attackSurface?: AttackSurfaceAttribute;
  /**
   * クラウドサービス / 業務アプリの認可状況（[[SANCTION_ATTRIBUTE_APPLICABLE]] の型用）。
   * それ以外の型では未使用。未指定は「不明」扱い。
   */
  cloudSanction?: CloudSanctionStatus;
  /**
   * クラウドサービス / 業務アプリの所有状況（[[SANCTION_ATTRIBUTE_APPLICABLE]] の型用）。
   * それ以外の型では未使用。未指定は「不明」扱い。
   */
  cloudOwnership?: CloudOwnership;
  /**
   * エージェント特有属性（[[plan]] §2.22 1.6b で追加）。
   * 設計者が明示宣言する情報レイヤ。未指定属性は脅威エンジンで「最悪を仮定」評価される（1.6c 実装予定）。
   * 適用対象は [[AGENCY_APPLICABLE]] / [[IDENTITY_TIER_APPLICABLE]] を参照。
   */
  agentAttributes?: AgentAttributes;
  /**
   * 攻撃者区分（[[THREAT_ACTOR_TYPE_APPLICABLE]] の型用）。
   * それ以外の型では未使用。未指定は「不明」扱い。
   */
  threatActorType?: ThreatActorType;
  /**
   * 攻撃者の objective（標的とする同一レイヤー上のノード id）。
   * 適用対象は [[ATTACK_OBJECTIVE_APPLICABLE]]。標的ノード削除時は store 側で解除される。
   */
  attackObjectiveId?: string;
}

export interface DiagramEdge {
  id: string;
  /**
   * レイヤー×種別で単調増加する採番（[[plan]] §2.26）。表示 ID は `DF{seq}`。
   * 採番は store 側で行う（Step 2）。旧データは optional（ロード時にマイグレ）。
   */
  seq?: number;
  source: string;
  target: string;
  auth: AuthType;
  network: NetworkType;
  encryption: EncryptionType;
  /**
   * データ通信の向き。未指定（旧データ）は 'outbound' 相当として扱う。
   */
  dataFlow?: DataFlow;
  /**
   * エッジに付与する自由記述ラベル（例: "Bearer Token", "GraphQL Query"）。
   * キャンバス上で線の中点付近に表示される。
   */
  dataFlowName?: string;
  /**
   * エッジの意味論ラベル（[[plan]] §2.22 1.6d）。
   * 未指定エッジは脅威エンジンで `data_flow`（既定）として評価される。
   */
  semantic?: EdgeSemantic;
}

export interface DiagramBoundary {
  id: string;
  /**
   * レイヤー×種別で単調増加する採番（[[plan]] §2.26）。表示 ID は `Z{seq}`。
   * 採番は store 側で行う（Step 2）。旧データは optional（ロード時にマイグレ）。
   */
  seq?: number;
  type: BoundaryTypeId;
  x: number;
  y: number;
  width: number;
  height: number;
  /**
   * 脅威エンジン内部で使用する信頼レベル。
   * RECT/RECT_DASHED は UI から直接設定、ROUNDED/ROUNDED_DASHED は
   * macroTrust/microTrust からマッピングで派生する。
   */
  trustLevel: TrustLevel;

  // ── ROUNDED（マクロセグメンテーション）専用属性 ──
  /** マクロセグメンテーションの TRUST ATTRIBUTE。 */
  macroTrust?: MacroTrustAttribute;
  /** VLAN 名（自由記述）。 */
  vlanName?: string;
  /** VLAN ID（0-4094）。 */
  vlanId?: number;
  /** ネットワークアドレス（CIDR 形式、例: 10.0.0.0/24）。 */
  networkAddress?: string;

  // ── ROUNDED_DASHED（マイクロセグメンテーション）専用属性 ──
  /** マイクロセグメンテーションの TRUST ATTRIBUTE。 */
  microTrust?: MicroTrustAttribute;
  /** マイクロセグメンテーション適用状態。 */
  microSegmentationStatus?: MicroSegmentationStatus;
  /** 取り扱い機密データ区分。 */
  sensitiveData?: SensitiveData;
}

import type { ComplianceRef, MitigationTiers, Reference } from '../../threat-library/schema/threatRule';

export interface DetectedThreat {
  id: string;
  /** この脅威を生成したルールの id（`id` の接頭辞）。出荷/カスタムの判別に使う。 */
  ruleId?: string;
  /**
   * 等価グルーピングキー（ルール由来、任意）。同一 subject 上で同じ `canonicalId` を持つ
   * 検出脅威は `buildThreatViews` が 1 枚に畳み込む（クロスソース重複の解消）。
   */
  canonicalId?: string;
  /**
   * 脅威の対象要素への参照（[[plan]] §2.26）。Analytics の要素単位集約はこれを正準キーにする。
   * engine 出力は Step 4 で populate するため現状は optional。`nodeId` は既存 UI 互換のため不変。
   */
  subject?: ElementRef;
  nodeId: string;
  framework: Framework;
  category: string;
  /** 脅威名（表示用タイトル）。ルール由来。未指定時は UI が `category` をタイトルにフォールバックする。 */
  name?: string;
  severity: Severity;
  description: string;
  /** ルール定義由来の緩和策（任意）。脅威カードに表示する。 */
  mitigation?: string;
  /**
   * 緩和策の 3 段階成熟度（Foundation / Enterprise / Advanced）。
   * ローダーが `mitigation` の markup から自動 populate する（[[plan]] §2.22 1.6a）。
   */
  mitigationTiers?: MitigationTiers;
  /** ルール定義由来のコンプライアンス参照（任意）。 */
  complianceRefs?: ComplianceRef[];
  /** ルール定義由来の出典・参考文献（任意）。 */
  references?: Reference[];
  isDynamic?: boolean;
  /**
   * 検出時にノード属性の「最悪仮定」（未設定フィールドの insecure baseline）を使った場合のフラグ。
   * スキーマ／YAML 非永続。UI で「属性未設定による仮定検出」を明示し、信頼性の読み違いを防ぐ。
   */
  assumptionFlags?: DetectionAssumptionFlag[];
}

/**
 * 自動検出が insecure baseline に依存した軸。
 * - attackSurface: 攻撃面フィールド未設定を baseline（開放寄り）で評価
 * - agentAttributes: agency/blastRadius/identityTier 未設定を最悪値で評価
 */
export type DetectionAssumptionFlag = 'attackSurface' | 'agentAttributes';

/**
 * ユーザーが手動で追加する脅威シナリオ。自動検出（`DetectedThreat`）とは別系統の
 * **プロジェクト固有データ**で、脅威ライブラリ（YAML ルール）には属さない。
 * activeLayer + `framework` スコープで保持し、IndexedDB に永続化する。
 *
 * 将来の Kill Chain（複数ステップの攻撃シナリオ、[[plan]] Phase2）対応で
 * `steps?` を非破壊追加できるよう、`DetectedThreat` とは独立した型に保つ。
 */
export interface ManualThreat {
  id: string;
  /**
   * 脅威の対象要素への参照（[[plan]] §2.26）。`nodeId` / `targetType` のスコープ表現とは別軸の
   * 正準キーで、Analytics の要素単位集約に使う。配線は Step 4 以降のため現状は optional。
   */
  subject?: ElementRef;
  /** 作成時のフレームワーク。表示はこの framework がアクティブなときのみ。 */
  framework: Framework;
  /**
   * 対象ノード ID（特定インスタンスを対象にする場合）。
   * `targetType` と排他。どちらも未指定はプロジェクト全体スコープ。
   */
  nodeId?: string;
  /**
   * 対象コンポーネント型（プロジェクトローカルなカスタム node ルールとして、
   * アクティブレイヤー上の同型ノード全てに適用する場合）。`nodeId` と排他。
   */
  targetType?: ComponentTypeId;
  /** 脅威カテゴリ／タイトル。 */
  category: string;
  severity: Severity;
  description: string;
  /** 緩和策（任意）。 */
  mitigation?: string;
}

/**
 * 検出脅威のリスク対応方針（Risk Treatment）。
 * 回避 / 低減 / 移転 は「実リスクに対応中」として表示・カウントを維持し、
 * 受容 / 誤検知 のみ「抑制」（淡色化・件数/バッジ除外）扱いになる。
 * 内部の型名・フィールド名は後方互換のため `SuppressionStatus` のまま据え置く。
 */
export type SuppressionStatus = 'avoid' | 'reduce' | 'transfer' | 'accepted' | 'false-positive';

/**
 * 自動検出された脅威への対応方針注記。脅威を削除せず状態だけ付与し、
 * 監査証跡として残す。`DetectedThreat.id` をキーにグローバル Record で保持する。
 */
export interface SuppressionState {
  status: SuppressionStatus;
  /** 対応方針の理由・補足（任意）。 */
  note?: string;
  /** 設定時刻（epoch ms）。 */
  at: number;
}

/** 「抑制」（淡色化・件数/バッジ除外）扱いになる対応方針。受容・誤検知のみ。 */
export const SUPPRESSING_STATUSES: readonly SuppressionStatus[] = ['accepted', 'false-positive'];

/** その脅威が抑制対象か（受容/誤検知のみ true。回避/低減/移転は false）。 */
export function isSuppressed(t: { suppression?: SuppressionState }): boolean {
  return !!t.suppression && SUPPRESSING_STATUSES.includes(t.suppression.status);
}

/** 対策実装状況（リスク対応方針=suppression とは別レイヤー）。 */
export type ControlStatusValue = 'implemented' | 'required' | 'not-applicable' | 'rejected';

/** 検出/手動脅威への対策実装状況。`ThreatView.id` をキーにグローバル Record で保持する。 */
export interface ControlStatusState {
  status: ControlStatusValue;
  /** 補足。implemented/not-applicable/rejected では必須、required では任意。 */
  note?: string;
  at: number;
}

/** DREAD 各評価項目の 3 段階スコア（1=低 / 2=中 / 3=高）。 */
export type DreadValue = 1 | 2 | 3;

/**
 * 脅威への DREAD 評価（ユーザー入力。[[plan]] §2.34）。
 * suppressions と同様に `ThreatView.id` をキーにグローバル Record で保持する。
 * 5 項目の合計（5–15）を `dreadRank` で Severity へマッピングし、評価済み脅威は
 * Analytics でルール由来 severity より優先して表示する。
 */
export interface DreadScore {
  /** D: 損害の大きさ（Damage） */
  damage: DreadValue;
  /** R: 再現性（Reproducibility） */
  reproducibility: DreadValue;
  /** E: 攻撃の容易さ（Exploitability） */
  exploitability: DreadValue;
  /** A: 影響ユーザー範囲（Affected Users） */
  affectedUsers: DreadValue;
  /** D: 発見の容易さ（Discoverability） */
  discoverability: DreadValue;
  /** 評価時刻（epoch ms）。 */
  at: number;
}

/**
 * 一覧・カード表示用に検出脅威と手動脅威を合流させたビュー型。
 * engine 出力 `DetectedThreat` は不変に保ち、UI 層でのみこの型を使う
 * （`buildThreatViews` が生成）。
 */
export interface ThreatView extends DetectedThreat {
  origin: 'detected' | 'manual';
  /** 検出脅威がユーザーのカスタムルール由来か（"Custom" バッジ表示用）。 */
  isCustom?: boolean;
  /** origin==='manual' のとき、元 `ManualThreat` の id（編集／削除用）。 */
  manualId?: string;
  /** origin==='manual' で型ターゲティングのとき、対象コンポーネント型（表示ラベル用）。 */
  manualTargetType?: ComponentTypeId;
  /** 抑制注記（検出脅威にのみ付く）。 */
  suppression?: SuppressionState;
  /** DREAD 評価（評価済みの脅威にのみ付く。[[plan]] §2.34）。 */
  dread?: DreadScore;
  /** 対策実装状況（リスク対応方針=suppression とは別レイヤー）。 */
  controlStatus?: ControlStatusState;
  /**
   * クロスソース畳み込みの裏付け情報（2 件以上が同じ `canonicalId` + subject で
   * マージされたときのみ付与）。複数フレームワークが同一脅威を指摘している事実を
   * カードに表示し、コンサル資産としての権威性を高める。
   */
  corroboration?: {
    /** マージ元の検出脅威 id 一覧（代表を含む）。 */
    ruleIds: string[];
    /** マージ元の framework（重複排除済み）。 */
    frameworks: Framework[];
  };
}

/**
 * 単一ノード／境界のドラッグ transient 状態。ズーム対応のため、開始時の client 座標と
 * 対象の元ワールド座標を保持し、move で `orig + (client - startClient) / scale` を計算する
 * （offset 方式では scale≠1 のとき移動量がワールドとずれるため差分方式に統一）。
 */
export interface DragState {
  id: string;
  startClientX: number;
  startClientY: number;
  origX: number;
  origY: number;
}

/**
 * キャンバスのビューポート変換。`tx`/`ty` は画面 px のパン量、`scale` は倍率。
 * ワールド点 (wx,wy) は `main` ローカル座標 (tx + wx*scale, ty + wy*scale) に描画される。
 * transient（永続化しない・Undo/Redo 対象外）。
 */
export interface Viewport {
  scale: number;
  tx: number;
  ty: number;
}

/** パン（Space+ドラッグ）の transient 状態。開始時の client 座標と tx/ty を保持。 */
export interface PanState {
  startClientX: number;
  startClientY: number;
  startTx: number;
  startTy: number;
}

/**
 * 範囲選択（マーキー）の transient 状態。座標はすべて `main`（キャンバス）要素相対。
 * `offsetLeft` / `offsetTop` は mousemove の client 座標を相対座標へ変換するための
 * `main` 要素の client 基準点。
 */
export interface MarqueeState {
  offsetLeft: number;
  offsetTop: number;
  startX: number;
  startY: number;
  curX: number;
  curY: number;
}

/**
 * 複数要素（ノード + 境界）のグループ移動の transient 状態。
 * `nodeOrigins` / `boundaryOrigins` はドラッグ開始時点の各座標で、`start` からの
 * 差分を全要素へ一括適用する。
 */
export interface GroupDragState {
  startClientX: number;
  startClientY: number;
  nodeOrigins: { id: string; x: number; y: number }[];
  boundaryOrigins: { id: string; x: number; y: number }[];
}

/**
 * 矩形の 8 方向リサイズハンドル識別子。
 * PowerPoint 等と同じ命名（北西/北/北東/東/南東/南/南西/西）。
 */
export type ResizeHandle = 'nw' | 'n' | 'ne' | 'e' | 'se' | 's' | 'sw' | 'w';

export interface ResizeState {
  id: string;
  handle: ResizeHandle;
  startX: number;
  startY: number;
  startBox: { x: number; y: number; width: number; height: number };
}
