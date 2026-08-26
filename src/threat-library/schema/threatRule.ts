import { z } from 'zod';

/**
 * 脅威ライブラリの Zod スキーマ定義。
 *
 * 仕様の概要は docs/threat-schema.md を参照。スキーマ確定前に大量のルールを
 * 書かないこと（CLAUDE.md「やってはいけないこと」§5）。
 *
 * 設計原則：
 * - ルールは「コンポーネント型に紐づく静的ルール」と「エッジ属性に紐づく動的ルール」を
 *   `appliesTo` のタグ付き union で統一表現する。エンジン側は `kind` で分岐するだけ。
 * - ルール id はライブラリ全体でユニーク（ローダーが起動時に検査）。
 * - 出典明記が必要なため `references` / `complianceRefs` を用意。
 */

/**
 * コンポーネント型 ID は open string（schema レベルでは形式のみ検証）。
 * 「実在する型か」はロード時に `ComponentRegistry` で動的に検証する。
 * カスタムライブラリ（例：`MCP_SERVER`）も同じ枠で扱える。
 */
export const ComponentTypeIdSchema = z
  .string()
  .min(1)
  .regex(/^[A-Z][A-Za-z0-9_]*$/, 'component id must start with uppercase letter');

export const FrameworkSchema = z.enum(['STRIDE', 'AI', 'AgenticAI']);
export const SeveritySchema = z.enum(['Low', 'Medium', 'High', 'Critical']);
export const AuthTypeSchema = z.enum(['None', 'Password', 'MFA']);
export const NetworkTypeSchema = z.enum(['Internet', 'VPN', 'VPC']);
export const EncryptionTypeSchema = z.enum(['Plain', 'TLS', 'E2EE']);
export const DataFlowSchema = z.enum(['inbound', 'outbound', 'bidirectional']);
export const TrustLevelSchema = z.enum(['Internal', 'Partner', 'Internet']);
export const ManagedStateSchema = z.enum(['Managed', 'Unmanaged']);
export const UserTrustAttributeSchema = z.enum(['Guest', 'Employee', 'Contractor', 'Partner']);

/**
 * エージェント特有属性の Zod スキーマ（[[plan]] §2.22 1.6b）。
 * 値の意味と適用対象ノード型は `src/core/model/types.ts` を一次ソースとする。
 */
export const AgencyLevelSchema = z.enum(['None', 'Advisory', 'Bounded', 'Autonomous']);
export const BlastRadiusSchema = z.enum(['ReadOnly', 'Self', 'Tenant', 'CrossTenant', 'Admin']);
export const IdentityTierSchema = z.enum(['LabelOnly', 'Cryptographic', 'HardwareBound']);

/**
 * エッジ意味論（[[plan]] §2.22 1.6d）。
 * 値の意味は `src/core/model/types.ts` の `EdgeSemantic` を一次ソースとする。
 */
export const EdgeSemanticSchema = z.enum([
  'data_flow',
  'tool_invocation',
  'delegation',
  'memory_read',
  'memory_write',
  'rag_retrieval',
]);

/**
 * Attack Surface Attribute マッチ条件。各属性は optional boolean。
 * 指定された属性はノード側の値と完全一致が必要（true 指定 → ノード側 true）。
 * 未指定の属性は不問。
 *
 * ノード側の値が undefined の場合は insecure baseline として扱う：
 *   hasGlobalIp = true、他はすべて false。
 * これにより未設定の FRONT_END_SERVER でもベースラインリスクが検出される。
 *
 * 少なくとも 1 つの属性指定が必要（空オブジェクト拒否）。
 */
export const AttackSurfaceMatchSchema = z
  .object({
    hasGlobalIp: z.boolean().optional(),
    hasSourceIpRestriction: z.boolean().optional(),
    hasRemoteAccessRestriction: z.boolean().optional(),
    hasUserAuthentication: z.boolean().optional(),
    hasAccessLog: z.boolean().optional(),
    hasWafProtection: z.boolean().optional(),
    hasDdosProtection: z.boolean().optional(),
  })
  .refine(
    (a) =>
      a.hasGlobalIp !== undefined ||
      a.hasSourceIpRestriction !== undefined ||
      a.hasRemoteAccessRestriction !== undefined ||
      a.hasUserAuthentication !== undefined ||
      a.hasAccessLog !== undefined ||
      a.hasWafProtection !== undefined ||
      a.hasDdosProtection !== undefined,
    { message: 'attackSurface must include at least one condition' },
  );

/**
 * Node ルール用の単一リーフ（葉）。`anyOf` の中身として再利用する。
 */
const NodeLeafSchema = z.object({
  nodeType: ComponentTypeIdSchema,
});

/**
 * エージェント特有属性によるノード絞り込み条件（[[plan]] §2.22 1.6c）。
 *
 * - 各フィールドは配列（**OR**）。複数フィールド指定時は **AND**。
 * - ノード側で未指定の属性は脅威エンジン側で **「最悪を仮定」評価** する：
 *   - `agency` 未指定 → `Autonomous`（最大自律度）として扱う
 *   - `blastRadius` 未指定 → `Admin`（最大影響範囲）として扱う
 *   - `identityTier` 未指定 → `LabelOnly`（最弱アイデンティティ）として扱う
 *
 *   これにより既存ルール（属性条件なし）の挙動を保ちつつ、明示宣言したノードは
 *   ルール対象から外せる（設計者に明示宣言を促す圧力）。
 * - 少なくとも 1 フィールド指定が必要（空オブジェクト拒否）。
 *
 * セマンティクス詳細と適用対象は docs/threat-schema.md §3.1「エージェント属性条件」参照。
 */
export const AgentAttributesMatchSchema = z
  .object({
    agency: z.array(AgencyLevelSchema).nonempty().optional(),
    blastRadius: z.array(BlastRadiusSchema).nonempty().optional(),
    identityTier: z.array(IdentityTierSchema).nonempty().optional(),
  })
  .refine(
    (a) => a.agency !== undefined || a.blastRadius !== undefined || a.identityTier !== undefined,
    { message: 'agentAttributes match must include at least one of agency / blastRadius / identityTier' },
  );

export const ConnectionDirectionSchema = z.enum(['any', 'inbound', 'outbound']);

/**
 * Node ルールの接続要件。省略時のデフォルトは `{ required: true, direction: 'any' }`
 * （= 「対象ノードに 1 本以上の任意方向のエッジが繋がっている場合のみ発火」）。
 *
 * - `required: false` を指定すると内在的脅威として扱い、接続有無に関係なく発火する。
 *   この場合は `direction` / `peerType` を併記できない（意味的に矛盾）。
 * - `direction: 'inbound'` は対象ノードが `edge.target` のエッジが対象。`'outbound'` は逆。
 * - `peerType` は反対側（自分でない側）のノード型が列挙のいずれかと一致するエッジが
 *   少なくとも 1 本ある場合に成立。
 * - `peerAttackSurface` は接続先（ピア）ノードの攻撃面属性を条件にする。`peerType` と
 *   併用すれば「特定型のピアで、かつその攻撃面が条件を満たす」を表現できる
 *   （例：接続先 GATEWAY の `hasGlobalIp:true`）。direction/peerType/peerAttackSurface は
 *   同一エッジで AND 評価され、すべて満たすエッジが 1 本以上あるとき成立。
 *
 * 仕様詳細は docs/threat-schema.md「接続要件」節を参照。
 */
const ConnectionRequirementSchema = z
  .object({
    required: z.boolean().optional(),
    direction: ConnectionDirectionSchema.optional(),
    peerType: z.array(ComponentTypeIdSchema).nonempty().optional(),
    /** 接続先（ピア）ノードの攻撃面条件。攻撃面は FRONT_END_SERVER / GATEWAY で意味を持つ。 */
    peerAttackSurface: AttackSurfaceMatchSchema.optional(),
  })
  .superRefine((c, ctx) => {
    if (
      c.required === false &&
      (c.direction !== undefined ||
        c.peerType !== undefined ||
        c.peerAttackSurface !== undefined)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          'connection.required:false cannot be combined with direction / peerType / peerAttackSurface (intrinsic threat does not depend on edges)',
      });
    }
  });

/**
 * 静的ルール: 特定のノード型が存在するだけで成立する。
 *
 * 表現の選択肢（互いに排他、ちょうど 1 つを指定）：
 * - `nodeType`: 単一型を直接指定（後方互換）。
 * - `anyOf`: 複数リーフの OR。例 `anyOf: [{ nodeType: AGENT }, { nodeType: LLM }]`。
 *
 * `allOf` はノード単一型と矛盾する（1 ノードは 1 型）ため導入しない。
 * 組合せ条件はネスト 1 段までに制限する設計方針に従う（docs/plan.md §4）。
 *
 * `connection`（任意）で接続要件を追加できる。省略時はデフォルト = 接続必須（任意方向）。
 * 内在的脅威（接続不問）には `connection: { required: false }` を明示する。
 */
const NodeAppliesToSchema = z.object({
  kind: z.literal('node'),
  nodeType: ComponentTypeIdSchema.optional(),
  anyOf: z.array(NodeLeafSchema).min(2).optional(),
  connection: ConnectionRequirementSchema.optional(),
  /**
   * Attack Surface Attribute による絞り込み（任意）。
   * FRONT_END_SERVER / GATEWAY 向け。指定された属性の値が一致するノードのみ発火。
   */
  attackSurface: AttackSurfaceMatchSchema.optional(),
  /**
   * エージェント特有属性による絞り込み（[[plan]] §2.22 1.6c）。
   * 未指定属性は「最悪を仮定」評価。詳細は AgentAttributesMatchSchema。
   */
  agentAttributes: AgentAttributesMatchSchema.optional(),
});

/**
 * エッジ属性に対する条件式。`appliesTo.when`（適用判定）と `conditions[].when`
 * （severity/description の段階分け）の両方で共有する。
 *
 * 各フィールドは OR（配列内のいずれかに一致）。複数フィールド指定時は AND。
 * 少なくとも 1 つの軸を指定すること（空オブジェクトは無意味なので拒否）。
 */
const EdgeWhenSchema = z
  .object({
    auth: z.array(AuthTypeSchema).nonempty().optional(),
    network: z.array(NetworkTypeSchema).nonempty().optional(),
    encryption: z.array(EncryptionTypeSchema).nonempty().optional(),
    sourceType: z.array(ComponentTypeIdSchema).nonempty().optional(),
    targetType: z.array(ComponentTypeIdSchema).nonempty().optional(),
    /** source ノードが所属する境界の trustLevel（境界跨ぎ判定用） */
    sourceTrust: z.array(TrustLevelSchema).nonempty().optional(),
    /** target ノードが所属する境界の trustLevel（境界跨ぎ判定用） */
    targetTrust: z.array(TrustLevelSchema).nonempty().optional(),
    /** source ノードの端末管理状態（PC/SMARTPHONE/IOT のみ意味を持つ） */
    sourceManagedState: z.array(ManagedStateSchema).nonempty().optional(),
    /** target ノードの端末管理状態（PC/SMARTPHONE/IOT のみ意味を持つ） */
    targetManagedState: z.array(ManagedStateSchema).nonempty().optional(),
    /**
     * source ノードのユーザー信頼区分（USER のみ意味を持つ）。
     * managedState と同じく、ノード側で未宣言なら不成立（明示宣言時のみ発火）。
     */
    sourceUserTrust: z.array(UserTrustAttributeSchema).nonempty().optional(),
    /** target ノードのユーザー信頼区分（USER のみ意味を持つ）。未宣言は不成立。 */
    targetUserTrust: z.array(UserTrustAttributeSchema).nonempty().optional(),
    /**
     * エッジ意味論ラベルによる絞り込み（[[plan]] §2.22 1.6d）。
     * 未指定エッジは `data_flow`（既定）として評価される。
     */
    semantic: z.array(EdgeSemanticSchema).nonempty().optional(),
  })
  .refine(
    (w) =>
      w.auth !== undefined ||
      w.network !== undefined ||
      w.encryption !== undefined ||
      w.sourceType !== undefined ||
      w.targetType !== undefined ||
      w.sourceTrust !== undefined ||
      w.targetTrust !== undefined ||
      w.sourceManagedState !== undefined ||
      w.targetManagedState !== undefined ||
      w.sourceUserTrust !== undefined ||
      w.targetUserTrust !== undefined ||
      w.semantic !== undefined,
    { message: 'edge when must include at least one condition' },
  );

/**
 * conditions の 1 ケース。appliesTo.when を通過した edge に対し、追加の when で
 * マッチ判定し、最初に一致したケースの severity / description でルールの
 * デフォルトを上書きする（first-match-wins）。
 *
 * severity と description の少なくとも一方を必ず上書きする（両方未指定は無意味）。
 */
const EdgeConditionCaseSchema = z
  .object({
    when: EdgeWhenSchema,
    severity: SeveritySchema.optional(),
    description: z.string().min(1).optional(),
  })
  .refine((c) => c.severity !== undefined || c.description !== undefined, {
    message: 'condition must override at least one of severity / description',
  });

/**
 * 動的ルール: エッジ属性の組合せで成立する。
 *
 * 表現の選択肢（`when` / `allOf` / `anyOf` から **ちょうど 1 つ**を指定）：
 * - `when`: 単一リーフ。5 軸 AND（後方互換）。
 * - `allOf`: 複数リーフの AND。組織化・可読性目的で利用（5 軸 AND の集合を分割表現）。
 * - `anyOf`: 複数リーフの OR。`when` では表現できない「ブロック単位の OR」を追加する。
 *
 * 組合せ条件はネスト 1 段まで（`allOf` の中に `anyOf` を入れる等は不可）。
 * 設計方針は docs/plan.md §4「組合せ条件スキーマの設計」参照。
 */
const EdgeAppliesToSchema = z.object({
  kind: z.literal('edge'),
  when: EdgeWhenSchema.optional(),
  allOf: z.array(EdgeWhenSchema).min(2).optional(),
  anyOf: z.array(EdgeWhenSchema).min(2).optional(),
  /**
   * 同一ルール内で severity / description を分岐させる場合に使用。
   * 例: ツール接続ルールは常に発火させたいが、MFA 時は Low / 説明文も穏当にしたい等。
   */
  conditions: z.array(EdgeConditionCaseSchema).nonempty().optional(),
});

export const AppliesToSchema = z
  .discriminatedUnion('kind', [NodeAppliesToSchema, EdgeAppliesToSchema])
  .superRefine((a, ctx) => {
    // 組合せ条件の排他制御は discriminatedUnion の制約上、ここで一元的に行う。
    // node: nodeType | anyOf のちょうど 1 つ
    // edge: when | allOf | anyOf のちょうど 1 つ
    if (a.kind === 'node') {
      const count = (a.nodeType !== undefined ? 1 : 0) + (a.anyOf !== undefined ? 1 : 0);
      if (count !== 1) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'node appliesTo must specify exactly one of: nodeType, anyOf',
        });
      }
    } else {
      const count =
        (a.when !== undefined ? 1 : 0) +
        (a.allOf !== undefined ? 1 : 0) +
        (a.anyOf !== undefined ? 1 : 0);
      if (count !== 1) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'edge appliesTo must specify exactly one of: when, allOf, anyOf',
        });
      }
    }
  });

/**
 * 緩和策の 3 段階成熟度（Anthropic "Zero Trust for AI Agents" 2026 に準拠）。
 *
 * - Foundation：最小実用セキュリティ。AI 加速攻撃の現状を踏まえ「単なる friction による
 *   対策」は Foundation 要件を満たさない（docs/threat-schema.md §7.5.2 参照）。
 * - Enterprise：標準的エンタープライズ実装。多くの組織が目指すべき水準。
 * - Advanced：高リスク・規制対応・最先端。3〜5 年後に Enterprise 標準へ降りてくる見込み。
 *
 * YAML 上は `mitigation` 文字列内の `[Foundation] ... [Enterprise] ... [Advanced] ...`
 * インライン markup として記述し、ローダーで自動分解される（書き手は markup のみ意識）。
 * 直接 `mitigationTiers` を YAML に書くことも可能だが、現運用は markup 経由を推奨。
 *
 * 少なくとも 1 段階の指定が必要（空オブジェクト拒否）。
 */
export const MitigationTiersSchema = z
  .object({
    foundation: z.string().min(1).optional(),
    enterprise: z.string().min(1).optional(),
    advanced: z.string().min(1).optional(),
  })
  .refine((m) => m.foundation !== undefined || m.enterprise !== undefined || m.advanced !== undefined, {
    message: 'mitigationTiers must include at least one of foundation / enterprise / advanced',
  });

export const ComplianceRefSchema = z.object({
  /** NIST AI RMF / ISO/IEC 42001 / AI 事業者ガイドライン 等 */
  standard: z.string().min(1),
  /** 当該標準内の節・ID（例: "GOVERN 1.1", "8.2"） */
  ref: z.string().min(1),
});

export const ReferenceSchema = z.object({
  title: z.string().min(1),
  url: z.string().url().optional(),
});

/**
 * 個別の脅威ルール。`id` は kebab-case 英数字でライブラリ全体で一意。
 */
export const ThreatRuleSchema = z.object({
  id: z
    .string()
    .min(1)
    .regex(/^[a-z0-9][a-z0-9-]*$/, 'id must be kebab-case (lowercase alphanumeric + hyphen)'),
  /**
   * 等価グルーピングキー（任意）。複数ソース（MITRE ATLAS / OWASP 等）が同じ実世界脅威を
   * 別 id で収録している場合、同じ `canonicalId` を振ることで提示層（`buildThreatViews`）が
   * 同一 subject 上の重複を 1 枚に畳み込み、出典を束ねて表示する。
   * `id` と異なり一意である必要はない（むしろ複数ルールで共有するためのキー）。
   * 未指定のルールは従来どおり独立した脅威として扱われる（後方互換）。
   */
  canonicalId: z
    .string()
    .min(1)
    .regex(/^[a-z0-9][a-z0-9-]*$/, 'canonicalId must be kebab-case (lowercase alphanumeric + hyphen)')
    .optional(),
  framework: FrameworkSchema,
  category: z.string().min(1),
  /**
   * 脅威名（表示用タイトル）。任意。未指定時は UI が `category` をタイトルにフォールバックする。
   * `category` は分類ラベル（STRIDE の Tampering 等／フレームワーク固有の分類）に純化し、
   * 具体的な脅威名はこちらに置く。
   */
  name: z.string().min(1).optional(),
  severity: SeveritySchema,
  description: z.string().min(1),
  mitigation: z.string().min(1).optional(),
  /**
   * 緩和策の 3 段階成熟度（Foundation / Enterprise / Advanced）。
   * 通常は `mitigation` 文字列の markup からローダーが自動 populate するが、
   * YAML から直接指定することもできる（その場合 markup より優先）。
   */
  mitigationTiers: MitigationTiersSchema.optional(),
  appliesTo: AppliesToSchema,
  complianceRefs: z.array(ComplianceRefSchema).nonempty().optional(),
  references: z.array(ReferenceSchema).nonempty().optional(),
});

/** YAML ファイル 1 本のスキーマ。`schemaVersion` で破壊的変更を管理する。 */
export const ThreatLibraryFileSchema = z.object({
  schemaVersion: z.literal(1),
  rules: z.array(ThreatRuleSchema),
});

export type ComponentTypeId = z.infer<typeof ComponentTypeIdSchema>;
export type Framework = z.infer<typeof FrameworkSchema>;
export type Severity = z.infer<typeof SeveritySchema>;
export type AppliesTo = z.infer<typeof AppliesToSchema>;
export type ConnectionDirection = z.infer<typeof ConnectionDirectionSchema>;
export type ConnectionRequirement = z.infer<typeof ConnectionRequirementSchema>;
export type AttackSurfaceMatch = z.infer<typeof AttackSurfaceMatchSchema>;
export type AgentAttributesMatch = z.infer<typeof AgentAttributesMatchSchema>;
export type MitigationTiers = z.infer<typeof MitigationTiersSchema>;
export type ComplianceRef = z.infer<typeof ComplianceRefSchema>;
export type Reference = z.infer<typeof ReferenceSchema>;
export type ThreatRule = z.infer<typeof ThreatRuleSchema>;
export type ThreatLibraryFile = z.infer<typeof ThreatLibraryFileSchema>;

/** 現行のスキーマバージョン。データファイル側と一致させる。 */
export const CURRENT_SCHEMA_VERSION = 1 as const;
