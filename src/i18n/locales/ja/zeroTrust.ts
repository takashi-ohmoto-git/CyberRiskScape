/**
 * Zero Trust for AI Agents パネル の文言（日本語 = 真実）。
 * 集約は ../ja.ts。キー規約（`<領域>.<用途>`、プレースホルダ `{name}`）は
 * そちらの冒頭コメントを参照。
 */
export const jaZeroTrust = {
  'zeroTrust.header.subtitle':
    '自律型 AI エージェントをエンタープライズに展開するためのセキュリティフレームワーク',
  'zeroTrust.header.quote': '「何も信頼するな。すべてを検証せよ。侵害を前提とせよ。」',
  'zeroTrust.header.source': '出典: Anthropic『Zero Trust for AI Agents』eBook (2026)',

  'zeroTrust.principles.sectionTitle': '原則',
  'zeroTrust.principles.neverTrust.title': '決して信頼せず、常に検証する',
  'zeroTrust.principles.neverTrust.body':
    'すべてのリクエストは送信元を問わず認証・認可される — ネットワーク内部だからといって素通りはできない。',
  'zeroTrust.principles.assumeBreach.title': '侵害を前提とする',
  'zeroTrust.principles.assumeBreach.body':
    '侵入の防止だけでなく、被害の局限を前提に設計する。アイデンティティで分割し、影響範囲（ブラスト半径）を封じ込める。',
  'zeroTrust.principles.leastAgency.title': '最小権限 → 最小エージェンシー',
  'zeroTrust.principles.leastAgency.body':
    'エージェントが何にアクセスできるかだけでなく、各ツールが何を・どれだけの頻度で・どこで実行できるかまで制約する。',
  'zeroTrust.principles.designTest.title': '設計テスト：「面倒ではなく、不可能に」',
  'zeroTrust.principles.designTest.body':
    'エージェント型攻撃者は無限の忍耐と試行あたりほぼゼロのコストを持つため、摩擦を与えるだけの対策（レート制限、SMS による MFA）は破られる。能力を抑制する対策よりも、能力そのものを取り除く対策を優先せよ。',

  'zeroTrust.whyNow.sectionTitle': '今こそ必要な理由',
  'zeroTrust.whyNow.speedOfExploit.stat': '数か月 → 数時間',
  'zeroTrust.whyNow.speedOfExploit.body':
    'AI は脆弱性から悪用までの時間を、わずかなコストで圧縮する。',
  'zeroTrust.whyNow.backdoorDocs.stat': '250 文書',
  'zeroTrust.whyNow.backdoorDocs.body':
    'LLM（6 億〜130 億パラメータ）にバックドアを仕込み、安全性訓練後も残存させるのに十分な量。',
  'zeroTrust.whyNow.spotlighting.stat': '50% → <2%',
  'zeroTrust.whyNow.spotlighting.body':
    '信頼できないコンテンツのスポットライティングにより、間接インジェクションの成功率が低下。',
  'zeroTrust.whyNow.jailbreakBlockRate.stat': '95%',
  'zeroTrust.whyNow.jailbreakBlockRate.body':
    'constitutional classifiers が阻止したジェイルブレイク試行の割合。',

  'zeroTrust.matrix.sectionTitle': '能力マトリクス — 3 ティア × 7 ドメイン',
  'zeroTrust.matrix.domainHeader': 'ドメイン',
  'zeroTrust.matrix.tier.foundation.label': '基礎 (FOUNDATION)',
  'zeroTrust.matrix.tier.foundation.tagline': '最低限の実装水準 — 底上げされた基準線',
  'zeroTrust.matrix.tier.enterprise.label': 'エンタープライズ (ENTERPRISE)',
  'zeroTrust.matrix.tier.enterprise.tagline': '多くの組織が目指すべき成熟度',
  'zeroTrust.matrix.tier.advanced.label': '高度 (ADVANCED)',
  'zeroTrust.matrix.tier.advanced.tagline': '規制対象／高影響度の環境向け',

  'zeroTrust.matrix.domain.identityAuth.name': 'アイデンティティと認証',
  'zeroTrust.matrix.domain.identityAuth.foundation':
    'エージェントごとの暗号学的 ID、短命の IdP トークン — 静的 API キーは使わない',
  'zeroTrust.matrix.domain.identityAuth.enterprise':
    'ライフサイクル管理付き X.509 証明書、相互 TLS ＋証明書ピンニング',
  'zeroTrust.matrix.domain.identityAuth.advanced':
    'HSM/TPM によるハードウェア裏付けの ID とリモート構成証明',

  'zeroTrust.matrix.domain.accessControl.name': 'アクセス制御と権限',
  'zeroTrust.matrix.domain.accessControl.foundation':
    'RBAC、デフォルト拒否、アイデンティティに基づくワークロード分離',
  'zeroTrust.matrix.domain.accessControl.enterprise':
    'コンテキスト対応 ABAC、エージェントごとのサンドボックス実行',
  'zeroTrust.matrix.domain.accessControl.advanced':
    '継続的認可、JIT/JEA、コンフィデンシャルコンピューティング',

  'zeroTrust.matrix.domain.observability.name': '可観測性と監査',
  'zeroTrust.matrix.domain.observability.foundation':
    '網羅的なアクションログ、リクエスト ID で操作と契機を紐付け',
  'zeroTrust.matrix.domain.observability.enterprise':
    '改ざん不能な監査証跡、分散トレーシング（OpenTelemetry）',
  'zeroTrust.matrix.domain.observability.advanced':
    'リアルタイム SIEM ストリーミング、入力から出力までの完全な来歴チェーン',

  'zeroTrust.matrix.domain.behaviorMonitoring.name': '振る舞い監視',
  'zeroTrust.matrix.domain.behaviorMonitoring.foundation':
    '手動ベースライン、モデルが一次トリアージ案を作成するアラート',
  'zeroTrust.matrix.domain.behaviorMonitoring.enterprise':
    '学習ベースライン、自動封じ込めとアクセス失効',
  'zeroTrust.matrix.domain.behaviorMonitoring.advanced':
    '継続的なドリフト検知、自動化された SOAR プレイブック',

  'zeroTrust.matrix.domain.ioControl.name': '入出力制御',
  'zeroTrust.matrix.domain.ioControl.foundation':
    '入力検証と長さ制限、PII／資格情報の出力フィルタリング',
  'zeroTrust.matrix.domain.ioControl.enterprise':
    '攻撃パターンのコンテンツフィルタリング、意味的な出力分析',
  'zeroTrust.matrix.domain.ioControl.advanced':
    'constitutional classifiers ＋スポットライティング、高リスク操作への人間承認',

  'zeroTrust.matrix.domain.integrityRecovery.name': '完全性と復旧',
  'zeroTrust.matrix.domain.integrityRecovery.foundation':
    'バージョン管理された構成、文書化・テスト済みのロールバック',
  'zeroTrust.matrix.domain.integrityRecovery.enterprise':
    '署名付き構成、ヘルスチェック付きの自動ロールバック',
  'zeroTrust.matrix.domain.integrityRecovery.advanced':
    'イミュータブルインフラ、自己修復による自動是正',

  'zeroTrust.matrix.domain.aiGovernance.name': 'AI ガバナンス',
  'zeroTrust.matrix.domain.aiGovernance.foundation':
    '文書化された利用規定とインシデント対応方針、シャドー AI への対処',
  'zeroTrust.matrix.domain.aiGovernance.enterprise':
    '部門横断のステークホルダー監督を伴う正式なフレームワーク',
  'zeroTrust.matrix.domain.aiGovernance.advanced':
    'デプロイパイプラインで強制される自動コンプライアンスチェック',

  'zeroTrust.matrix.footnote.lead': '各ティアは前のティアの上に積み上がる。',
  'zeroTrust.matrix.footnote.emphasis': '「一つでも能力を飛ばせば、攻撃者はその隙を突く。」',

  'zeroTrust.threats.sectionTitle': '脅威（OWASP）',
  'zeroTrust.threats.promptInjection.title': 'プロンプトインジェクション',
  'zeroTrust.threats.promptInjection.body':
    '直接・間接 — LLM は情報としての文脈と、実行すべき指示とを確実に区別できない。',
  'zeroTrust.threats.toolAbuse.title': 'ツール・リソースの悪用',
  'zeroTrust.threats.toolAbuse.body':
    'MCP ツールポイズニング、ラグプル的なツールすり替え、ツール連鎖による情報持ち出し、リソース枯渇。',
  'zeroTrust.threats.identityAbuse.title': 'アイデンティティ・権限の濫用',
  'zeroTrust.threats.identityAbuse.body':
    'スコープ外の権限継承、混乱した代理（confused deputy）の中継、メモリを介した権限の保持。',
  'zeroTrust.threats.supplyChain.title': 'サプライチェーンリスク',
  'zeroTrust.threats.supplyChain.body':
    '汚染されたモデル重み、悪意ある MCP サーバー、依存関係混乱（dependency confusion）攻撃。',
  'zeroTrust.threats.memoryPoisoning.title': 'メモリ・コンテキストの汚染',
  'zeroTrust.threats.memoryPoisoning.body':
    'RAG／ベクトル DB のポイズニング、共有コンテキストへの攻撃、長期記憶の緩やかなドリフト。',
  'zeroTrust.threats.baselineRising.label': '基準線は上がり続ける：',
  'zeroTrust.threats.baselineRising.body':
    '今日の「高度」は明日の「エンタープライズ」に、そして「エンタープライズ」は「基礎」になると考えよ。',

  'zeroTrust.workflow.sectionTitle': '実装ワークフロー — 8 フェーズ',
  'zeroTrust.workflow.phase.identifyRequirements.title': '要件の特定',
  'zeroTrust.workflow.phase.identifyRequirements.body': '規制・運用・ステークホルダーの整合',
  'zeroTrust.workflow.phase.protectSupplyChain.title': 'サプライチェーンの保護',
  'zeroTrust.workflow.phase.protectSupplyChain.body':
    'AI-BOM、スコアカード、AI ベンダリング、署名',
  'zeroTrust.workflow.phase.defineAgentBoundaries.title': 'エージェント境界の定義',
  'zeroTrust.workflow.phase.defineAgentBoundaries.body':
    '一意の ID、最小エージェンシー、ブラスト半径',
  'zeroTrust.workflow.phase.defendPromptInjection.title': 'プロンプトインジェクション対策',
  'zeroTrust.workflow.phase.defendPromptInjection.body': '入力の分離、分類器、攻撃面の限定',
  'zeroTrust.workflow.phase.secureToolAccess.title': 'ツールアクセスの保護',
  'zeroTrust.workflow.phase.secureToolAccess.body': '許可リスト、パラメータ検証、サンドボックス',
  'zeroTrust.workflow.phase.protectCredentials.title': '資格情報の保護',
  'zeroTrust.workflow.phase.protectCredentials.body':
    '短命・ハードウェア紐付け・JIT・エージェントごと',
  'zeroTrust.workflow.phase.protectMemory.title': 'メモリの保護',
  'zeroTrust.workflow.phase.protectMemory.body': '分離、取得時の完全性チェック、TTL',
  'zeroTrust.workflow.phase.measureMetrics.title': '重要指標の測定',
  'zeroTrust.workflow.phase.measureMetrics.body': '滞留時間、カバレッジ、説明可能性',
} as const;
