/**
 * 日本語ロケール = 全 UI 文言の「真実」。
 * デフォルトロケールであり、全キーをここで定義する。他ロケール（en 等）は
 * 本辞書のキー部分集合を上書きし、未定義キーは ja にフォールバックする。
 *
 * 規約：
 * - キーは `<画面/領域>.<用途>` のドット区切り（例 `topbar.focusMode`）。
 * - プレースホルダは `{name}` 形式（index.ts の interpolate が置換）。
 * - ブランド名は直書きせず、呼び出し側で BRANDING を params に渡す。
 *
 * 現状は基盤確立のためのパイロット文言のみ。既存の直書き文言は今後の差分で
 * 順次このファイルへ集約していく（一括移行はしない）。
 */
export const ja = {
  'app.loading': '読み込み中…',

  'topbar.focusMode': '集中モード',
  'topbar.showSidebar': 'サイドバーを表示',

  // {name}=ファイル名, {brand}=BRANDING.name
  'projectFile.loadFailed':
    '「{name}」は読み込めませんでした（{brand} のプロジェクト形式ではない可能性）。',

  // ── appliesToSummary（脅威カード「検出根拠」の発火条件文） ──
  'appliesToSummary.node.target.single': '{type} が対象です。',
  'appliesToSummary.node.target.anyOf': '{types} のいずれかが対象です。',
  'appliesToSummary.node.connection.default': '対象ノードに何らかの接続があるときに発火します。',
  'appliesToSummary.node.connection.intrinsic':
    '接続の有無に関係なく（内在的脅威として）発火します。',
  'appliesToSummary.node.connection.inbound':
    '対象ノードへの入力方向の接続があるときに発火します。',
  'appliesToSummary.node.connection.outbound':
    '対象ノードからの出力方向の接続があるときに発火します。',
  'appliesToSummary.node.connection.peerType': '接続先が {types} のいずれかであることが条件です。',
  'appliesToSummary.node.connection.peerAttackSurface':
    '接続先の攻撃面条件: {conditions}',
  'appliesToSummary.node.attackSurface': '対象ノード自身の攻撃面条件: {conditions}',
  'appliesToSummary.node.agentAttributes': 'エージェント属性条件: {conditions}',
  'appliesToSummary.edge.when': 'エッジ条件: {conditions}',
  'appliesToSummary.edge.allOf': 'エッジ条件（すべて満たす）: {groups}',
  'appliesToSummary.edge.anyOf': 'エッジ条件（いずれか満たす）: {groups}',

  // ── appliesToSummary のフィールド名ラベル（値は翻訳しない、フィールド名のみ） ──
  'appliesToSummary.field.hasGlobalIp': 'グローバルIP',
  'appliesToSummary.field.hasSourceIpRestriction': '送信元IP制限',
  'appliesToSummary.field.hasRemoteAccessRestriction': 'リモートアクセス制限',
  'appliesToSummary.field.hasUserAuthentication': 'ユーザー認証',
  'appliesToSummary.field.hasAccessLog': 'アクセスログ',
  'appliesToSummary.field.hasWafProtection': 'WAF保護',
  'appliesToSummary.field.hasDdosProtection': 'DDoS保護',
  'appliesToSummary.field.auth': '認証',
  'appliesToSummary.field.network': 'ネットワーク',
  'appliesToSummary.field.encryption': '暗号化',
  'appliesToSummary.field.sourceType': '送信元',
  'appliesToSummary.field.targetType': '宛先',
  'appliesToSummary.field.sourceTrust': '送信元信頼レベル',
  'appliesToSummary.field.targetTrust': '宛先信頼レベル',
  'appliesToSummary.field.sourceManagedState': '送信元管理状態',
  'appliesToSummary.field.targetManagedState': '宛先管理状態',
  'appliesToSummary.field.sourceUserTrust': '送信元ユーザー信頼区分',
  'appliesToSummary.field.targetUserTrust': '宛先ユーザー信頼区分',
  'appliesToSummary.field.semantic': 'エッジ意味論',
  'appliesToSummary.field.agency': '自律度',
  'appliesToSummary.field.blastRadius': '影響範囲',
  'appliesToSummary.field.identityTier': 'アイデンティティ強度',

  // ── ThreatCard「検出根拠」セクション ──
  'threatCard.detectionBasis.heading': '検出根拠',
  'threatCard.detectionBasis.ruleLabel': 'ルール',
  'threatCard.detectionBasis.customRuleFallback': 'カスタムルール',
  'threatCard.detectionBasis.corroboratedRules': '畳み込まれた全ルール',
  'threatCard.assumption.badge': '仮定検出',
  'threatCard.assumption.attackSurface':
    '攻撃面が未設定のため、開放寄りの既定値で評価しています。NodePanel で攻撃面を明示すると精度が上がります。',
  'threatCard.assumption.agentAttributes':
    'エージェント属性が未設定のため、最悪値（Autonomous / Admin / LabelOnly）で評価しています。属性を明示すると精度が上がります。',

  // ── TopControls ──
  'topbar.libraryInspector': '脅威ライブラリ・インスペクタを開く',

  // ── LibraryInspectorModal（読み取り専用の脅威ライブラリ閲覧） ──
  'libraryInspector.title': '脅威ライブラリ・インスペクタ',
  'libraryInspector.close': '閉じる',
  'libraryInspector.searchPlaceholder': 'ルール名・説明・IDで検索',
  'libraryInspector.filter.sourceAll': 'ソース: すべて',
  'libraryInspector.filter.frameworkAll': 'フレームワーク: すべて',
  'libraryInspector.filter.severityAll': '重大度: すべて',
  'libraryInspector.leftColumn.nodeTypesHeading': 'ノード型',
  'libraryInspector.leftColumn.edgeRules': '接続（エッジ）ルール',
  'libraryInspector.leftColumn.uncategorized': 'その他',
  'libraryInspector.rightPane.nodeHeading': '{type} に発火しうる脅威 {count} 件',
  'libraryInspector.rightPane.edgeHeading': '接続（エッジ）ルール {count} 件',
  'libraryInspector.rightPane.empty': '条件に一致するルールがありません。',
  'libraryInspector.section.intrinsic': '設置だけで発火（内在的脅威）',
  'libraryInspector.section.conditional': '接続条件つきで発火',
  'libraryInspector.card.detailsShow': '詳細を表示',
  'libraryInspector.card.detailsHide': '詳細を隠す',
  'libraryInspector.card.descriptionHeading': '説明',
  'libraryInspector.card.mitigationHeading': '緩和策',
  'libraryInspector.card.referencesHeading': '出典',
  'libraryInspector.card.sourceLabel': 'ソース',
  'libraryInspector.card.corroborationBadge': '{count} ソース',
  'libraryInspector.diagram.anyType': '任意',
  'libraryInspector.emptyLibrary': 'ライブラリにルールがありません。',

  // ── AttackTreeModal（攻撃経路分析：縦レイアウトの経路グラフ） ──
  'attackTree.title': '攻撃経路分析',
  'attackTree.targetMissing': '標的（objective）が見つかりません',
  'attackTree.routesSummary': '経路 {routes}（チャネル組合せ {combinations}）',
  'attackTree.minCost': '最小コスト {cost}',
  'attackTree.allBlocked': '全経路遮断',
  'attackTree.legend.weakestRoute': '最脆弱パス',
  'attackTree.legend.covered': '対策済（被覆）',
  'attackTree.legend.partial': '一部対策',
  'attackTree.legend.noEvidence': '既知の脅威なし',
  'attackTree.residualToggle': '残存経路のみ（対策済ホップを遮断）',
  'attackTree.noPath.title': '攻撃者と標的を結ぶ経路が見つかりません。',
  'attackTree.noPath.body':
    '攻撃経路分析はキャンバス上のエッジ（接続線）を辿って構築されます。攻撃者の侵入点となるコンポーネントへエッジを作成してください。',
  'attackTree.truncated': '経路が多いため一部を省略しました（深さ・経路数の上限あり）。',
  'attackTree.footnote':
    '難易度は DREAD Exploitability 優先（小さいほど容易）。未評価時は検出 severity の暫定値を使います。エッジは向きに依らず横移動の経路として扱います。1 つの対策で経路を完全遮断とは見なさず、被覆ホップはコスト加算で表します（「残存経路のみ」で遮断扱いに切替）。',
  'attackTree.node.difficulty': '難易度 {value}',
  'attackTree.node.unevaluated': '未評価',
  'attackTree.node.softDifficulty': '暫定 {value}',
  'attackTree.node.threatCount': '脅威 {count} 件',
  'attackTree.coverage.full': '対策済',
  'attackTree.coverage.partial': '一部対策',
  'attackTree.hop.channelCount': '×{count}',
  'attackTree.hop.noEvidence': '根拠なし',
  'attackTree.detail.nodeHeading': '検出根拠（{name}）',
  'attackTree.detail.hopHeading': '検出根拠（ホップ）',
  'attackTree.detail.hopEndpoints': '{a} ⇔ {b}',
  'attackTree.detail.travelDirection': '最脆弱経路上の通過方向: {from} → {to}',
  'attackTree.detail.noThreats': 'この要素で検出された脅威はありません',
  'attackTree.detail.chosenChannel': '採用チャネル',
  'attackTree.detail.close': '選択解除',
  'attackTree.detail.formula':
    '難易度 = 4 − max(DREAD Exploitability)。脅威あり・DREAD 未評価は severity 転用の暫定難易度（Critical/High→1、Medium→2、Low→3）。脅威なしは中立 2。一部対策 +1 / 対策済 +8（残存経路モードでは遮断）。',
  'attackTree.allUnevaluatedNote':
    'DREAD 未評価のため、コストは severity 転用の暫定難易度＋ホップ数基準です',
  'attackTree.chokePoint.heading': 'チョークポイント（対策の投資対効果が高い要素）',
  'attackTree.chokePoint.hits': '{total} 経路中 {hits} 本が通過',
  'attackTree.routeTable.heading': '経路テーブル',
  'attackTree.routeTable.colRoute': '経路',
  'attackTree.routeTable.colCost': 'コスト',
  'attackTree.routeTable.colWeakestHop': '最弱ホップ',
  'attackTree.routeTable.colStatus': '状態',
  'attackTree.routeTable.blocked': '遮断',
  'attackTree.routeTable.statusFeasible': '到達可能',
  'attackTree.routeTable.statusBlocked': '遮断済み',
} as const;

/** 全翻訳キーの型。en 等の他ロケールはこの部分集合を持つ。 */
export type TranslationKey = keyof typeof ja;
