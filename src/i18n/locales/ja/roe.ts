/**
 * 交戦規定（RoE）／スコープ宣言（Markdown）の文言（日本語 = 真実）。
 * 集約は ../ja.ts。
 */
export const jaRoe = {
  'roe.title': '交戦規定（RoE）／スコープ宣言: {system}',
  'roe.h.overview': '1. 概要と前提',
  'roe.h.inScope': '2. 許可された対象（診断してよい）',
  'roe.h.outOfScope': '3. スコープ外の対象（診断してはならない）',
  'roe.h.approval': '4. 承認方針',
  'roe.h.sourceSide': '5. 送信元へ写す項目（運用者チェックリスト）',
  'roe.h.limits': '6. 限界',

  'roe.overview.system': 'システム: {system}',
  'roe.overview.layer': 'レイヤー: {layer}',
  'roe.overview.generated': '作成日: {date}（{product} が脅威モデルから生成）',
  'roe.overview.purpose':
    'この文書は、エージェント型ペネトレーションツールを自社で運用するときの交戦規定（RoE）です。許可された対象・スコープ外の対象・承認方針を宣言し、ツールの遮断ルールと送信元のファイアウォール／プロキシへ写して突き合わせるために使います。',
  'roe.overview.note':
    'これは脅威モデルから自動で作った下書きです。宛先（ドメイン・IP アドレス）は図からは確定できないため、下の「アドレスの手がかり」は必ず人が確認して確定してください。対象の強制は、ツール内の設定（プロンプト・遮断ルール）に頼らず、送信元のファイアウォール／プロキシで行ってください。',

  'roe.inScope.none': '許可された対象はありません（図に自社資産が描かれていません）。',
  'roe.inScope.rule':
    '外部・第三者を除く、図内の自社資産です。各対象のアドレスを確認し、送信元側の allowlist に登録してください。',
  'roe.outOfScope.rule': '次の対象は診断してはなりません（取り違えると第三者への攻撃になります）。',
  'roe.outOfScope.everythingElse':
    '**この図に描かれていない対象は、すべてスコープ外です。** 明示的に許可した対象だけを診断してください。',

  'roe.zone.internal': '社内',
  'roe.zone.partner': 'パートナー',
  'roe.zone.internet': '公衆網',
  'roe.zone.undeclared': 'ゾーン未宣言',

  'roe.inScope.undeclared': '⚠ 信頼境界に入れていません。自社資産か（第三者でないか）確認してください。',

  'roe.reason.thirdParty': '第三者が所有するサービス',
  'roe.reason.partnerZone': 'パートナー境界の対象',
  'roe.reason.internetZone': '公衆網側・外部の対象',

  'roe.addressHint': 'アドレスの手がかり: {hint}（要確認）',
  'roe.addressNone': 'アドレスの手がかりなし（手動で確認）',

  'roe.approval.intro':
    'ツールのツール実行は、次の方針で統制してください。各項目はツールの遮断ルール（intercept）とポリシーに写します。',
  'roe.approval.backed': '（この図でも該当する脅威が発火しています）',
  'approval.defaultDeny':
    '既定の判定を拒否（deny by default）にし、許可するツールと操作を allowlist で明示する。',
  'approval.reviewAllTools':
    'MCP ツール・カスタムツールを含む、すべてのツール呼び出しを審査の対象にする。',
  'approval.enforceScopeAtSource':
    '働きかけてよい対象の強制を、プロンプトの指示ではなく、送信元のファイアウォール／プロキシで行う。',
  'approval.gateSelfExtension':
    'エージェントが自分でツール・MCP・スキル・承認ルールを登録・変更できないようにし、変更は人の承認と署名付き配布に限る。',
  'approval.humanApprovalHighImpact':
    '高影響の操作は、内容の要約と差分を示して人に承認させ、承認の件数と所要時間を監視して形骸化を検知する。',
  'approval.rulesNotDisableable':
    '遮断ルールの無効化・削除をエージェントや利用者の権限から外し、変更に監査ログを付ける。',

  'roe.sourceSide.intro':
    '上の宣言を、ツール内の設定ではなく実行環境の外側へ写します。写し終えたらチェックしてください。',
  'roe.sourceSide.item1':
    '「2. 許可された対象」のアドレスを確認し、送信元のファイアウォール／プロキシの allowlist に登録した。',
  'roe.sourceSide.item2':
    'allowlist 外への通信を実行前に遮断する設定にした（既定は拒否）。',
  'roe.sourceSide.item3':
    '承認方針（4 章）をツールの遮断ルールとポリシーに写し、エージェントから無効化できないようにした。',
  'roe.sourceSide.item4':
    'ツールの実行環境を本番から隔離し、本番の認証情報・管理面への経路を置いていない。',

  'roe.limits.item1':
    '宛先（ドメイン・IP アドレス）は図からは確定できません。アドレスの手がかりは人が確認してください。',
  'roe.limits.item2':
    'この図に描かれていない対象は評価されません。スコープの質は、図の洗い出しの質で決まります。',
  'roe.limits.item3':
    'この文書は宣言であって、実機の強制ではありません。実際に遮断されているかは実行環境で確かめてください。',
} as const;
