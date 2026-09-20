/**
 * サイドバー・トップバー・プロジェクト系モーダル の文言（日本語 = 真実）。
 * 集約は ../ja.ts。キー規約（`<領域>.<用途>`、プレースホルダ `{name}`）は
 * そちらの冒頭コメントを参照。
 */
export const jaProject = {
  // ── 共通（複数コンポーネントで再利用） ──
  'project.common.close': '閉じる',
  'project.common.cancel': 'キャンセル',
  'project.common.save': '保存',
  'project.common.saving': '保存中…',

  // ── LeftSidebar ──
  'project.sidebar.untitled': 'プロジェクト未設定',
  'project.sidebar.depthLayer': '深度レイヤー（{layer}）',
  'project.sidebar.layerDesc.L0': 'ビジネスロジック中心（ビジネスサイドが記載）',
  'project.sidebar.layerDesc.L1': '詳細設計（セキュリティ担当者、通常はここまで）',
  'project.sidebar.layerDesc.L2': '機密性が高い場合の追加詳細',
  'project.sidebar.layerDesc.L3': '更に厳密な内容',
  'project.sidebar.reportSummary': '表示中の脅威一覧（{layer} / {framework}・{count} 件）を出力',
  'project.sidebar.exportCsv': 'CSV ダウンロード',
  'project.sidebar.exportJson': 'JSON ダウンロード',
  'project.sidebar.exportDcrh': 'DCRH THREAT_MODEL.md（Anthropic 公式互換）',
  'project.sidebar.newProject': '新規作成',
  'project.sidebar.fileMenu': 'ファイル（保存 / 開く）',
  'project.sidebar.saveStateSaved': '保存しました',
  'project.sidebar.saveStateError': '保存に失敗',
  'project.sidebar.usageHint1': '🔹 パーツを選択して "Create Link" で接続',
  'project.sidebar.usageHint2': '🔹 コネクタを中継点として利用可能',

  // ── TopControls（topbar.* は既存キー。ここは未抽出分のみ） ──
  'project.topControls.undo': '元に戻す (Ctrl+Z)',
  'project.topControls.redo': 'やり直し (Ctrl+Shift+Z)',
  'project.topControls.openAnalytics': 'Analytics（アクティブレイヤーの分析）を開く',
  'project.topControls.openComplianceMap': 'コンプライアンスマップを開く',
  'project.topControls.zoomOut': '縮小',
  'project.topControls.resetZoom': '100% に戻す',
  'project.topControls.zoomIn': '拡大',
  'project.topControls.fitToContent': '全体表示（Fit）',

  // ── ProjectFileModal ──
  'project.fileModal.pickFailed': 'フォルダ選択に失敗: {message}',
  'project.fileModal.permissionDenied': 'フォルダへのアクセスが許可されませんでした。',
  'project.fileModal.saved': '「{name}」に保存しました。',
  'project.fileModal.saveFailed': '保存に失敗: {message}',
  'project.fileModal.readFailed': '読み込みに失敗: {message}',
  'project.fileModal.title': 'ファイル（保存 / 開く）',
  'project.fileModal.unsupported':
    'このブラウザはフォルダ保存（File System Access API）に対応していません。Chrome または Edge をご利用ください。なお作業内容はブラウザ内（IndexedDB）に自動保存されており、再読み込みしても失われません。',
  'project.fileModal.saveFolder': '保存先フォルダ',
  'project.fileModal.notSelected': '未選択',
  'project.fileModal.needsReconnect': '（要再接続）',
  'project.fileModal.connect': '接続',
  'project.fileModal.change': '変更',
  'project.fileModal.select': '選択',
  'project.fileModal.tabSave': '保存（このプロジェクト）',
  'project.fileModal.tabOpen': '開く（一覧から）',
  'project.fileModal.filenameLabel': 'ファイル名',
  'project.fileModal.filenamePlaceholder': '例: CreditScoringAPI.json',
  'project.fileModal.overwriteWarning':
    '同名のファイルが既に存在します。「上書き保存」を押すと置き換えます。',
  'project.fileModal.overwriteButton': '上書き保存',
  'project.fileModal.selectFolderFirst': 'まず保存先フォルダを選択してください。',
  'project.fileModal.reconnectNeeded':
    'フォルダへのアクセスが切れています。上の「接続」を押してから一覧を表示します。',
  'project.fileModal.noFiles': 'このフォルダに保存済みのプロジェクト（.json）はありません。',

  // ── ProjectEditModal ──
  'project.editModal.nameLabel': 'プロジェクト名',
  'project.editModal.namePlaceholder': '例: 与信判定サービス 脅威モデリング',
  'project.editModal.systemNameLabel': 'システム名称',
  'project.editModal.systemNamePlaceholder': '例: CreditScoringAPI v2',
  'project.editModal.purposeLabel': 'システム目的',
  'project.editModal.purposePlaceholder': 'このシステムが解決する課題・提供する価値を簡潔に。',
  'project.editModal.businessImpactLabel': 'ビジネスインパクト',
  'project.editModal.businessImpactPlaceholder':
    '停止・侵害が発生した場合の事業影響（金額・期間・対象顧客数など）。',
  'project.editModal.securityObjectivesLabel': 'セキュリティ目標',
  'project.editModal.securityObjectivesPlaceholder':
    '守るべき機密性・完全性・可用性などの到達目標。脅威の優先度付けの基準になります。',

  // ── NewProjectModal ──
  'project.newModal.title': '新規プロジェクト',
  'project.newModal.confirmMessage':
    '現在の作業内容を消去して、まっさらな新規プロジェクトを作成します。作成する前に、現在のプロジェクトをファイルへ保存しますか？',
  'project.newModal.warning': '保存せずに作成すると、現在の図・手動脅威・DREAD 評価などは失われます。',
  'project.newModal.createWithoutSaving': '保存せずに作成',
  'project.newModal.saveAndCreate': '保存して作成',

  // ── TemplateModal ──
  'project.templateModal.defaultName': '{layer} テンプレート',
  'project.templateModal.tabExport': 'Export（書き出し）',
  'project.templateModal.tabImport': 'Import（読み込み）',
  'project.templateModal.exportIntroBefore': '現在のアクティブレイヤー（',
  'project.templateModal.exportIntroAfter': '・{count} 件）の図をテンプレートとして書き出します。',
  'project.templateModal.nameLabel': 'テンプレート名',
  'project.templateModal.namePlaceholder': '例: 標準 Web 三層構成',
  'project.templateModal.download': 'ダウンロード',
  'project.templateModal.importIntro1': 'テンプレート JSON を読み込み、アクティブレイヤー（',
  'project.templateModal.importIntro2': '）に',
  'project.templateModal.replaceWord': ' 置き換え ',
  'project.templateModal.importIntro3': 'で適用します。既存要素があるときは確認します。',
  'project.templateModal.selectFile': 'JSON ファイルを選択',
  'project.templateModal.importedOpenQuote': '「',
  'project.templateModal.importedStats': '」 — ノード {nodes} / エッジ {edges} / 境界 {boundaries}',
  'project.templateModal.confirmReplace':
    '{layer} には既に {count} 件の要素があります。これらを破棄してテンプレートで置き換えます。「置き換える」を押すと適用します（元に戻すで復元できます）。',
  'project.templateModal.replaceButton': '置き換える',
  'project.templateModal.replaceAndApply': '置き換えて適用',
  'project.templateModal.apply': '適用',
} as const;
