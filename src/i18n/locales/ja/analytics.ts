/**
 * Analytics・コンプライアンス・攻撃経路 の文言（日本語 = 真実）。
 * 集約は ../ja.ts。キー規約（`<領域>.<用途>`、プレースホルダ `{name}`）は
 * そちらの冒頭コメントを参照。
 */
export const jaAnalytics = {
  'analytics.close': '閉じる',

  // ── DREAD 評価フォーム ──
  'analytics.dread.damage.label': 'D: 損害（Damage）',
  'analytics.dread.damage.level1': '軽微な障害・限定的な情報露出',
  'analytics.dread.damage.level2': '一部データの漏えい・改ざん',
  'analytics.dread.damage.level3': '全データ侵害・システム全停止',
  'analytics.dread.reproducibility.label': 'R: 再現性（Reproducibility）',
  'analytics.dread.reproducibility.level1': '特定条件下でまれに成立',
  'analytics.dread.reproducibility.level2': '条件が揃えば成立',
  'analytics.dread.reproducibility.level3': '常に成立',
  'analytics.dread.exploitability.label': 'E: 攻撃容易性（Exploitability）',
  'analytics.dread.exploitability.level1': '高度な技術・内部知識が必要',
  'analytics.dread.exploitability.level2': 'ツール・手順が一部公開',
  'analytics.dread.exploitability.level3': '既製ツールで容易に攻撃可能',
  'analytics.dread.affectedUsers.label': 'A: 影響範囲（Affected Users）',
  'analytics.dread.affectedUsers.level1': 'ごく一部のユーザー',
  'analytics.dread.affectedUsers.level2': '相当数のユーザー・テナント',
  'analytics.dread.affectedUsers.level3': '全ユーザー・管理者を含む',
  'analytics.dread.discoverability.label': 'D: 発見容易性（Discoverability）',
  'analytics.dread.discoverability.level1': '内部知識がないと発見困難',
  'analytics.dread.discoverability.level2': '注意深い調査で発見可能',
  'analytics.dread.discoverability.level3': '外部から容易に発見可能',
  'analytics.dread.level.low': '低',
  'analytics.dread.level.medium': '中',
  'analytics.dread.level.high': '高',
  'analytics.dread.heading': 'DREAD 評価',
  'analytics.dread.totalLabel': '合計',
  // {severity}=threat.severity（ルール由来の元 severity）
  'analytics.dread.ruleSeverityTooltip': '（ルール由来: {severity}）',
  // {severity}=threat.severity
  'analytics.dread.scoredTooltip': 'DREAD 評価済み（元の severity: {severity}）',
  'analytics.dread.clearButton': '評価をクリア',
  'analytics.dread.saveButton': '保存',

  // ── フィルタバー / プリセット ──
  'analytics.filter.label': 'フィルタ',
  'analytics.filter.placeholder': 'ElementalID / 名称 / カテゴリ',
  'analytics.preset.all': '全件',
  'analytics.preset.highPlus': 'High 以上',
  'analytics.preset.withMit': '緩和策あり',
  'analytics.preset.withoutMit': '緩和策なし',

  'analytics.controlGroup.unset': '未設定',

  // {layer}=activeLayer, {elements}=要素数, {threats}=脅威件数
  'analytics.header.summary': 'レイヤー {layer} / {elements} 要素 / 脅威 {threats} 件',

  'analytics.renumber.tooltip':
    '削除で生じた欠番を詰め、全レイヤーの ElementalID を 1 から振り直します',
  'analytics.renumber.button': 'ID を振り直す',
  'analytics.renumber.confirmBody':
    '全レイヤーの ElementalID（C / DF / Z）を 1 から振り直します。過去のレポート等で参照した ID は別の要素を指す可能性があり、Undo 履歴もクリアされます。',
  'analytics.renumber.confirmButton': '振り直しを実行',
  'analytics.renumber.cancelButton': 'キャンセル',

  'analytics.tree.empty': '該当する脅威はありません。',
  'analytics.tree.maxSeverityTooltip': 'この要素の最大リスク',

  // {count}=対策件数
  'analytics.countermeasures.heading': '対策 {count} 件',
  'analytics.countermeasures.empty': '緩和策のある脅威はありません。',
  // {severity}=threat.severity, {element}=要素ラベル
  'analytics.countermeasureItem.title': '{severity} ・ {element}',

  'analytics.detail.empty': '脅威を選択してください。',
  'analytics.detail.mitigationLabel': '緩和策',
  'analytics.detail.riskTreatmentHeading': 'リスク対応方針',
  'analytics.detail.controlStatusHeading': '対策実装状況',

  'analytics.unassigned.label': '要素に紐づかない脅威',
  'analytics.unassigned.parenLabel': '（要素に紐づかない脅威）',

  // {trustLevel}=境界の trustLevel
  'analytics.boundaryFallbackLabel': '{trustLevel} 境界',
  // {base}=ノード名の矢印表記, {flow}=dataFlowName
  'analytics.edgeLabelWithFlow': '{base}（{flow}）',

  // ── Compliance Map ──
  // {standards}=規格数, {total}=合計項目数
  'analytics.compliance.standardsSummary': '{standards} 規格 / 合計 {total} 項目',
  // {count}=項目数
  'analytics.compliance.itemsCount': '{count} 項目',
  'analytics.compliance.officialLink': '公式情報',
  // {license}=ライセンス名
  'analytics.compliance.license': 'ライセンス: {license}',
  'analytics.compliance.filterPlaceholder': 'ref / 名称 / 要約 で絞り込み',
  'analytics.compliance.noItems': '該当する項目はありません。',
  'analytics.compliance.selectPrompt': '左のリストから規格を選択してください。',
  'analytics.compliance.originalLinkTooltip': '原文リンク',
  'analytics.compliance.crosswalkTooltip': '対応する他規格項目（クロスウォーク）',
} as const;
