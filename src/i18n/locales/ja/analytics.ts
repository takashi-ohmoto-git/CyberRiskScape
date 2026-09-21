/**
 * Analytics・コンプライアンス・攻撃経路 の文言（日本語 = 真実）。
 * 集約は ../ja.ts。キー規約（`<領域>.<用途>`、プレースホルダ `{name}`）は
 * そちらの冒頭コメントを参照。
 */
export const jaAnalytics = {
  'analytics.close': '閉じる',

  // ── リスク評価フォーム（Impact × Likelihood 2 軸方式） ──
  'analytics.risk.damage.label': '損害（Damage）',
  'analytics.risk.damage.level1': '軽微な障害・限定的な情報露出',
  'analytics.risk.damage.level2': '一部データの漏えい・改ざん',
  'analytics.risk.damage.level3': '全データ侵害・システム全停止',
  'analytics.risk.affectedUsers.label': '影響範囲（Affected Users）',
  'analytics.risk.affectedUsers.level1': 'ごく一部のユーザー',
  'analytics.risk.affectedUsers.level2': '相当数のユーザー・テナント',
  'analytics.risk.affectedUsers.level3': '全ユーザー・管理者を含む',
  'analytics.risk.reproducibility.label': '再現性（Reproducibility）',
  'analytics.risk.reproducibility.level1': '特定条件下でまれに成立',
  'analytics.risk.reproducibility.level2': '条件が揃えば成立',
  'analytics.risk.reproducibility.level3': '常に成立',
  'analytics.risk.exploitability.label': '攻撃容易性（Exploitability）',
  'analytics.risk.exploitability.level1': '高度な技術・内部知識が必要',
  'analytics.risk.exploitability.level2': 'ツール・手順が一部公開',
  'analytics.risk.exploitability.level3': '既製ツールで容易に攻撃可能',
  'analytics.risk.level.low': '低',
  'analytics.risk.level.medium': '中',
  'analytics.risk.level.high': '高',
  'analytics.risk.heading': 'リスク評価',
  'analytics.risk.impactHeading': 'Impact（損害・影響範囲）',
  'analytics.risk.likelihoodHeading': 'Likelihood（再現性・攻撃容易性）',
  // {impact}=Impact レベル（低/中/高）, {likelihood}=Likelihood レベル（低/中/高）
  'analytics.risk.previewLine': 'Impact {impact} ／ Likelihood {likelihood} →',
  // {severity}=threat.severity（ルール由来の元 severity）
  'analytics.risk.ruleSeverityTooltip': '（ルール由来: {severity}）',
  // {severity}=threat.severity
  'analytics.risk.scoredTooltip': 'リスク評価済み（元の severity: {severity}）',
  // {impact}=Impact レベル, {likelihood}=Likelihood レベル
  'analytics.risk.scoredBadge': 'リスク {impact}×{likelihood}',
  'analytics.risk.clearButton': '評価をクリア',
  'analytics.risk.saveButton': '保存',

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
  // 認証基盤インベントリ（[[plan]] §2.40 ②）
  'analytics.inventory.heading': '認証基盤インベントリ（{count} 件）',
  'analytics.inventory.note': '図の中で資格情報の発行元になり得るノードと、その影響範囲。Tier 1 はこの発行元を宣言しているコンポーネント（落ちると認証が壊れる）で、エッジ側の「資格情報の発行元」とコンポーネント側の「認証の預け先」の両方を数えます。Tier 2 は線で直接つながっている相手。どちらも宣言していない依存は数えられないため、影響範囲は過小評価になり得る。',
  'analytics.inventory.tier1': 'Tier 1 依存（{count}）',
  'analytics.inventory.tier2': 'Tier 2 直接接続（{count}）',
  'analytics.inventory.none': 'なし',
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
