/**
 * エクスポートするレポートの文言 の文言（日本語 = 真実）。
 * 集約は ../ja.ts。キー規約（`<領域>.<用途>`、プレースホルダ `{name}`）は
 * そちらの冒頭コメントを参照。
 */
export const jaReport = {
  // ── 対応状況（ThreatReportRow.status / DCRH controls 注記で共用） ──
  'report.status.unaddressed': '未対応',
  'report.status.avoid': '回避',
  'report.status.reduce': '低減',
  'report.status.transfer': '移転',
  'report.status.accepted': 'リスク受容',
  'report.status.falsePositive': '誤検知',

  // ── 種別（ThreatReportRow.origin） ──
  'report.origin.manual': '手動',
  'report.origin.detected': '自動検出',

  // ── CSV 列見出し ──
  'report.csv.col.id': 'ID',
  'report.csv.col.asset': '対象要素',
  'report.csv.col.framework': 'フレームワーク',
  'report.csv.col.category': 'カテゴリ',
  'report.csv.col.name': '脅威名',
  'report.csv.col.threat': '脅威',
  'report.csv.col.severity': 'ルール深刻度',
  'report.csv.col.effectiveSeverity': '実効深刻度',
  'report.csv.col.impact': 'Impact',
  'report.csv.col.likelihood': 'Likelihood',
  'report.csv.col.mitigation': '緩和策',
  'report.csv.col.status': '対応状況',
  'report.csv.col.controlStatus': '対策実装状況',
  'report.csv.col.comments': 'コメント',
  'report.csv.col.origin': '種別',

  // ── CSV 先頭のプロジェクトメタブロック ──
  'report.csv.meta.schemaVersion': 'スキーマバージョン',
  'report.csv.meta.projectName': 'プロジェクト名',
  'report.csv.meta.systemName': 'システム名称',
  'report.csv.meta.purpose': 'システム目的',
  'report.csv.meta.businessImpact': 'ビジネスインパクト',
  'report.csv.meta.securityObjectives': 'セキュリティ目標',
  'report.csv.meta.framework': 'フレームワーク',
  'report.csv.meta.layer': 'レイヤー',
  'report.csv.meta.threatCount': '脅威件数',

  // ── DCRH（Anthropic 公式 THREAT_MODEL.md）出力 ──
  // {name}=システム名, {brand}=BRANDING.name
  'report.csv.inventory.heading': '認証基盤インベントリ',
  'report.csv.inventory.col.provider': '発行元',
  'report.csv.inventory.col.kind': '種別',
  'report.csv.inventory.col.dependentCount': '依存先件数',
  'report.csv.inventory.col.dependents': '依存先',
  'report.csv.inventory.col.peerCount': '直接接続件数',
  'report.csv.inventory.col.peers': '直接接続',

  'report.dcrh.defaultContext': '{name} の脅威モデル（{brand} からエクスポート）。',
  'report.dcrh.businessImpactLine': 'ビジネスインパクト：{value}',
  'report.dcrh.securityObjectivesLine': 'セキュリティ目標：{value}',
  'report.dcrh.dataFlowDescription': 'データフロー（{network} / {encryption}）',
  'report.dcrh.reason.falsePositive': '誤検知として除外',
  'report.dcrh.reason.notApplicable': '対策対象外（not-applicable）',
  // {label}=理由ラベル, {note}=注記
  'report.dcrh.reasonWithNote': '{label}：{note}',
  // {controls}=緩和策本文, {extra}=対応方針注記
  'report.dcrh.controlsWithNote': '{controls}（{extra}）',

  // section 6「Open questions」の固定文言
  'report.dcrh.openQuestions.actor':
    '- actor は {brand} では未モデル化。section 4 の actor 列は空欄。要レビュー。',
  'report.dcrh.openQuestions.likelihood':
    '- likelihood はリスク評価未評価の脅威で既定 `possible` を採用している。',
  'report.dcrh.openQuestions.evidence':
    '- evidence（CVE / 所見リンク等）は本ツールが未保持のため常に空。',
  'report.dcrh.openQuestions.sensitivity':
    '- sensitivity はそのアセットに紐づく脅威のリスク評価 Damage の最大値から推定（1=low / 2=medium / 3=high）。`critical` は出力しない。',
  'report.dcrh.openQuestions.sensitivityDefault':
    '- リスク評価済みの脅威が 1 件も無いアセットは sensitivity を既定 `medium` としている。',
  'report.dcrh.openQuestions.entryPoint':
    '- entry point は脅威が紐づくデータフローのみを列挙（未割当のエッジは省略）。',
  'report.dcrh.openQuestions.section8':
    '- section 8 の closes_class / effort は暫定値（要レビュー）。',

  // ── PDF レポート ──
  'report.pdf.title': '脅威モデリング報告書',
  'report.pdf.meta.project': 'プロジェクト名',
  'report.pdf.meta.system': 'システム名',
  'report.pdf.meta.purpose': 'システム目的',
  'report.pdf.meta.businessImpact': 'ビジネスインパクト',
  'report.pdf.meta.securityObjectives': 'セキュリティ目標',
  'report.pdf.meta.generatedAt': '生成日時',
  'report.pdf.meta.tool': 'ツール',
  'report.pdf.meta.framework': 'フレームワーク',
  'report.pdf.meta.layers': '対象レイヤー',
  'report.pdf.meta.schemaVersion': 'レポート形式版',
  'report.pdf.summary.heading': 'サマリ（レイヤー別・実効深刻度別の脅威件数）',
  'report.pdf.summary.layer': 'レイヤー',
  'report.pdf.summary.total': '有効合計',
  'report.pdf.summary.suppressed': '受容・誤検知',
  'report.pdf.summary.grandTotal': '合計',
  'report.pdf.layer.heading': '{layer} レイヤー',
  'report.pdf.section.threats': '脅威一覧',
  'report.pdf.section.suppressed': '受容・誤検知とした脅威',
  'report.pdf.section.details': '脅威の詳細',
  'report.pdf.noThreats': 'このレイヤーに脅威はありません。',
  'report.pdf.table.no': 'No',
  'report.pdf.table.asset': '対象',
  'report.pdf.table.name': '脅威名',
  'report.pdf.table.severity': '実効深刻度',
  'report.pdf.table.status': '対応状況',
  'report.pdf.table.controlStatus': '対策実装状況',
  'report.pdf.detail.category': 'カテゴリ',
  'report.pdf.detail.asset': '対象要素',
  'report.pdf.detail.description': '説明',
  'report.pdf.detail.mitigation': '緩和策',
  'report.pdf.detail.compliance': 'コンプライアンス参照',
  'report.pdf.detail.impact': 'Impact',
  'report.pdf.detail.likelihood': 'Likelihood',
  'report.pdf.detail.comments': 'コメント',
  'report.pdf.detail.status': '対応状況',
  'report.pdf.detail.controlStatus': '対策実装状況',
  'report.pdf.footer.page': '{page} / {total} ページ',
  'report.pdf.metric.active': '有効脅威数',
  'report.pdf.metric.criticalHigh': 'Critical＋High 件数',
  'report.pdf.metric.progress': '対策実装進捗率',
  'report.pdf.metric.progressDone': '実装済み {done} / {total} 件',
  'report.pdf.metric.progressCh': 'Critical＋High：{rate}',
  'report.pdf.metric.unaddressed': '未対応件数',
  'report.pdf.top.heading': '重要脅威 上位 10',
  'report.pdf.top.rank': '順位',
  'report.pdf.top.layer': 'レイヤー',
  'report.pdf.top.empty': '有効な脅威はありません。',
  'report.pdf.counts.treatment': '対応方針別の件数',
  'report.pdf.counts.control': '対策実装状況別の件数（有効脅威）',
  'report.pdf.control.unset': '未設定',
  'report.pdf.premise.heading': '評価の前提',
  'report.pdf.topDetail.heading': '重要脅威 上位 10 の詳細',
  'report.pdf.appendix.heading': '付録：レイヤー別の脅威',
  'report.pdf.detail.firstStep': 'まず着手すべき対策',
  'report.pdf.detail.layer': 'レイヤー',
} as const;
