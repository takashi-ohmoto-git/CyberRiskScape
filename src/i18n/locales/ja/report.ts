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
} as const;
