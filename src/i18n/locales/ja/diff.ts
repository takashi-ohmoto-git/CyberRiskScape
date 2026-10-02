/**
 * CLI `diff` サブコマンド（モデル差分レポート）の文言（日本語 = 真実）。
 * 集約は ../ja.ts。キー規約は ../../locales/ja.ts の冒頭コメントを参照。
 */
export const jaDiff = {
  'diff.heading': '# モデル差分レポート',

  'diff.summary.added': '追加: {count} 件',
  'diff.summary.removed': '解消: {count} 件',
  'diff.summary.suppressionChanged': '対応方針変更: {count} 件（要承認 {approvalCount} 件）',
  'diff.summary.severityChanged': '実効severity変化: {count} 件',

  'diff.section.triggers': '## 実行トリガー',
  'diff.triggers.none': '該当する実行トリガーはありません。',
  'diff.triggers.manualHeading': '### PR レビューで確認（モデル差分では自動判定できません）',

  'diff.section.added': '## 追加された脅威',
  'diff.section.removed': '## 解消された脅威',
  'diff.section.suppressionChanged': '## 対応方針の変更',
  'diff.section.severityChanged': '## 実効severityの変化',
  'diff.section.gate': '## ゲート判定',

  'diff.table.none': '（該当なし）',
  'diff.col.severity': 'Severity',
  'diff.col.asset': '対象要素',
  'diff.col.threat': '脅威',
  'diff.col.before': '変更前',
  'diff.col.after': '変更後',
  'diff.col.approval': '要承認',

  'diff.approval.yes': '要承認',
  'diff.approval.no': '',

  // {failOn}=--fail-on のしきい値, {count}=ゲート対象の件数
  'diff.gate.pass': 'PASS（しきい値 {failOn} 以上の新規未抑制脅威はありません）',
  'diff.gate.fail': 'FAIL（しきい値 {failOn} 以上の新規未抑制脅威が {count} 件）',
  'diff.gate.notConfigured': '未設定（--fail-on 省略）',
} as const;
