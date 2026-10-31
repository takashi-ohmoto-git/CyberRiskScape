/**
 * CLI `findings-report` サブコマンド（Veracode の指摘 × 構成図の脅威）の文言（日本語 = 真実）。
 * 集約は ../ja.ts。キー規約は ../../locales/ja.ts の冒頭コメントを参照。
 */
export const jaFindingsReport = {
  'findingsReport.heading': '# 脆弱性スキャン結果と脅威モデルの突き合わせ',
  'findingsReport.intro':
    'Veracode の指摘を、CWE の対応表を介して構成図から検出した脅威と突き合わせた結果です。対応表にない CWE は「対応づけできない指摘」に出ます。',

  'findingsReport.summary.open': '未解決の指摘: {count} 件',
  'findingsReport.summary.confirmed': '構成図の脅威と一致: {count} 件（脅威 {threats} 件）',
  'findingsReport.summary.notInModel': '構成図に該当する脅威がない: {count} 件',
  'findingsReport.summary.unmapped': '対応づけできない: {count} 件',
  'findingsReport.summary.excluded': '集計から除外: SCA {sca} 件・解決済み {closed} 件',

  'findingsReport.section.confirmed': '## 構成図の脅威がコードで確認されたもの',
  'findingsReport.section.confirmed.none': '一致したものはありません。',
  'findingsReport.section.priority': '## 優先して確認する指摘（上位 {limit} 件）',
  'findingsReport.section.notInModel': '## 構成図に該当する脅威がない指摘（構成図の描き漏れ候補）',
  'findingsReport.section.notInModel.none': '該当はありません。',
  'findingsReport.section.unmapped': '## 対応づけできない指摘',
  'findingsReport.section.unmapped.none': '該当はありません。',

  'findingsReport.section.gate': '## ゲート判定',
  'findingsReport.gate.pass': 'PASS（{failOn} 以上の未抑制の脅威に当たる指摘はありません）',
  'findingsReport.gate.fail': 'FAIL（{failOn} 以上の未抑制の脅威に当たる指摘が {count} 件）',
  'findingsReport.gate.notConfigured': '未設定（--fail-on 省略）',
  'findingsReport.gate.stderr':
    '--fail-on {failOn}: 構成図で {failOn} 以上の未抑制の脅威に当たる Veracode の指摘が {count} 件あります。',

  'findingsReport.confirmed.modelThreats': '構成図の脅威:',
  'findingsReport.findingsCount': '指摘: {count} 件（Veracode 重大度の最大 {max}）',
  'findingsReport.more': '…ほか {count} 件',
  'findingsReport.cweUnknown': 'CWE なし',
  'findingsReport.capec': 'CAPEC: {value}',
  'findingsReport.recorded': '［記録済みの判断: {labels}。指摘と食い違っていないか確認］',
  'findingsReport.priority.line': '構成図 {modelSeverity} / Veracode {severity}',

  // skill-scanner / mcp-scanner（Cisco AI Defense）用。AITech 分類の対応表を介して突き合わせる
  'findingsReport.intro.aitech':
    '{source} の指摘を、AITech 分類の対応表を介して構成図から検出した脅威と突き合わせた結果です。対応表にない分類の指摘は「対応づけできない指摘」に出ます。',
  'findingsReport.scopeNode':
    '対象ノード: {node}（このノード・接する線・線の先のノード・内包の親子の脅威とだけ突き合わせています）',
  'findingsReport.summary.incompleteItems': '検査が完了していない項目: {count} 件（検査できていない項目は安全とは限りません）',
  'findingsReport.findingsCount.label': '指摘: {count} 件（重大度の最大 {max}）',
  'findingsReport.aitechUnknown': '分類なし',
  'findingsReport.priority.lineSource': '構成図 {modelSeverity} / {source} {severity}',
  'findingsReport.gate.stderrSource':
    '--fail-on {failOn}: 構成図で {failOn} 以上の未抑制の脅威に当たる {source} の指摘が {count} 件あります。',
  'findingsReport.cli.sourceRequired':
    '--veracode・--skill-scanner・--mcp-scanner のうちどれか 1 つに、スキャン結果のファイルを指定してください。',
  'findingsReport.cli.sourceExclusive':
    '--veracode・--skill-scanner・--mcp-scanner は同時に指定できません。1 つだけ指定してください。',

  'findingsReport.cli.missingVeracode': '--veracode に Veracode の結果ファイルを指定してください。',
  'findingsReport.cli.done':
    '突き合わせました（未解決 {open} 件・一致 {confirmed} 件・構成図に無い {notInModel} 件・対応づけできない {unmapped} 件・除外 SCA {sca} 件／解決済み {closed} 件）',
} as const;
