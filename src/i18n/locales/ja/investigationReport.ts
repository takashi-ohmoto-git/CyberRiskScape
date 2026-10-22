/**
 * 侵害調査レポート（`investigation-report`）の文言（日本語 = 真実）。
 * 集約は ../ja.ts。
 */
export const jaInvestigationReport = {
  'investigationReport.title': '侵害調査レポート: {system}（{layer}）',
  'investigationReport.disclaimer':
    'この報告は侵害の有無を判定しない。痕跡が無いことは、侵害が無かったことの証明にならない。',
  'investigationReport.generated': '作成日: {date}（{product} が脅威モデルと集めた証拠から生成）',
  'investigationReport.scope.path': '対象: 攻撃者から攻撃目標へ至る経路上のノード。',
  'investigationReport.scope.all': '対象: 全ノード。攻撃者と攻撃目標をつなぐ経路が図に無いため、絞り込んでいません。',
  'investigationReport.summary':
    '概要: 痕跡あり {found} ／ 否定できない {notNegatable} ／ 未調査 {notInvestigated} ／ 痕跡なし {noTraces}（証拠 {evidence} 件・図に無いホスト {unknown} 件・読めなかった入力 {rejected} 件）',
  'investigationReport.legend.h': '状態の凡例',
  'investigationReport.legend.traces-found': '痕跡あり: 対応づいた証拠のどれかに、痕跡とみなす結果がある。',
  'investigationReport.legend.not-negatable':
    '否定できない: 証拠はあるが、調べた期間が分からない、読めなかったファイルがある、または痕跡を探す結果が含まれていない。痕跡が無いとは言えない。',
  'investigationReport.legend.not-investigated': '未調査: 対応づいた証拠が無い。',
  'investigationReport.legend.no-traces':
    '痕跡なし: 証拠があり、痕跡とみなす結果が無く、調べた期間が分かり、読めなかったファイルも無い。侵害が無かったことを意味しない。',
  'investigationReport.status.traces-found': '痕跡あり',
  'investigationReport.status.not-negatable': '否定できない',
  'investigationReport.status.not-investigated': '未調査',
  'investigationReport.status.no-traces': '痕跡なし',
  'investigationReport.h.nodes': 'ノードごとの状態',
  'investigationReport.nodes.none': '対象のノードがありません。',
  'investigationReport.node.status': '状態: {status}',
  'investigationReport.node.period': '調べた期間: {period}',
  'investigationReport.node.period.unknown': '調べた期間: 不明',
  'investigationReport.period.observed': '{from} 〜 {to}（証拠から観測した値）',
  'investigationReport.period.observed.noEnd': '{from} 〜（収集日は不明。証拠から観測した値）',
  'investigationReport.period.retention.OneYearOrMore':
    '収集日（{to}）から少なくとも 1 年前まで（図のログ保存期間の入力による。観測値ではない）',
  'investigationReport.period.retention.Under1Year':
    '収集日（{to}）から 90 日以上前、1 年未満（図のログ保存期間の入力による。観測値ではない）',
  'investigationReport.period.retention.Under90Days':
    '90 日未満（収集日 {to}。図のログ保存期間の入力による。観測値ではない）',
  'investigationReport.node.reasons': '否定できない理由:',
  'investigationReport.reason.periodUnknown': '調べた期間が分からない（証拠にも、図のログ保存期間の入力にも手がかりが無い）。',
  'investigationReport.reason.skipped': '読めなかったファイルがある（下記）。',
  'investigationReport.reason.noSearch': '痕跡を探す結果が含まれていない（参考情報の件数だけ）。',
  'investigationReport.node.limitations': '調べられない恐れ（調査計画と同じ判定）:',
  'investigationReport.node.evidence': '証拠:',
  'investigationReport.evidence.line': '{source}・ホスト {host}・{path}・収集日 {collected}',
  'investigationReport.evidence.unknownHost': '(ホスト名なし)',
  'investigationReport.evidence.unknownDate': '不明',
  'investigationReport.evidence.source.triage': 'トリアージ',
  'investigationReport.evidence.source.velociraptor': 'Velociraptor',
  'investigationReport.evidence.traces': '痕跡とみなす結果: {count} 件（{categories}）',
  'investigationReport.evidence.noTraces': '痕跡とみなす結果: 0 件',
  'investigationReport.evidence.top': '上位:',
  'investigationReport.evidence.reference': '参考情報（件数のみ）: {list}',
  'investigationReport.evidence.skipped': '読めなかったもの:',
  'investigationReport.h.unknownHosts': '図に無いホスト',
  'investigationReport.unknownHosts.none': '該当なし。',
  'investigationReport.unknownHosts.intro':
    '次の証拠は、図のどのノードにも対応づけられませんでした。対応表（hosts.json）を確かめてください。',
  'investigationReport.unknownHost.notInHostMap': '対応表に無い',
  'investigationReport.unknownHost.nodeNotInDiagram': '対応表のノードが図に無い',
  'investigationReport.unknownHost.nodeNotInScope': '対応表のノードが、この報告の対象（攻撃経路上）に入っていない',
  'investigationReport.h.unmapped': '対応づけできない結果',
  'investigationReport.unmapped.intro':
    '調査観点の定義（compromise.yaml）に載っていない artifact の結果です。痕跡の判定には使わず、件数だけ載せます。',
  'investigationReport.h.rejected': '読めなかった入力',
  'investigationReport.cli.done':
    '侵害調査レポートを出力しました（{layer}・痕跡あり {found}・否定できない {notNegatable}・未調査 {notInvestigated}・痕跡なし {noTraces}・図に無いホスト {unknown}）',
  'investigationReport.cli.missingEvidence': '--evidence を 1 つ以上指定してください。',
  'investigationReport.cli.missingHosts': '--hosts を指定してください（hosts 配列に host と node を持つ JSON。例は tools/triage/README を参照）。',
  'investigationReport.cli.badHosts': '--hosts の形式が不正です: {error}',
  'investigationReport.cli.noEvidenceFound':
    '証拠が 1 件も見つかりませんでした（トリアージの JSON、または results/ を持つ Velociraptor の収集が必要です）。',
  'investigationReport.read.notFound': '読み込めません',
  'investigationReport.read.symlink': 'シンボリックリンクは読みません',
  'investigationReport.read.notJson': 'JSON として解析できません',
  'investigationReport.read.unsupported': '対応しない形式です（トリアージの JSON ではありません）',
  'investigationReport.read.invalid': '形式が不正です: {error}',
  'investigationReport.read.truncated': '大きすぎるため先頭 {mb} MB だけ読みました',
  'investigationReport.read.badLines': '解析できない行が {count} 行ありました',
  'investigationReport.read.tooManyEntries': 'フォルダー内の項目が多すぎるため、途中で探索をやめました',
  'investigationReport.read.noResults': '読み込める収集結果がありません',
} as const;
