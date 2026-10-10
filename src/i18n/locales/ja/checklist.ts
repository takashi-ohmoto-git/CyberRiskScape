/**
 * 注意喚起チェックリスト（画面・CSV・CLI）の文言（日本語 = 真実）。
 * 集約は ../ja.ts。キー規約は ../../locales/ja.ts の冒頭コメントを参照。
 */
export const jaChecklist = {
  'checklist.menu': '注意喚起チェックリスト',
  'checklist.title': '注意喚起チェックリスト',
  'checklist.close': '閉じる',
  'checklist.pick': 'チェックリスト',
  // {publisher}=発行元, {title}=タイトル, {date}=公開日
  'checklist.source': '出典：{publisher}「{title}」（{date}）',
  'checklist.disclaimer':
    '判定は構成図に基づく。実機の点検の代わりではありません。ログ・パッチ・アカウントの実際の状態は、実機と各サービスの管理画面で確かめてください。',
  'checklist.layer': '対象レイヤー',
  'checklist.layerNodes': '{layer}（{count} ノード）',
  'checklist.empty': 'このレイヤーにはノードがありません。レイヤーを切り替えてください。',
  'checklist.status.action': '要対応',
  'checklist.status.unfilled': '未入力',
  'checklist.status.accepted': 'リスク受容',
  'checklist.status.ok': '問題なし',
  'checklist.status.notApplicable': '対象なし',
  'checklist.status.action.desc': '未入力でない根拠で検出された脅威がある',
  'checklist.status.unfilled.desc': '検出はすべて未入力（属性が空）のため「対策なし」と仮定したもの',
  'checklist.status.accepted.desc': '検出はすべてリスク受容済み',
  'checklist.status.ok.desc': '対象のノードがあり、検出が無い',
  'checklist.status.notApplicable.desc': '図にこの項目の対象となる型のノードが無い',
  'checklist.item.howTo': '確かめ方',
  'checklist.item.nodes': '関係ノード',
  'checklist.item.noNodes': '関係ノードはありません',
  // {action}=要対応, {unfilled}=未入力, {accepted}=受容
  'checklist.item.counts': '検出：要対応 {action} 件・未入力 {unfilled} 件・受容 {accepted} 件',
  'checklist.item.selectNode': '{label} をキャンバスで選択',
  'checklist.stale.heading': '点検が古い・未記録のノード',
  // {days}=日数, {asOf}=基準日
  'checklist.stale.intro': '最終点検日が未記録、または基準日（{asOf}）から {days} 日を超えているノードです。',
  'checklist.stale.none': '該当するノードはありません。',
  'checklist.stale.col.node': 'ノード',
  'checklist.stale.col.state': '最終点検日',
  'checklist.stale.unrecorded': '未記録',
  // {date}=最終点検日, {days}=経過日数
  'checklist.stale.stale': '{date}（{days} 日前）',
  'checklist.csv': 'CSV 出力',

  'checklist.csv.meta.checklist': 'チェックリスト',
  'checklist.csv.meta.source': '出典',
  'checklist.csv.meta.asOf': '基準日',
  'checklist.csv.meta.staleDays': '点検が古いとみなす日数',
  'checklist.csv.meta.summary': '集計',
  'checklist.csv.meta.note': '注記',
  'checklist.csv.col.group': 'グループ',
  'checklist.csv.col.no': '項目 No',
  'checklist.csv.col.item': '項目',
  'checklist.csv.col.status': '状態',
  'checklist.csv.col.targets': '対象の型のノード数',
  'checklist.csv.col.relatedCount': '関係ノード数',
  'checklist.csv.col.action': '要対応',
  'checklist.csv.col.unfilled': '未入力',
  'checklist.csv.col.accepted': 'リスク受容',
  'checklist.csv.col.nodes': '関係ノード',
  'checklist.csv.col.howTo': '確かめ方',
  'checklist.csv.col.actionNodes': '確認が必要なノード',

  // CLI の Markdown 出力
  'checklist.md.summary': '集計',
  'checklist.md.col.no': 'No',
  'checklist.md.col.item': '項目',
  'checklist.md.col.status': '状態',
  'checklist.md.col.nodes': '関係ノード',
  'checklist.md.layer': '対象レイヤー',
  // CLI のエラー・stderr
  'checklist.cli.unknownId': '不明なチェックリスト ID です: "{id}"（指定可能: {ids}）',
  'checklist.cli.invalidAsOf': '不正な --as-of の値です: "{value}"（YYYY-MM-DD 形式の実在する日付を指定）',
  'checklist.cli.noNodes': 'ノードのあるレイヤーがありません。',
  'checklist.cli.failOnAction': '--fail-on-action: 要対応の項目が {count} 件あります。',
} as const;
