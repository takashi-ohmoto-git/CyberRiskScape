/**
 * 業務の文脈（ノードが担う業務プロセスと重要度）の文言（日本語 = 真実）。
 * 集約は ../ja.ts。キー規約は ../../locales/ja.ts の冒頭コメントを参照。
 */
export const jaBusinessContext = {
  'businessContext.section.title': '業務の文脈',
  'businessContext.section.hint':
    'このノードが担う業務プロセスと、業務上の重要度。プロセスマイニング等の集計表の取り込み、または手入力で記録します。脅威ルールの発火には使いません。High は推奨標的に加わり、SSVC の Mission & Well-being を引き上げます。',
  'businessContext.criticality.label': '業務上の重要度',
  'businessContext.criticality.unset': '未設定',
  'businessContext.criticality.High': 'High',
  'businessContext.criticality.Medium': 'Medium',
  'businessContext.criticality.Low': 'Low',
  'businessContext.criticalitySource.declared': '表に記載・手入力',
  'businessContext.criticalitySource.derived': '金額の割合から',
  'businessContext.processes': '業務プロセス',
  'businessContext.processes.empty': '業務プロセスの記録はありません（取り込みで入ります）。',
  'businessContext.process.cases': '{count} 件',
  'businessContext.source': '出どころ: {product}（{at}）',
  'businessContext.source.ref': '参照: {ref}',

  'businessContext.import.menu': '業務の文脈を取り込む',
  'businessContext.import.title': '業務の文脈を取り込む',
  'businessContext.import.hint':
    '業務の文脈の表（CSV: node,process,cases,value,currency,period,criticality ／ JSON）を読み、ノードが担う業務プロセスと重要度を記録します。重要度は表の criticality、無ければ表全体の金額（無ければ件数）に占める割合（30% 以上 High・10% 以上 Medium）から決めます。表に出たノードだけ置き換えます。',
  'businessContext.import.pick': '表のファイル（.csv / .json）',
  'businessContext.import.read': '読み込む',
  'businessContext.import.apply': '反映する',
  'businessContext.import.close': '閉じる',
  'businessContext.import.cancel': 'キャンセル',
  'businessContext.import.error.tooLarge': 'ファイルが大きすぎます（上限 {max} MB）。',
  'businessContext.import.summary':
    '表の行 {rows} / 反映するノード {applied} / 決められず見送り {skipped} / 図に無い参照 {unknown} / 特定できない参照 {ambiguous}',
  'businessContext.import.basis': '割合の基準: {basis}',
  'businessContext.import.basis.value': '金額',
  'businessContext.import.basis.cases': '件数',
  'businessContext.import.basis.none': 'なし',
  'businessContext.import.nodeLine': '{node}: {criticality}（{how}）',
  'businessContext.import.how.derived': '割合から {share}%',
  'businessContext.import.how.declared': '表に記載',
  'businessContext.import.skippedLine': '{node}: 重要度を決められないため見送り（表に criticality・金額・件数が無い）',
  'businessContext.import.unknown': '図に無いノードの参照: {refs}',
  'businessContext.import.ambiguous': '複数のノードに当たる参照（ID で指定してください）: {refs}',
  'businessContext.import.note': '注意: {note}',
  'businessContext.import.done': '反映しました（{count} ノード）。元に戻す（Undo）で戻せます。',
  'businessContext.import.nothing': '反映できるノードがありません。',
} as const;
