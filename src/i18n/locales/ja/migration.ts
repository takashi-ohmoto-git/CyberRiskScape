/**
 * 移行レポート（Microsoft Threat Modeling Tool から取り込んだ脅威 × CyberRiskScape の検出脅威）の文言（日本語 = 真実）。
 * 集約は ../ja.ts。キー規約は ../../locales/ja.ts の冒頭コメントを参照。
 */
export const jaMigration = {
  'migration.heading': '# 移行レポート（Microsoft Threat Modeling Tool → CyberRiskScape）',
  'migration.intro':
    'TMT から取り込んだ脅威と、CyberRiskScape が同じ図から検出した脅威を、要素（線とその両端）と STRIDE の分類で突き合わせました。TMT の脅威は STRIDE の汎用の問いで、CyberRiskScape のルールとは 1 対 1 に対応しません。「重なり」は、同じ問いに具体的な脅威が当たっていることを示すだけで、同じ脅威であることを意味しません。',
  'migration.summary.heading': '## 1. 概要',
  'migration.summary.tmt': '- TMT の脅威：{total} 件（状態：{states}）',
  'migration.summary.detected':
    '- CyberRiskScape の検出脅威：{total} 件（Critical {critical} / High {high} / Medium {medium} / Low {low}）',
  'migration.summary.covered': '- 同じ要素・分類で CyberRiskScape の脅威が当たった TMT の脅威：{covered} / {total} 件',
  'migration.summary.detectedOnly':
    '- どの TMT の脅威とも重ならない検出脅威：{count} 件（検出全体のうち、STRIDE 以外＝AI・エージェントの脅威は {beyond} 件）',
  'migration.summary.assumed':
    '- 未入力の属性を悪い値と仮定して出た検出脅威：{count} 件（TMT で「Not Selected」のままの属性など。実態を入力すると消えます）',
  'migration.summary.recheck': '- 判断の見直し候補：{count} 件（下の 2 章）',
  'migration.recheck.heading': '## 2. 判断の見直し候補',
  'migration.recheck.intro':
    'TMT で対策済み（Mitigated）・対象外（Not Applicable）としたのに、同じ要素・分類で CyberRiskScape が抑制されていない脅威を出しているものです。TMT での判断の前提が、具体的な脅威にも当てはまるかを確かめてください。',
  'migration.recheck.columns': '| TMT の ID | TMT の脅威 | TMT での状態（変更者） | 対象 | CyberRiskScape の脅威 |',
  'migration.entries.heading': '## 3. TMT の脅威ごとの対応',
  'migration.entries.intro': '取り込んだ TMT の脅威の全件です。右端は同じ要素・分類で CyberRiskScape が検出した脅威です。',
  'migration.entries.columns': '| TMT の ID | TMT の脅威 | 分類 | TMT での状態 | 対象 | CyberRiskScape の脅威 |',
  'migration.entries.noMatch': '（同じ要素・分類の検出なし）',
  'migration.detectedOnly.heading': '## 4. CyberRiskScape だけが検出した脅威',
  'migration.detectedOnly.intro':
    'どの TMT の脅威とも重ならない検出脅威です（抑制済みを除く）。重大度の高い順です。AI・エージェントの脅威や、構成要素の型ごとの具体的な脅威は TMT の既定のテンプレートにはありません。',
  'migration.detectedOnly.columns': '| 重大度 | 脅威 | フレームワーク | 対象 | 仮定 |',
  'migration.assumedMark': '未入力のため仮定',
  'migration.none': '（該当なし）',
  'migration.next.heading': '## 5. 次の作業',
  'migration.next.body':
    '1. 注釈と説明の「[TMT] 要確認」を確認する（対応表に無い型・線の形の境界・つながっていない線）\n2. 仮定で出た脅威の要素に、実態の属性を入力する（認証方式・暗号・攻撃面・運用状況）\n3. 2 章の見直し候補について、TMT での判断を CyberRiskScape の脅威の対応方針・実装状況に記録し直す',
} as const;
