/**
 * 侵害調査計画（Markdown）の文言（日本語 = 真実）。
 * 集約は ../ja.ts。
 */
export const jaInvestigation = {
  'investigation.title': '侵害調査計画: {system}（{layer}）',
  'investigation.disclaimer': 'この計画は侵害の有無を判定しない。痕跡が無いことは、侵害が無かったことの証明にならない。',
  'investigation.system': 'システム: {system}',
  'investigation.generated': '作成日: {date}（{product} が脅威モデルから生成）',
  'investigation.scope.path': '対象: 攻撃者から攻撃目標へ至る経路上のノード。通る経路の多いノードから並べています。',
  'investigation.scope.all': '対象: 全ノード。攻撃者と攻撃目標をつなぐ経路が図に無いため、優先度は付けていません。',
  'investigation.howTo': '各ノードの「確かめること」と「見るログ」を出発点に調べ、「調べられない恐れ」があるノードは、先にログの状況を確かめてください。',
  'investigation.h.nodes': '調査の対象ノード',
  'investigation.nodes.none': '対象のノードがありません。',
  'investigation.routeHits': '通る攻撃経路の数: {hits}',
  'investigation.noViewpoint': '調査観点に当たる脅威は検出されませんでした。',
  'investigation.viewpoint': '{title}（脅威: {threats}）',
  'investigation.accepted': '※ {threat}: リスク受容済み（判断の理由は記録なし）。受容は調査を省く理由にならないため、観点に含めています。',
  'investigation.accepted.note': '※ {threat}: リスク受容済み（判断：{note}）。受容は調査を省く理由にならないため、観点に含めています。',
  'investigation.logs': '見るログ:',
  'investigation.toolHint': '{tool} の手がかり:',
  'investigation.limitations': '調べられない恐れ',
  'investigation.limit.none': '図の入力上は、ログの取得と保存期間に懸念はありません（実態は別途確認してください）。',
  'investigation.limit.logNotCollected': 'ログが集められていません。',
  'investigation.limit.logCollectionUnset': 'ログの取得が未入力です（集められていない前提で扱います）。',
  'investigation.limit.logRetentionShort': 'ログの保存期間が 90 日未満です。遡れる期間が短い恐れがあります。',
  'investigation.limit.logRetentionUnset': 'ログの保存期間が未入力です。遡れる期間が不明です。',
  'investigation.limit.logNotModelable': 'この型は、ログの状況を図で表せません（取得・保存期間は別途確認してください）。',
} as const;
