/**
 * 検知要件（Markdown）の文言（日本語 = 真実）。
 * 集約は ../ja.ts。「検知できる」とは書かない（監視すべきことと、ログの届き方だけを示す）。
 */
export const jaDetection = {
  'detection.title': '攻撃経路ごとの検知要件: {system}（{layer}）',
  'detection.disclaimer':
    'この文書は「監視すべき振る舞い」と「必要なログ」を示すもので、実際に検知できることを意味しない。ログが監視先に届くかは図の入力に基づく読み取りで、実態の確認が別途必要。',
  'detection.system': 'システム: {system}',
  'detection.generated': '作成日: {date}（{product} が脅威モデルから生成）',
  'detection.scope.path': '対象: 攻撃者から攻撃目標へ至る経路上のノード。通る経路の多いノードから並べています。',
  'detection.scope.all': '対象: 全ノード。攻撃者と攻撃目標をつなぐ経路が図に無いため、優先度は付けていません。',
  'detection.h.routes': '攻撃経路とログが届かない区間',
  'detection.routes.truncated': '実行可能な経路 {total} 本のうち、コストの低い {shown} 本を載せています。',
  'detection.route': '経路 {n}: {attacker} → {objective}',
  'detection.route.nodes': '経路: {nodes}',
  'detection.route.blind': '評価できるノードのどこからも、ログが監視先に届くとは読み取れません。',
  'detection.route.noGap': 'ログが監視先に届かない区間は、図の入力上はありません（実態は別途確認してください）。',
  'detection.route.gap': 'この区間はログが監視先に届かない（届くかは未確認／未入力）: {nodes}',
  'detection.h.nodes': '監視の対象ノード',
  'detection.nodes.none': '対象のノードがありません。',
  'detection.routeHits': '通る攻撃経路の数: {hits}',
  'detection.logState': 'ログの届き方: {state}',
  'detection.log.forwarded': 'ログの送信先が図に入力されています（実際に届くかは別途確認してください）。',
  'detection.log.localOnly': 'ログはノード内に取得されますが、監視先に届くかは未確認／未入力です。',
  'detection.log.none': 'ログが取得されない設定です。ログが監視先に届きません。',
  'detection.log.noneAssumed': 'ログが監視先に届かない（届くかは未確認／未入力のため、届かない前提で扱います）。',
  'detection.log.notModelable': 'この型は、ログの状況を図で表せません（別途確認してください）。',
  'detection.noRequirement': '監視要件の対応表に当たる脅威は検出されませんでした。',
  'detection.requirement': '{title}（脅威: {threats}）',
  'detection.watch': '監視すべき振る舞い:',
  'detection.logs': '必要なログ:',
} as const;
