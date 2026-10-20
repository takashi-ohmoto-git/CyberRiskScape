/**
 * SBOM／CBOM（CycloneDX）からノードの暗号を確認するレポート・CLI `pqc-sbom-report`・画面ボタンの文言
 * （日本語 = 真実）。集約は ../ja.ts。
 */
export const jaSbomCrypto = {
  'sbomCrypto.title': 'SBOM の暗号の確認',
  'sbomCrypto.h.summary': '1. 概要',
  'sbomCrypto.h.algorithms': '2. アルゴリズム',
  'sbomCrypto.h.protocols': '3. プロトコル',
  'sbomCrypto.h.certificates': '4. 証明書',
  'sbomCrypto.h.libraries': '5. 暗号ライブラリ',
  'sbomCrypto.h.compare': '6. 図との比較',
  'sbomCrypto.h.limits': '7. この確認の限界',

  'sbomCrypto.summary.source': 'SBOM: {source}（CycloneDX {version}）',
  'sbomCrypto.summary.node': '対象のノード: {id} {label}',
  'sbomCrypto.summary.counts': '部品 {components} 件・暗号資産 {assets} 件・暗号ライブラリ {libraries} 件',
  'sbomCrypto.summary.generated': '作成日: {date}（{product} が作成）',

  'sbomCrypto.col.name': '名前',
  'sbomCrypto.col.primitive': '種類',
  'sbomCrypto.col.parameterSet': 'パラメーター',
  'sbomCrypto.col.curve': '曲線',
  'sbomCrypto.col.nist': 'NIST 量子セキュリティレベル（申告値）',
  'sbomCrypto.col.verdict': '判定',
  'sbomCrypto.col.type': '種類',
  'sbomCrypto.col.version': 'バージョン',
  'sbomCrypto.col.cipherSuites': '暗号スイート',
  'sbomCrypto.col.subject': '主体',
  'sbomCrypto.col.issuer': '発行者',
  'sbomCrypto.col.notValidAfter': '有効期限',
  'sbomCrypto.col.signature': '署名方式',
  'sbomCrypto.col.library': 'ライブラリ',
  'sbomCrypto.col.purl': 'purl',
  'sbomCrypto.col.role': '用途',
  'sbomCrypto.col.note': '注記',

  'sbomCrypto.role.tls': 'TLS などの通信路',
  'sbomCrypto.role.general': '汎用の暗号処理',
  'sbomCrypto.role.jwt': 'トークンの署名',
  'sbomCrypto.role.pqc': 'PQC 専用',

  'sbomCrypto.algorithms.none':
    'この SBOM には暗号資産（アルゴリズム）の記載がありません。部品だけの SBOM（多くの SBOM 生成ツールの既定の出力）には方式の情報がないため、5 章のライブラリから、使っている方式を確かめてください。',
  'sbomCrypto.protocols.none': 'プロトコルの記載はありません。',
  'sbomCrypto.certificates.none': '証明書の記載はありません。',
  'sbomCrypto.libraries.none': '暗号ライブラリの一覧に当たる部品は見つかりませんでした。',
  'sbomCrypto.libraries.unmatched': '一覧に当たらなかった部品: {count} 件（ここには載せていません）',

  'sbomCrypto.compare.lead':
    '次は、SBOM から見つかった候補です。PQC レイヤーで入力する値の参考にしてください。図は変更していません。',
  'sbomCrypto.compare.notEntered': '未入力',
  'sbomCrypto.compare.noCandidates': '候補なし',
  'sbomCrypto.compare.nodeSignature': 'ノードの署名方式: 図の入力値 {entered} / SBOM の候補 {candidates}',
  'sbomCrypto.compare.edge':
    '{id}（{peer}）: プロトコル {protocol}・バージョン {version}・鍵交換 {kex} / SBOM の鍵交換の候補 {candidates}',
  'sbomCrypto.compare.noEdges': 'このノードにつながる通信はありません。',

  'sbomCrypto.limits.1':
    'SBOM に含まれていても、その方式を使っているとは限りません。部品が入っているだけで、アプリが呼んでいないこともあります。',
  'sbomCrypto.limits.2':
    '設定で方式を無効にしたり固定したりできます。実際に使う方式は、設定と実際の通信でも確かめてください。',
  'sbomCrypto.limits.3':
    '部品だけの SBOM（多くの SBOM 生成ツールの既定の出力）には、アルゴリズムの情報がありません。その場合はライブラリの一覧だけを出します。',
  'sbomCrypto.limits.4': 'ライブラリの注記は要約です。版の対応状況は、そのライブラリのリリースノートで確かめてください。',

  'sbomCrypto.error.notJson':
    'CycloneDX の JSON だけ読めます。XML などは、JSON で書き出し直してください（例: --format cyclonedx-json）。',
  'sbomCrypto.error.notCycloneDx': 'CycloneDX の SBOM（bomFormat が CycloneDX の JSON）ではありません。',
  'sbomCrypto.error.tooLarge': '{mb} MB を超えるファイルは読めません。',

  'sbomCrypto.cli.missingSbom': '--sbom に CycloneDX の JSON ファイルを指定してください。',
  'sbomCrypto.cli.missingNode': '--node に対象のノードの ID（例: C3）を指定してください。',
  'sbomCrypto.cli.readFailed': 'SBOM を読み込めません: {file}（{reason}）',
  'sbomCrypto.cli.nodeNotFound': 'ノード "{node}" が {layer} にありません。指定できる ID: {ids}',
  'sbomCrypto.cli.done':
    'SBOM の暗号の確認を出力しました（{layer}・{node}・暗号資産 {assets} 件・暗号ライブラリ {libraries} 件）',

  'sbomCrypto.ui.button': 'SBOM から暗号を確認',
  'sbomCrypto.ui.hint':
    'CycloneDX の JSON を選ぶと、このノードの暗号を確認するレポート（Markdown）を書き出します。図は変わりません。',
  'sbomCrypto.ui.error': '読み込めませんでした: {reason}',
} as const;
