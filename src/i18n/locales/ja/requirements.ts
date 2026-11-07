/**
 * セキュリティ要件一覧（Markdown / CSV）の文言（日本語 = 真実）。
 * 集約は ../ja.ts。
 */
export const jaRequirements = {
  'requirements.title': 'セキュリティ要件一覧（たたき台）: {system}（{layer}）',
  'requirements.disclaimer':
    'この一覧は脅威モデルから機械的に導いたたたき台です。採否・優先度・委託先への依頼は人間が決めてください。',
  'requirements.system': 'システム: {system}',
  'requirements.generated': '作成日: {date}（{product} が脅威モデルから生成）',
  'requirements.howTo':
    '要件は脅威ごとの緩和策を段階（Foundation / Enterprise / Advanced）に分けたものです。設計段階で必要な段階を選び、要件定義書や委託先への仕様に取り込んでください。',
  'requirements.h.list': '要件',
  'requirements.none': '要件に落とせる緩和策のある脅威は検出されませんでした。',
  'requirements.col.id': '要件ID',
  'requirements.col.tier': '段階',
  'requirements.col.text': '要件',
  'requirements.col.targets': '対象ノード',
  'requirements.col.basis': '根拠の脅威',
  'requirements.col.severity': '最大重大度',
  'requirements.col.stage': '工程',
  'requirements.col.csf': 'NIST CSF 2.0',
  'requirements.col.contractor': '委託先への要求',
  'requirements.col.status': '状態',
  'requirements.yes': '要',
  'requirements.accepted': 'リスク受容済み（実施しない判断）',
  'requirements.accepted.note': 'リスク受容済み（実施しない判断：{note}）',
  'requirements.h.contractor': '委託先へ求める要件の例',
  'requirements.contractor.lead': '図に当たる脅威があるものだけを載せています。契約・仕様書に取り込むときの出発点にしてください。',
  'requirements.contractor.basis': '根拠: {threats}',
  'project.sidebar.exportRequirements': 'セキュリティ要件一覧（たたき台）',
};
