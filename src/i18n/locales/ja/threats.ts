/**
 * 脅威カードと手動脅威・対応方針 の文言（日本語 = 真実）。
 * 集約は ../ja.ts。キー規約（`<領域>.<用途>`、プレースホルダ `{name}`）は
 * そちらの冒頭コメントを参照。
 */
export const jaThreats = {
  // ── ThreatCard ──
  'threats.threatCard.manualTypeRuleHint':
    '同型ノード全てに適用されるカスタムルール。編集／削除はルール全体に効きます。',
  'threats.threatCard.manualTypeRuleLabel': '型ルール: {label}',
  'threats.threatCard.corroborationHint':
    '複数ソースが同一脅威を指摘しています（出典欄に全て掲載）。',
  'threats.threatCard.corroborationSources': '{count} ソース',
  'threats.threatCard.pentestVerified': '{product} で実証',
  'threats.threatCard.pentestVerifiedHint':
    'このツールが実際に実行して成立した攻撃手段です。検証した範囲に限られ、網羅したものではありません。',
  'threats.threatCard.pentestAttempted': '{product} 試行',
  'threats.threatCard.pentestAttemptedHint':
    'このツールが攻撃手段として試行した記録です。成立は確認されていません。試行していない手段が安全という意味でもありません。',
  'threats.threatCard.pentestAttemptedTag': '試行',
  'threats.threatCard.securityAuditVerified': 'ソース監査で実証（ローカル）',
  'threats.threatCard.securityAuditVerifiedHint':
    'AI によるソース監査が、手元のソースコードの上で成立を確かめた指摘です。実環境での確認ではありません。',
  'threats.threatCard.securityAuditUnverified': 'ソース監査で要確認',
  'threats.threatCard.securityAuditUnverifiedHint':
    'AI によるソース監査が根拠を示したものの、決め手の事実が未解決の指摘です。重大度は付いていません。',
  'threats.threatCard.mitigationHeadingTiered': '緩和策（3 段階成熟度）',
  'threats.threatCard.mitigationHeading': '緩和策',
  'threats.threatCard.complianceHeading': 'コンプライアンス',
  'threats.threatCard.referencesHeading': '出典',
  'threats.threatCard.controlStatusHeading': '対策実装状況',
  'threats.threatCard.riskTreatmentHeading': 'リスク対応方針',
  'threats.threatCard.editButton': '編集',
  'threats.threatCard.collapse': '折りたたむ',
  'threats.threatCard.deleteButton': '削除',

  // ── ManualThreatModal ──
  'threats.manualThreatModal.editTitle': 'シナリオを編集',
  'threats.manualThreatModal.addTitle': 'シナリオを追加',
  'threats.manualThreatModal.close': '閉じる',
  'threats.manualThreatModal.frameworkLabel': 'フレームワーク',
  'threats.manualThreatModal.frameworkFixedHint': '作成時に固定されます',
  'threats.manualThreatModal.categoryLabel': '脅威カテゴリ / タイトル',
  'threats.manualThreatModal.categoryPlaceholder': '例: 内部不正による顧客データ持ち出し',
  'threats.manualThreatModal.severityLabel': '深刻度',
  'threats.manualThreatModal.targetLabel': '対象',
  'threats.manualThreatModal.targetOptionWhole': 'プロジェクト全体（ノード未指定）',
  'threats.manualThreatModal.targetGroupType': '型: {label}（同型ノード全てに適用）',
  'threats.manualThreatModal.targetGroupNode': '配置済みノード（このインスタンスのみ）',
  'threats.manualThreatModal.targetTypeHint':
    '型を選ぶと、アクティブレイヤー上の同型ノード全てに適用されるプロジェクトローカルな カスタムルールになります。',
  'threats.manualThreatModal.descriptionLabel': '脅威の内容',
  'threats.manualThreatModal.descriptionPlaceholder':
    '想定される攻撃シナリオ・前提条件・影響を記述します。',
  'threats.manualThreatModal.mitigationLabel': '緩和策（任意）',
  'threats.manualThreatModal.mitigationPlaceholder': 'この脅威への対策・統制を記述します。',
  'threats.manualThreatModal.cancel': 'キャンセル',

  // ── ControlStatusEditor / RiskTreatmentEditor 共通 ──
  'threats.editor.current': '現在:',
  'threats.editor.unset': '未設定',
  'threats.editor.reset': '解除',
  'threats.editor.save': '保存',

  // ── ControlStatusEditor ──
  'threats.controlStatusEditor.notePlaceholderRequired': '理由・実装方法を記録（必須）',
  'threats.controlStatusEditor.notePlaceholderOptional': '補足（任意）',
  'threats.controlStatusEditor.noteRequiredWarning': '「{label}」は note が必須です。',
  'threats.controlStatusEditor.changedBy': '変更者: {by}',

  // ── RiskTreatmentEditor ──
  'threats.riskTreatmentEditor.notePlaceholder': '判断の根拠・残留リスクの補足など（任意）',

  // ── controlStatusStyle（対策実装状況ラベル。controlStatusStyle.ts はフック不可のためキーのみ保持） ──
  'threats.controlStatus.implemented': '実装済み',
  'threats.controlStatus.required': '必須',
  'threats.controlStatus.notApplicable': '適用外',
  'threats.controlStatus.rejected': '拒否',

  // ── riskTreatmentStyle（リスク対応方針ラベル。riskTreatmentStyle.ts はフック不可のためキーのみ保持） ──
  'threats.riskTreatment.avoid': '回避',
  'threats.riskTreatment.reduce': '低減',
  'threats.riskTreatment.transfer': '移転',
  'threats.riskTreatment.accepted': '受容',
  'threats.riskTreatment.falsePositive': '誤検知',

  // ── ThreatListPanel ──
  'threats.list.addScenario': 'シナリオ追加',
  'threats.list.suppressedShow': '抑制済み {count} 件を表示',
  'threats.list.suppressedHide': '抑制済み {count} 件を非表示',
  'threats.list.verifiedOnly': '実証された攻撃手段 {count} 件だけを表示',
  'threats.list.attemptedOnly': '試行された攻撃手段 {count} 件だけを表示',
  'threats.list.verifiedShowAll': 'すべての脅威を表示',
  'threats.list.empty': '脅威は検出されませんでした',
  'threats.list.typeTarget': '{type}型（該当ノードなし）',
  'threats.list.wholeProject': 'プロジェクト全体',
} as const;
