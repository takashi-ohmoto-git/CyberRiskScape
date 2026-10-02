/**
 * CLI `triggers` サブコマンド（実行トリガー チェックリスト）の文言（日本語 = 真実）。
 * 集約は ../ja.ts。キー規約は ../../locales/ja.ts の冒頭コメントを参照。
 */
export const jaCliTriggers = {
  'cliTriggers.heading': '# 脅威モデリングの実行トリガー チェックリスト',
  'cliTriggers.intro':
    'このPRで脅威モデルの更新が必要かどうかを確認してください。該当する項目にチェックを入れ、必要なら脅威モデルを更新してください。',

  'cliTriggers.section.auto': '## モデル差分で自動判定できる項目',
  'cliTriggers.section.manual': '## 人（または AI レビュアー）による確認が必要な項目（モデル差分では自動判定できません）',
} as const;
