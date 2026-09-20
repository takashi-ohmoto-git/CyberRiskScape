// ESLint フラット設定（最小構成）
//
// 方針：目的は「新規混入の抑止」であり既存コードの一斉修正ではない。
// 既に存在する違反（デザイン規約の極小文字など）は warn に留め、CI を止めない。
// Prettier は未導入（整形はエディタに委ねる）。

import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import globals from 'globals';

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**'] },

  js.configs.recommended,
  ...tseslint.configs.recommended,

  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      globals: globals.browser,
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      // tsc が原理的に検出できない依存配列の漏れを拾う
      'react-hooks/rules-of-hooks': 'warn',
      'react-hooks/exhaustive-deps': 'warn',

      // `_` 始まりは意図的な未使用（既存コードの慣習）
      '@typescript-eslint/no-unused-vars': [
        'warn',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' },
      ],

      // 診断目的の warn / error のみ許可。console.log の混入を止める
      'no-console': ['warn', { allow: ['warn', 'error'] }],

      'no-useless-assignment': 'warn',

      'no-restricted-syntax': [
        'warn',
        // docs/DesignPrinciples.md §6.1：本文の最小は 12px
        {
          selector: 'Literal[value=/text-\\[(8|9|10|11)px\\]/]',
          message:
            'DesignPrinciples §6.1：text-[8/9/10/11px] は禁止（最小 12px）。text-xs 以上を使う。',
        },
        {
          selector: 'TemplateElement[value.raw=/text-\\[(8|9|10|11)px\\]/]',
          message:
            'DesignPrinciples §6.1：text-[8/9/10/11px] は禁止（最小 12px）。text-xs 以上を使う。',
        },
        // eslint-plugin-react は入れないため react/no-danger 相当をここで持つ
        {
          selector: 'JSXAttribute[name.name="dangerouslySetInnerHTML"]',
          message:
            'dangerouslySetInnerHTML は XSS 経路。サニタイズ済みと確認できる場合のみ disable コメント付きで使う。',
        },
      ],
    },
  },

  // Node で実行される設定ファイル・補助スクリプト
  {
    files: ['*.config.{js,ts}', '.claude/**/*.mjs'],
    languageOptions: { globals: globals.node },
    rules: { '@typescript-eslint/no-require-imports': 'off' },
  },

  // テストは Vitest のグローバルを使う
  {
    files: ['**/*.test.{ts,tsx}'],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
  },
);
