# コントリビュートガイド

[English](CONTRIBUTING.md) | **日本語**

Issue と Pull Request を歓迎します。

## 基本ルール

- **脅威ルールはコードにハードコードせず**、`data/threat-library/` の YAML に追加する
- 新しいルールには **出典を明記** し、原文の逐語転載を避けて要約に留める
- ロジックの変更にはテストを添える
- コミットメッセージは [Conventional Commits](https://www.conventionalcommits.org/) に従う

## 開発の流れ

```bash
npm install
npm run dev          # 開発サーバ起動
npx tsc --noEmit     # 型チェック（strict）
npm run lint         # ESLint（warn のみ。CI は総数の上限で判定。設定は eslint.config.js）
npm test             # テスト一括実行
npm run build        # 本番ビルド
```

Pull Request を出す前に、型チェックとテストが通ることを確認してください。
これらは CI（`.github/workflows/ci.yml`）でも実行されます。

## 脅威ルールを追加する

脅威ルールは `data/threat-library/` 配下の YAML で管理しています。既存ファイルと
その構造は [`data/threat-library/`](data/threat-library) を参照してください。

新しいルールの PR では、以下を本文に記載してください。

- 追加するルールが**どの外部ソース（フレームワーク・ガイドライン）に基づくか**と、その参照箇所
- 既存ルールと重複する場合、なぜ別ルールとして立てるのか

## 翻訳

現時点で最も助けが必要な領域です。

UI 文言は `src/i18n/` の自前 i18n 基盤（外部ライブラリ非依存）で管理しています。
`src/i18n/locales/ja.ts` が正で、`src/i18n/locales/en.ts` が部分的に上書きし、
未定義キーは日本語にフォールバックします。未着手の課題は 2 つです。

- **`en.ts` の拡充**。翻訳できたキーから順に追加してください。部分的な対応で問題ありません
- **言語切替 UI**。locale ストア（`useLocale`）はありますが UI から設定する箇所がなく、
  起動時は常に日本語です。永続化は IndexedDB を使ってください
  （本プロジェクトは `localStorage` / `sessionStorage` を使いません）

脅威ルールの文言（`name` / `description` / `mitigation`）は日本語です。`data/threat-library/i18n/en/`
にルール ID を鍵とする翻訳オーバーレイを置き、既存スキーマを変更せず、未翻訳は原文へ
フォールバックする方針を予定しています。着手前に形式を合意したいので、まず Issue を立ててください。

## ドキュメントの言語

**英語が正です。** 変更時に更新すべきは `README.md` / `CONTRIBUTING.md` / `SECURITY.md` で、
日本語版（`*.ja.md`）は要約として同期し、細部が遅れることを許容します（意図的な運用です）。
日本語版のみを更新した Pull Request には英語版の更新もお願いします。逆は必須ではありません。

## ライセンス

コントリビュートされた内容は、本プロジェクトのライセンスである
[Apache License 2.0](LICENSE) の下で配布されます。
