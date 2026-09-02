# コントリビュートガイド

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
npm test             # テスト一括実行
npm run build        # 本番ビルド
```

Pull Request を出す前に、型チェックとテストが通ることを確認してください。
これらは CI（`.github/workflows/ci.yml`）でも実行されます。

## 脅威ルールを追加する

脅威ルールは `data/threat-library/` 配下の YAML で管理しています。詳細は
README の [脅威ライブラリ](README.md#脅威ライブラリ) を参照してください。

新しいルールの PR では、以下を本文に記載してください。

- 追加するルールが**どの外部ソース（フレームワーク・ガイドライン）に基づくか**と、その参照箇所
- 既存ルールと重複する場合、なぜ別ルールとして立てるのか

## 翻訳

UI 文言は i18n 経由で管理しています。現在は日本語が既定で、英語は一部のみ対応して
います。英語リソースの拡充は歓迎します。

## ライセンス

コントリビュートされた内容は、本プロジェクトのライセンスである
[Apache License 2.0](LICENSE) の下で配布されます。
