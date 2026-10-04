# 連携ガイド — 開発・API・AI 基盤のツールとつなぐ

[English](integrations.md) | **日本語**

CyberRiskScape の脅威モデルは、図の中だけで終わらせず、設計・実装・検証で使うツールとつなげられます。
このページは、連携できる製品とユースケースの一覧です。詳しい手順は各ページを参照してください。

> 各製品名はそれぞれの所有者の商標です。各ページは CyberRiskScape での使い方を説明するもので、
> 製品の提供元が提供・認定・推奨するものではありません。

---

## 連携のしかた

### MCP で、AI エージェントから直接つなぐ

CyberRiskScape は **MCP（Model Context Protocol）サーバーを内蔵**しています。MCP に対応した AI エージェント
（Claude Code・GitHub Copilot・Cursor など）に登録すると、エージェントが設計中に脅威を問い合わせ、
構成図の更新を提案できます。他社の MCP サーバー（Snyk など）と同じエージェントに並べて使うこともできます。

導入手順は **[コーディングエージェントから使う — MCP サーバー導入ガイド](mcp-integration.ja.md)** を参照してください。

- 外部への通信は行いません（閉域環境でも動きます）
- 読み書きできるのは指定したディレクトリの中だけで、リスクの受容や評価の変更はできません。
  最終判断は人が PR で行います

### ファイルと CLI でつなぐ

設定ファイルの取り込み、検証用リクエストの書き出し、CI での差分判定は、ファイルと CLI（`dist-cli/main.js`）で行います。
いずれも製品の API を呼び出さないため、API キーや有償のプランは不要です。

---

## 連携できる製品

| 製品 | 連携の方法 | ユースケース | ページ |
|---|---|---|---|
| **Claude Code** | MCP | 設計中に脅威を調べる・構成図を更新する・PR 前にセルフレビューする | [MCP 導入ガイド](mcp-integration.ja.md)・[ユースケース](mcp-use-cases.ja.md) |
| **GitHub Copilot**（VS Code・コーディングエージェント） | MCP | Issue から構成図の更新と脅威の確認まで任せる | [MCP 導入ガイド](mcp-integration.ja.md)・[ユースケース](mcp-use-cases.ja.md)（§5） |
| **Cursor** | MCP | エディタ内で脅威を問い合わせる | [MCP 導入ガイド](mcp-integration.ja.md)・[ユースケース](mcp-use-cases.ja.md)（§6） |
| **Snyk** | MCP（エージェント経由で併用） | 脅威モデルの重要脅威と、コードの脆弱性診断の結果を突き合わせる | [ユースケース](mcp-use-cases.ja.md)（§7） |
| **GitHub Actions** | CLI・GitHub Action | 構成図の差分から新しい脅威を検出して PR を止める・実行トリガーで見直しを求める | [AI駆動開発のCIに組み込む](ci-integration.ja.md) |
| **Kong AI Gateway** | 設定ファイルの取り込み（decK の kong.yaml） | 設定から構成図を自動生成する・設定の変更で出る新しい脅威を PR で見張る | [Kong AI Gateway を脅威モデリングする](kong-ai-gateway.ja.md) |
| **Postman**（Postman CLI・Newman） | 検証用リクエストの書き出し（Collection v2.1） | 検出した脅威が実装でも成立するかを確かめ、CI で回帰テストにする | [脅威を Postman で確かめる](postman.ja.md) |
| **Salesforce Agentforce** | 専用のステンシル・脅威ルール・テンプレート | Service agent の構成を評価する・エージェント定義の変更を PR で見張る | [Salesforce Agentforce を脅威モデリングする](agentforce.ja.md) |
| **Okta** | MCP（エージェント経由で併用）・専用のステンシルと脅威ルール | 図の NHI と実在するサービスアプリを突き合わせる・認証方式で ID の強度を確かめる・使われていない NHI を探す | [NHI と ID 基盤を脅威モデリングする](nhi-identity.ja.md) |
| **SailPoint** | MCP（エージェント経由で併用）・IGA のステンシルと脅威ルール | 過剰な権限の代わりに、申請できる最小のアクセスを探す | [NHI と ID 基盤を脅威モデリングする](nhi-identity.ja.md) |
| **CyberArk（Idira）** | Conjur ポリシーの取り込み・MCP（エージェント経由で併用）・PAM のステンシルと脅威ルール | ポリシーから NHI とシークレットの読み取り経路の図を作る・図の NHI と Secrets Manager のワークロードを突き合わせる | [NHI と ID 基盤を脅威モデリングする](nhi-identity.ja.md) |
| **Shodan・Censys** | 検索結果を構成図に描く（ファイル・API の連携なし） | CISA の 4 ステップに沿って外部露出を棚卸しし、減らした効果を示し、定期評価で再発を検知する | [インターネット露出を減らす](exposure-reduction.ja.md) |
| **Anthropic `defending-code-reference-harness`** | `THREAT_MODEL.md` 互換の書き出し | 脅威モデルを、AI による脆弱性診断の入力にする | [Security Context に変換する](security-context.ja.md) |

---

## 目的から選ぶ

| やりたいこと | 使う連携 |
|---|---|
| AI エージェントに脅威モデリングを手伝わせたい | MCP（Claude Code・GitHub Copilot・Cursor） |
| 脅威モデルの更新漏れを PR で防ぎたい | GitHub Actions |
| 既存の設定から構成図を起こしたい | Kong AI Gateway |
| 指摘した脅威が本当に塞がっているか確かめたい | Postman |
| 製品固有の構成をそのまま評価したい | Salesforce Agentforce |
| サービスアカウントや AI エージェントなど NHI のリスクを洗い出したい | Okta・SailPoint・CyberArk（Idira） |
| インターネットに出ている資産を棚卸しして減らしたい | Shodan・Censys |
| 脅威モデルを脆弱性診断に活かしたい | Anthropic `defending-code-reference-harness`・Snyk |

---

## 次に読むもの

- まず全体を知る — [はじめに](getting-started.ja.md)
- MCP をつなぐ — [コーディングエージェントから使う](mcp-integration.ja.md)
- ガイドの一覧 — [CyberRiskScape ガイド](README.ja.md)
