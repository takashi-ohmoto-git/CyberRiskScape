# CyberRiskScape ガイド

[English](README.md) | **日本語**

CyberRiskScape を使う人のためのドキュメントです。
プロジェクトの概要・機能一覧・ビルド方法は[リポジトリの README](../README.ja.md) を参照してください。

インストールは不要です。[オンラインデモ](https://takashi-ohmoto-git.github.io/CyberRiskScape/)を
開けば、そのまま手を動かしながら読めます。

## ページ一覧

| ページ | 内容 |
|---|---|
| **[はじめに — CyberRiskScape 入門](getting-started.ja.md)** | ツールの目的と画面構成、キャンバス操作のすべて（コンポーネントの配置・接続・トラスト境界・ズーム／パン）を画面付きで説明 |
| **[はじめての脅威モデル](first-threat-model.ja.md)** | AI チャットボットを題材に、プロジェクト作成・深度レイヤーの選択・配置・接続・トラスト境界までを通しで作図するチュートリアル |
| **[テンプレートを作る・使う](templates.ja.md)** | 図を JSON で書き出し・読み込みする方法と、このガイドの AI チャットボット構成テンプレート |
| **[脅威パネルの読み方](reading-threats.ja.md)** | 検出された脅威をどう読み、リスク評価で優先順位を付け、対応方針を記録し、エクスポートするか |
| **[Analytics でリスクを評価する](analytics-assessment.ja.md)** | リスク評価・リスク対応方針・対策実装状況を 1 画面で検討し、記録する手順 |
| **[PDF レポートと構成図（PNG）を出力する](report-export.ja.md)** | CISO・経営層への報告用 PDF（1 枚サマリ・上位 10・レイヤー別付録）と、構成図の PNG 画像を出力する手順と、指標の読み方 |
| **[攻撃経路分析](attack-paths.ja.md)** | 攻撃者から標的までの到達経路を列挙し、チョークポイント（1 つの対策が最も多くの経路に効く場所）を特定する |
| **[コンプライアンスマップ](compliance-map.ja.md)** | 脅威と NIST CSF / NIST AI RMF / AI 事業者ガイドラインの対応を、脅威側・規格側の両方から確認する |
| **[脅威モデルを AI が読める Security Context に変換する](security-context.ja.md)** | 完成した脅威モデルを Markdown で書き出し、AI による脆弱性診断の入力として使う手順と、それが効く理由 |
| **[連携ガイド](integrations.ja.md)** | 連携できる製品（Claude Code・GitHub Copilot・Cursor・Snyk・GitHub Actions・Kong・Postman・Salesforce Agentforce 等）と連携の方法（MCP・ファイルと CLI）、ユースケースの一覧。各製品のページへの入口 |
| **[AI駆動開発のCIに組み込む](ci-integration.ja.md)** | 保存済みプロジェクト JSON を正本ファイルとして扱う：ヘッドレス CLI・GitHub Action・実行トリガーに基づくレビュー・CODEOWNERS とブランチ保護・閉域環境での使い方 |
| **[コーディングエージェントから使う](mcp-integration.ja.md)** | Claude Code・GitHub Copilot などのエージェントが脅威の問い合わせと構成図の更新をできるようにする MCP サーバーの導入：クライアント別の設定・ツール一覧・安全のための仕組み・PR の差分ゲートとの組み合わせ |
| **[ユースケースで学ぶ MCP 連携](mcp-use-cases.ja.md)** | MCP を使う場面別の実践：設計初期の調査・重要脅威の実装タスク化・コンポーネント追加の影響確認・PR 前のセルフレビュー・GitHub Copilot／Cursor での使い方・Snyk との組み合わせ・許可範囲の決め方 |
| **[Salesforce Agentforce を脅威モデリングする](agentforce.ja.md)** | Agentforce の構成要素と CyberRiskScape の型の対応、顧客向け Service agent の構成図テンプレート、外部から書き込める CRM 項目を経由する間接プロンプトインジェクション（ForcedLeak 型）など押さえたい脅威と、検出されるルール・されないこと、エージェント定義の変更を PR で見張る方法 |
| **[Kong AI Gateway を脅威モデリングする](kong-ai-gateway.ja.md)** | Kong Gateway の宣言設定（decK の kong.yaml）から構成図の下書きを自動で作る方法（画面・CLI）、設定と型の対応、AI Gateway の構成で押さえたい脅威（認証のない Route・MCP として公開したツール・ガードレールの限界・RAG・管理プレーン）と、kong.yaml の変更を PR で見張る方法 |
| **[NHI と ID 基盤を脅威モデリングする](nhi-identity.ja.md)** | サービスアカウント・ワークロードID・OAuthクライアント・RPAボット、特権アクセス管理（PAM）・ID ガバナンス（IGA）の描き方と、OWASP NHI Top 10 にもとづく脅威。Okta・SailPoint・CyberArk（Idira）の MCP サーバーと組み合わせて、図と実際の ID の状態を突き合わせる方法 |
| **[インターネット露出を減らす](exposure-reduction.ja.md)** | CISA の「Internet Exposure Reduction Guidance」の 4 ステップ（把握・必要性の判断・リスクの低減・定期評価）に沿って、Shodan・Censys で見つけた露出（Web・VPN・RDP・データベース・ローカル LLM）を構成図に描き（Shodan は書き出しから自動生成）、対応前後の脅威の差で効果を示し、定期評価で露出の再発を CLI で検知する方法 |
| **[脅威を Postman で確かめる](postman.ja.md)** | 検出した脅威のうち HTTP で確かめられるもの（認証なし・平文・BOLA・BFLA・レート制限・管理面・プロンプトインジェクション・システムプロンプト開示・MCP のツール記述子）について、確認リクエストを Postman Collection で書き出し、Postman・Postman CLI・Newman で実行して対策を確かめる方法 |
| **[Secure by Design 入門](secure-by-design.ja.md)** | 背景にある考え方。Secure by Design とは何か、なぜ今求められるのか、脅威モデリングが担う 4 つの役割、そして経営層・企画・セキュリティ・監査・CI が 1 つの脅威モデルを共有する Security Context Layer としての CyberRiskScape の役割。CISA 主導の国際共同ガイダンスに基づく |

## どこから読むか

- **まず触ってみたい** — [はじめに](getting-started.ja.md) から。
- **手を動かして 1 つ作り切りたい** — [はじめての脅威モデル](first-threat-model.ja.md) へ。
- **描く手間を省いて先に進みたい** — [テンプレート](templates.ja.md)を読み込んでください。
- **図は描けたが、出てきた脅威の扱いが分からない** — [脅威パネルの読み方](reading-threats.ja.md) へ。
- **脅威を評価して記録したい** — [Analytics でリスクを評価する](analytics-assessment.ja.md) へ。
- **経営層・CISO への報告資料を作りたい** — [PDF レポートと構成図（PNG）を出力する](report-export.ja.md) へ。
- **対策をどこから手を付けるか決めたい** — [攻撃経路分析](attack-paths.ja.md) へ。
- **規格・ガイドラインとの対応を確認したい** — [コンプライアンスマップ](compliance-map.ja.md) へ。
- **作った脅威モデルを AI の脆弱性診断に使いたい** —
  [脅威モデルを AI が読める Security Context に変換する](security-context.ja.md) へ。
- **脅威モデルを正本ファイルとして CI に組み込み、人のレビューに乗せたい** —
  [AI駆動開発のCIに組み込む](ci-integration.ja.md) を読んでください。
- **コーディングエージェントに脅威を問い合わせさせ、構成図も更新させたい** —
  [コーディングエージェントから使う](mcp-integration.ja.md) へ。
- **ほかのツールや製品とつなぎたい** — [連携ガイド](integrations.ja.md) で、連携できる製品と方法を一覧できます。
- **Salesforce Agentforce の構成を脅威モデル化したい** — [Salesforce Agentforce を脅威モデリングする](agentforce.ja.md) へ。
- **Kong Gateway（AI Gateway）の構成を脅威モデル化したい** — [Kong AI Gateway を脅威モデリングする](kong-ai-gateway.ja.md) へ。kong.yaml から図の下書きを作れます。
- **サービスアカウントや AI エージェントなど NHI のリスクを洗い出したい** — [NHI と ID 基盤を脅威モデリングする](nhi-identity.ja.md) へ。
- **インターネットに出ている資産を棚卸しして減らしたい** — [インターネット露出を減らす](exposure-reduction.ja.md) へ。Shodan・Censys の結果から始められます。
- **検出した脅威が実装でも成立するか確かめたい** — [脅威を Postman で確かめる](postman.ja.md) へ。
- **この取り組みの意義を誰かに説明したい** — [Secure by Design 入門](secure-by-design.ja.md) は
  単独で読める内容になっています。

各ページは日本語版と英語版があります。切り替えはページ冒頭の言語リンクからどうぞ。

なお「はじめての脅威モデル」以降の章は、すべて**同じ AI チャットボットの構成図**（往復フロー・脅威 48 件）を題材にしています。
章をまたいでも同じ図・同じ脅威を追いかけられます（「はじめに」だけは、初回起動時の
サンプル図をそのまま使っています）。
