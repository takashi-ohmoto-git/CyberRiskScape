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
| **Claude Code**（作業ディレクトリ） | 作業ディレクトリの取り込み（`import-repo`。package.json・requirements.txt・.env・.mcp.json・`.claude/` の設定。`.claude/` 以外のエージェントの設定は読まない） | 開発環境と依存パッケージの構成図を自動で作る・依存と権限設定の変化を PR で見張る | [Claude Codeの作業ディレクトリから脅威モデルを作成する](repo-import.ja.md) |
| **GitHub Copilot**（VS Code・コーディングエージェント） | MCP | Issue から構成図の更新と脅威の確認まで任せる | [MCP 導入ガイド](mcp-integration.ja.md)・[ユースケース](mcp-use-cases.ja.md)（§5） |
| **Cursor** | MCP | エディタ内で脅威を問い合わせる | [MCP 導入ガイド](mcp-integration.ja.md)・[ユースケース](mcp-use-cases.ja.md)（§6） |
| **Snyk** | MCP（エージェント経由で併用） | 脅威モデルの重要脅威と、コードの脆弱性診断の結果を突き合わせる | [ユースケース](mcp-use-cases.ja.md)（§7） |
| **GitHub Actions** | CLI・GitHub Action | 構成図の差分から新しい脅威を検出して PR を止める・実行トリガーで見直しを求める | [AI駆動開発のCIに組み込む](ci-integration.ja.md) |
| **Kong AI Gateway** | 設定ファイルの取り込み（decK の kong.yaml・AI Gateway 2.x の kongctl 宣言ファイル） | 設定から構成図を自動生成する・設定の変更で出る新しい脅威を PR で見張る | [Kong AI Gateway を脅威モデリングする](kong-ai-gateway.ja.md) |
| **Postman**（Postman CLI・Newman） | 検証用リクエストの書き出し（Collection v2.1） | 検出した脅威が実装でも成立するかを確かめ、CI で回帰テストにする | [脅威を Postman で確かめる](postman.ja.md) |
| **MITRE ATT&CK Navigator**（レイヤーを取り込める BAS・CTEM・SOC のツール） | Navigator レイヤーの書き出し（JSON） | 攻撃シナリオの経路で模擬する technique を渡し、図で切った経路が実機でも塞がっているかを確かめる | [攻撃経路のどこを切るか](agentic-attacker-paths.ja.md)（§6） |
| **Salesforce Agentforce** | 専用のステンシル・脅威ルール・テンプレート | Service agent の構成を評価する・エージェント定義の変更を PR で見張る | [Salesforce Agentforce を脅威モデリングする](agentforce.ja.md) |
| **Celonis**（プロセスマイニング） | 専用の型（業務自動化 / iPaaS・分析基盤 / DWH）・脅威ルール・テンプレート・業務の重要度の取り込み（共通の表・`convert-celonis`）・MCP（併用）・イベントログの書き出し（`export-event-log`。脅威への対応のプロセスマイニング） | 抽出・書き戻し・MCP を含む構成を評価する・データ単位の権限と資格情報の集約を確かめる・止まると困る業務を担うシステムを推奨標的と優先度に反映する | [Celonis を使う構成を脅威モデリングする](celonis.ja.md) |
| **Okta** | MCP（エージェント経由で併用）・専用のステンシルと脅威ルール | 図の NHI と実在するサービスアプリを突き合わせる・認証方式で ID の強度を確かめる・使われていない NHI を探す | [NHI と ID 基盤を脅威モデリングする](nhi-identity.ja.md) |
| **SailPoint** | MCP（エージェント経由で併用）・IGA のステンシルと脅威ルール | 過剰な権限の代わりに、申請できる最小のアクセスを探す | [NHI と ID 基盤を脅威モデリングする](nhi-identity.ja.md) |
| **CyberArk（Idira）** | Conjur ポリシーの取り込み・MCP（エージェント経由で併用）・PAM のステンシルと脅威ルール | ポリシーから NHI とシークレットの読み取り経路の図を作る・図の NHI と Secrets Manager のワークロードを突き合わせる | [NHI と ID 基盤を脅威モデリングする](nhi-identity.ja.md) |
| **ScopeSentry** | 書き出しの取り込み（Export の JSON）・API の取り込み（MCP・読み取りのみ） | 自前の ASM の資産・脆弱性・乗っ取り報告から露出の図を自動で作る・サブドメイン乗っ取りを評価する・定期の取り込みの差分で新しい露出を検知する | [ScopeSentry の観測結果を構成図にする](scopesentry.ja.md) |
| **Shodan** | 書き出しの取り込み（`shodan download` の .json.gz） | 外部に露出したサービスの図を自動で作る・前回の取り込みとの差分で新しく開いたポートを検知する・CISA の 4 ステップに沿って露出を減らす | [インターネット露出を減らす](exposure-reduction.ja.md) |
| **Anthropic `defending-code-reference-harness`** | `THREAT_MODEL.md` 互換の書き出し | 脅威モデルを、AI による脆弱性診断の入力にする | [Security Context に変換する](security-context.ja.md) |
| **Veracode** | 構成例（Veracode CLI・Findings API と、`THREAT_MODEL.md`・`findings-report`・Postman 書き出しの組み合わせ） | SAST・DAST の指摘を AI で修正する流れに、脅威モデルを前提知識・優先順位・回帰テストとして組み込む・Postman 書き出しを DAST の検査範囲にする | [Veracode の指摘を AI で直す](veracode-remediation.ja.md) |
| **Prowler** | 検査結果の取り込み（`import-prowler`。AWS の検査の OCSF 出力・CLI のみ） | 「未入力のため仮定」の運用状況・攻撃面属性を実測に置き換える・FAIL の検査を図の脅威と突き合わせる | [Prowler の検査結果を構成図に載せる](prowler.ja.md) |
| **Microsoft Threat Modeling Tool** | .tm7 の取り込み（`import-tm7`・画面の Import）・移行レポート（`migration-report`） | TMT の図・モデル情報・脅威と判断を移し、TMT の脅威と検出脅威の重なり・判断の見直し候補を見る | [Microsoft Threat Modeling Tool の脅威モデルを移行する](threat-modeling-tool.ja.md) |
| **Trivy** | 結果の取り込み（脆弱性は CycloneDX を `import-sbom`、IaC の設定不備・シークレットは SARIF を `import-sarif`。CLI のみ） | 依存パッケージの脆弱性を部品としてノードに結び、KEV と攻撃経路で優先順位を付ける・設定不備とシークレットをノードの指摘として持つ | [OSS で組む脆弱性管理](oss-vulnerability-management.ja.md) |
| **Syft / Grype** | SBOM・脆弱性の取り込み（CycloneDX を `import-sbom`。CLI のみ） | Syft の SBOM を部品の台帳にし、Grype の脆弱性を部品に結んで KEV と攻撃経路で優先順位付けする | [OSS で組む脆弱性管理](oss-vulnerability-management.ja.md) §8 |
| **ZAP** | 診断結果の取り込み（Automation Framework の `sarif-json` を `import-sarif`。CLI のみ） | 動いているアプリの指摘を、CWE の対応表で図の脅威と対応づける | [OSS で組む脆弱性管理](oss-vulnerability-management.ja.md) §5 |
| **Nuclei** | 結果の取り込み（`import-nuclei`。JSONL / JSON。CLI のみ） | CVE の指摘を KEV と攻撃経路で優先順位付けする・CWE の指摘を図の脅威と対応づける | [OSS で組む脆弱性管理](oss-vulnerability-management.ja.md) §6 |
| **Strix** | 結果の変換（`convert-strix`。findings.sarif → ペンテストの台帳 YAML → `import-pentest`。CLI のみ）・文脈の受け渡し（RoE・THREAT_MODEL.md を `--instruction-file`、CRS の MCP サーバーを読み取りのツールだけ許可して登録） | PoC で確かめた結果を脅威カードに「Strix で実証」として載せる・診断中に脅威モデルを引かせる | [OSS で組む脆弱性管理](oss-vulnerability-management.ja.md) §7 |
| **Metasploit** | 書き出しの変換・取り込み（`db_export -f xml` を `convert-metasploit` → `import-pentest`、ホストとサービスは `import-metasploit-assets`。CLI のみ） | 攻撃が通った脆弱性を脅威カードに「実証」として載せる・ホストとサービスを Asset タブに載せる | [OSS で組む脆弱性管理](oss-vulnerability-management.ja.md) §9 |
| **CyberStrikeAI** | 脆弱性の変換（`convert-cyberstrikeai`。API の応答を保存した JSON、または API（GET のみ・トークンは環境変数）→ ペンテストの台帳 YAML → `import-pentest`）・資産の取り込み（`import-aipentest-assets --format cyberstrikeai`。Asset タブに表示。CLI のみ） | AI 自律ペンテストで人が confirmed にした脆弱性を、脅威カードに「実証」として載せる。どの脅威・ノードかは人が台帳で決める | [OSS で組む脆弱性管理](oss-vulnerability-management.ja.md) §4 |
| **CycloneDX・SPDX** | 部品の取り込み（`import-sbom`。CLI のみ）・書き出し（`export-spdx`・`export-sbom-ai`。画面からも可） | SBOM・CBOM・AI BOM の部品をノードに結びつけ、Asset タブで確かめて、標準形式で書き出す（[ガイド](sbom.ja.md)） |
| **Cisco AI Defense**（skill-scanner / mcp-scanner） | 検査結果の突き合わせ（`findings-report --skill-scanner / --mcp-scanner`。結果ファイル・CLI のみ） | エージェントスキル・MCP サーバーの検査結果を、AITech 対応表を介して図の脅威と突き合わせる・描き漏れを見つける | [エージェントスキル・MCP サーバーの検査結果を脅威モデルと突き合わせる](ai-scanners.ja.md) |
| **Cloudflare security-audit**（スキル） | 指摘の取り込み（`findings.json`・`coverage-ledger.json`。画面と CLI `import-security-audit`） | ソースで実証した指摘と、配置を確かめないと決まらない要確認を脅威カードに出し、要確認の前提を図の事実と並べる | [AI によるソース監査の指摘を構成図に載せる](security-audit.ja.md) |
| **Velociraptor** | 収集結果（展開したフォルダー）の取り込み・調査計画書への artifact の手がかり・EDR / DFIR サーバーのステンシルと脅威ルール | 侵害が疑われるときに、攻撃経路上のノードで集める artifact を決め、収集結果をノードに重ねて報告する | [侵害の疑いがあるときに、脅威モデルで調べる範囲を決め、結果を報告する](compromise-investigation.ja.md) |

---

## 目的から選ぶ

| やりたいこと | 使う連携 |
|---|---|
| AI エージェントに脅威モデリングを手伝わせたい | MCP（Claude Code・GitHub Copilot・Cursor） |
| 脅威モデルの更新漏れを PR で防ぎたい | GitHub Actions |
| 既存の設定から構成図を起こしたい | Kong AI Gateway・CyberArk（Idira）Conjur・Shodan・ScopeSentry・Claude Code の作業ディレクトリ（`import-repo`） |
| 指摘した脅威が本当に塞がっているか確かめたい | Postman |
| ペネトレーションテストの範囲と重点を決めたい | テスト計画書の書き出し（[ガイド](pentest-plan.ja.md)。業者を問わない） |
| 図で切った攻撃経路を、BAS で模擬して確かめたい | ATT&CK Navigator レイヤーの書き出し（[ガイド](agentic-attacker-paths.ja.md) §6） |
| AI ペンテストツールを自社で運用する前に、診断してよい範囲を宣言したい | 交戦規定（RoE）／スコープ宣言の書き出し（[ガイド](agentic-pentest-operation.ja.md) §5） |
| 製品固有の構成をそのまま評価したい | Salesforce Agentforce |
| プロセスマイニング・iPaaS・DWH を含む構成を評価したい | Celonis |
| サービスアカウントや AI エージェントなど NHI のリスクを洗い出したい | Okta・SailPoint・CyberArk（Idira） |
| インターネットに出ている資産を棚卸しして減らしたい | Shodan |
| 脅威モデルを脆弱性診断に活かしたい | Anthropic `defending-code-reference-harness`・Snyk |
| 脆弱性診断の指摘を AI で直す流れを作りたい | Veracode |
| クラウドの検査結果（AWS）を図の属性に反映したい | Prowler |
| OSS の診断ツールの結果を、攻撃経路の上で優先順位を付けて管理したい | Trivy・Syft / Grype・ZAP・Nuclei・CyberStrikeAI・Strix・Metasploit（[ガイド](oss-vulnerability-management.ja.md)） |
| ペンテストで実際に通った攻撃手段を脅威カードに載せたい | Strix・CyberStrikeAI・Metasploit（[ガイド](oss-vulnerability-management.ja.md)） |
| エージェントスキル・MCP サーバーの検査結果を図と突き合わせたい | Cisco AI Defense（skill-scanner / mcp-scanner） |
| AI にソースを監査させた指摘を、実証と要確認に分けて図に載せたい | Cloudflare security-audit |
| 侵害が疑われるときに、調べる範囲を決めて結果を報告したい | Velociraptor・同梱のトリアージスクリプト（[ガイド](compromise-investigation.ja.md)） |

---

## 次に読むもの

- まず全体を知る — [はじめに](getting-started.ja.md)
- MCP をつなぐ — [コーディングエージェントから使う](mcp-integration.ja.md)
- ガイドの一覧 — [CyberRiskScape ガイド](README.ja.md)
