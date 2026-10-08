# CyberRiskScape

**AI・LLM・エージェントシステム・PQC に対応した、OSS のビジュアル脅威モデリングツール**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Threat rules](https://img.shields.io/badge/threat%20rules-172-orange.svg)](data/threat-library)
[![Tests](https://img.shields.io/badge/tests-1033%20passing-brightgreen.svg)](#開発)
[![Demo](https://img.shields.io/badge/demo-live-blueviolet.svg)](https://takashi-ohmoto-git.github.io/CyberRiskScape/)

[English](README.md) | **日本語**

ブラウザ上でシステム構成図（DFD）を描くと、構成に応じた脅威が自動で列挙されます。
サーバ不要・完全ローカル動作で、設計データが外部に送信されることはありません。

**▶ オンラインデモ： https://takashi-ohmoto-git.github.io/CyberRiskScape/**
（インストール不要。ブラウザだけで試せます）

はじめて使う方は **[はじめに — CyberRiskScape 入門](guide/getting-started.ja.md)** をご覧ください。
ツールの目的・画面構成・キャンバス操作を画面付きで説明しています。
背景にある考え方は [Secure by Design 入門](guide/secure-by-design.ja.md) にまとめています。

---

## 特徴

### エージェント型 AI の脅威モデリングに対応

古典的な STRIDE に加えて、**AI エージェント・LLM・MCP サーバ・長期メモリ**といった
現代的な構成要素を第一級のコンポーネント型として扱います。

| フレームワーク区分 | ルール数 | 内容 |
|---|---:|---|
| `STRIDE` | 74 | 古典的な脅威（なりすまし・改ざん・情報漏えい 等） |
| `AI` | 33 | 敵対的 ML、モデル抽出、学習データ汚染 等 |
| `AgenticAI` | 42 | 目標乗っ取り、ツール誤用、権限の持ち越し、メモリ汚染 等 |

### エコシステム — 開発・API・ID 基盤とつながる

脅威モデルを図の中で終わらせず、設計・実装・検証で使うツールとつなぎます。**MCP サーバーを内蔵**し、
API ゲートウェイ・API テスト・ID 基盤・AI エージェント基盤とファイルベースで連携します。外部への通信は
行わないため、閉域環境でも使えます。

| 連携先 | できること |
|---|---|
| **MCP**（Claude Code・GitHub Copilot・Cursor など） | コーディングエージェントが設計中に脅威を問い合わせ、構成図を更新する（[ガイド](guide/mcp-integration.ja.md)） |
| **CI**（GitHub Actions） | 構成図の差分から新しい脅威を検出して PR を止め、結果を SARIF で出力する（[ガイド](guide/ci-integration.ja.md)） |
| **API ゲートウェイ**（Kong AI Gateway） | decK の設定から構成図を自動生成し、設定の変更を PR で見張る（[ガイド](guide/kong-ai-gateway.ja.md)） |
| **API テスト**（Postman・Postman CLI・Newman） | 検出した脅威を確かめる検証用リクエストを書き出す（[ガイド](guide/postman.ja.md)） |
| **ID 基盤・NHI**（Okta・SailPoint・CyberArk（Idira）・Microsoft Entra ID・Active Directory / LDAP） | IdP・ディレクトリ・NHI・PAM・IGA をモデル化して評価し、Conjur のポリシーから図を自動生成、各社の MCP サーバーと組み合わせて実際の ID の状態と突き合わせる（[ガイド](guide/nhi-identity.ja.md)） |
| **ASM・外部露出**（Shodan） | `shodan download` の書き出しから露出サービスの図を自動生成し、CISA の 4 ステップに沿って評価・削減、前回との差分で新しい露出を検知する（[ガイド](guide/exposure-reduction.ja.md)） |
| **AI エージェント基盤**（Salesforce Agentforce） | 専用のステンシル・脅威ルール・構成図テンプレートで評価する（[ガイド](guide/agentforce.ja.md)） |
| **AI による脆弱性診断**（Anthropic `defending-code-reference-harness`） | 脅威モデルを `THREAT_MODEL.md` 互換で書き出し、診断の入力にする（[ガイド](guide/security-context.ja.md)） |

連携できる製品と方法の一覧は [連携ガイド](guide/integrations.ja.md) を参照してください。

### 主な機能

- **ビジュアル DFD エディタ** — 66 種のコンポーネント型（10 ライブラリ・12 カテゴリ）、
  トラスト境界、データフローの暗号化区分・認証状態の表現
- **脅威の自動検出** — 配置しただけで発火する内在脅威と、接続条件つきで発火する
  経路依存脅威を区別して検出
- **攻撃経路グラフ分析** — 攻撃者から資産に至る経路を可視化し、チョークポイント
  （複数経路が集中する防御点）を特定
- **コンプライアンスマッピング** — 検出脅威を NIST CSF 2.0（128 項目）/
  NIST AI RMF（72 項目）/ AI 事業者ガイドライン（34 項目）に紐付け
- **リスク評価** — Impact × Likelihood スコアリング、リスク対応方針（低減・受容・移転・回避）の記録
- **カスタムルール** — UI 上のエディタから独自の脅威ルールを追加
- **脅威ライブラリ・インスペクタ** — どのルールがどの条件で発火するかを読み取り専用で確認
- **エクスポート** — 脅威一覧を CSV / JSON、および Anthropic 公式
  `defending-code-reference-harness` の `THREAT_MODEL.md` 互換 Markdown で出力。
  さらに、**PDF レポート**（1 枚の経営層向けサマリ＋詳細）と構成図の **PNG 画像**を、
  レイヤーを選んで出力（[ガイド](guide/report-export.ja.md)）
- **ローカル保存** — IndexedDB による自動保持と、File System Access API による
  ローカルファイルへの明示的な保存

---

## スクリーンショット

![CyberRiskScape のスクリーンショット](assets/screenshot.png)

左：コンポーネントパレットとライブラリ管理 ／ 中央：DFD キャンバスと凡例 ／
右：検出された脅威（発火条件・3 段階成熟度の緩和策・コンプライアンス対応・出典）

実際の動作は[オンラインデモ](https://takashi-ohmoto-git.github.io/CyberRiskScape/)で確認できます。

---

## 動作要件

| 項目 | 要件 |
|---|---|
| Node.js | 20 以上（開発・ビルド時のみ） |
| ブラウザ | Chromium 系（Chrome / Edge）を推奨 |

ローカルファイルへの保存機能は File System Access API を使うため、Chromium 系
ブラウザでのみ有効です。Firefox / Safari では当該機能が無効表示になりますが、
それ以外の機能はすべて利用できます。

---

## クイックスタート

```bash
git clone https://github.com/takashi-ohmoto-git/CyberRiskScape.git
cd CyberRiskScape
npm install
npm run dev
```

表示された URL（既定では http://localhost:5173）をブラウザで開きます。

本番ビルドは以下で生成できます。出力は静的ファイルのみなので、任意の静的ホスティング
に配置できます。

```bash
npm run build     # dist/ に出力
npm run preview   # ビルド成果物をローカルで確認
```

---

## 使い方

1. **コンポーネントを配置** — 左サイドバーから DFD 要素（ユーザー、LLM、エージェント、
   データストア 等）をキャンバスへ配置します
2. **接続を引く** — 要素間にデータフローを引き、暗号化区分・認証状態・
   セマンティクス（ツール呼び出し、メモリ書き込み 等）を設定します
3. **トラスト境界を描く** — 信頼境界を配置し、境界をまたぐ通信を明示します
4. **脅威を確認** — 構成に応じた脅威が自動で列挙されます。各脅威は「検出根拠」から
   発火条件・ルール ID・出典を辿れます
5. **評価と対応方針を記録** — リスク評価と対応方針（低減／受容／移転／回避）を
   入力します。誤検知は抑制できます
6. **エクスポート** — 脅威一覧を CSV / JSON / Markdown、PDF レポート、構成図の PNG で出力します

各ステップの具体的な操作方法は [はじめに — CyberRiskScape 入門](guide/getting-started.ja.md) に
画面付きでまとめています。

---

## 開発

```bash
npm run dev          # 開発サーバ起動
npm run build        # 本番ビルド
npm run preview      # ビルド成果物の確認
npm run test         # テスト一括実行
npm run test:watch   # テスト watch モード
npx tsc --noEmit     # 型チェック（strict）
```

変更後の標準的な検証は `npx tsc --noEmit` とテストの実行です。現在 1,033 件の
テストが通ります。

---

## CLI（プレビュー）

ブラウザなしで保存済みプロジェクト JSON を解析するヘッドレス CLI です。CI でのゲート
判定等に使えます。評価対象は同梱の脅威ルールのみです（IndexedDB に保存するカスタム
ルールは CLI からは参照できません）。

```bash
npm run build:cli
node dist-cli/main.js analyze <project.json> [options]
```

| オプション | 値 | 既定 |
|---|---|---|
| `--format` | `json` \| `sarif` \| `md` | `json` |
| `--layer` | `L0` \| `L1` \| `L2` \| `L3` | ノードがある全レイヤー |
| `--framework` | `STRIDE` \| `AI` \| `AgenticAI` \| `ALL` | `ALL` |
| `--fail-on` | `Critical` \| `High` \| `Medium` \| `Low` | 指定なし（ゲート判定なし） |
| `--locale` | `ja` \| `en` | `ja` |
| `--out` | 出力先ファイルパス | 標準出力 |

終了コード：`0` 成功 ／ `1` `--fail-on` によるゲート不合格 ／ `2` 入力・引数エラー。

### モデル差分ゲート（`diff`）

保存済みプロジェクト JSON の 2 版（base / head）を比較し、脅威モデリングの**実行トリガー**
（下記 T1〜T8）に当たる変更と、脅威の追加・解消・対応方針変更・実効 severity 変化を
Markdown（PR コメントにそのまま貼れる形）または JSON で出します。

```bash
node dist-cli/main.js diff <base.json> <head.json> [options]
```

| オプション | 値 | 既定 |
|---|---|---|
| `--format` | `md` \| `json` | `md` |
| `--fail-on` | `Critical` \| `High` \| `Medium` \| `Low` | 指定なし（ゲート判定なし） |
| `--triggers` | 実行トリガー定義 YAML のパス | 同梱の T1〜T8（指定時は翻訳オーバーレイ非適用） |
| `--locale` | `ja` \| `en` | `ja` |
| `--out` | 出力先ファイルパス | 標準出力 |

ゲートは**新規に追加された脅威だけ**を対象にします（既存の未対応脅威では落ちません）。
受容・誤検知への対応方針変更はゲートを落とさず、「要承認」として出力に明示します。

実行トリガー一覧：

| ID | トリガー |
|---|---|
| T1 | 新しい信頼境界 |
| T2 | 新しい外部インターフェース |
| T3 | 新しい認証／認可の仕組み |
| T4 | 新しい技術またはランタイム |
| T5 | 機密データが新しい経路を通る |
| T6 | 新しいサードパーティ連携 |
| T7 | エージェントの能力拡大 |
| T8 | モデル・学習データ・RAG ソースの変更 |

T4 のみモデル差分から自動判定できず（図に技術スタックの情報が無いため）、常に
「PR レビューで確認」として出力されます。

### 実行トリガー チェックリスト（`triggers`）と CI 導入

```bash
node dist-cli/main.js triggers [options]
```

| オプション | 値 | 既定 |
|---|---|---|
| `--format` | `md` \| `json` | `md` |
| `--triggers` | 実行トリガー定義 YAML のパス | 同梱の T1〜T8（指定時は翻訳オーバーレイ非適用） |
| `--locale` | `ja` \| `en` | `ja` |
| `--out` | 出力先ファイルパス | 標準出力 |

上記 T1〜T8 を Markdown チェックリスト（PR テンプレートや AI レビュアーの観点表として使える形）
または JSON で出します。そのまま使える GitHub Action（`action.yml`）・ワークフロー例・
CODEOWNERS・PR テンプレートと、導入手順の全体は[ガイド](guide/README.ja.md)の
[AI駆動開発のCIに組み込む](guide/ci-integration.ja.md)を参照してください。

### MCP サーバー（`mcp`）

`node dist-cli/main.js mcp` で、stdio 経由の MCP サーバーを起動します。コーディングエージェント（Claude Code・GitHub Copilot 等）が
脅威を問い合わせ、構成図の構成を更新できます。外部通信は行わず、受容やリスク評価は変更できません。
導入は[コーディングエージェントから使う](guide/mcp-integration.ja.md)を参照してください。

---

## コントリビュート

Issue と Pull Request を歓迎します。開発の流れ・脅威ルール追加時のルール・翻訳への
参加方法は [CONTRIBUTING.ja.md](CONTRIBUTING.ja.md) を参照してください。

---

## セキュリティ

脆弱性を発見した場合は、公開の Issue ではなく GitHub の Security Advisory 機能から
非公開でご報告ください。報告手順と既知の注意点は [SECURITY.ja.md](SECURITY.ja.md) に
まとめています。

特に以下の 2 点にご注意ください。

- **信頼できない YAML を読み込まないでください。** コンポーネントライブラリの
  インライン SVG アイコンは現在サニタイズされていないため、第三者が配布する
  ライブラリ YAML は内容を確認してから使用してください
- 本ツールは脅威モデリングの**設計支援**を目的としており、検出結果の網羅性や
  正確性を保証するものではありません。実際のリスク評価は専門家の判断と併用してください

---

## ライセンス

[Apache License 2.0](LICENSE)

脅威ライブラリおよびコンプライアンスマッピングは本プロジェクトの独自著作であり、
参照している外部ソース（OWASP、MITRE ATLAS、NIST、CISA、Anthropic 等）の帰属表示は
[NOTICE](NOTICE) にまとめています。
