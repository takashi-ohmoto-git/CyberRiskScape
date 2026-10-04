# Kong AI Gateway を脅威モデリングする — decK の設定から構成図を作る

[English](kong-ai-gateway.md) | **日本語**

> Kong は Kong Inc. の商標です。このページは「CyberRiskScape で Kong Gateway の構成を脅威モデル化する方法」を
> 説明するもので、Kong 社が提供・認定・推奨するものではありません。プラグイン名と設定の形式は
> 執筆時点（2026 年 10 月）の公式ドキュメントによります。最新は各リンク先の公式の情報で確認してください。

---

## 1. このページで分かること・前提

- Kong Gateway の宣言設定（decK の `kong.yaml`）を読み込んで、**構成図の下書きを自動で作る**方法（画面・CLI）
- 設定のどの部分が、CyberRiskScape のどのコンポーネント型・接続の属性になるか
- 生成された図で**実際に検出される脅威**と、AI Gateway の構成で押さえたい脅威
- `kong.yaml` の変更を PR で見張り、新しい脅威が出たら CI を止める使い方
- この取り込みで**分からないこと**（図で補う必要がある属性）

**前提：Kong Gateway と decK**（執筆時点の公式の記載による）

- Kong Gateway は API ゲートウェイです。**Service**（転送先の API）、**Route**（どのリクエストをどの
  Service に送るか）、**Plugin**（認証・レート制限・ログなどの機能）、**Consumer**（API の利用者）を組み合わせて
  動きます。
- **decK** は、これらの設定をファイル（`kong.yaml`）で宣言的に管理する公式のツールです。プラグインは
  トップレベルに書いて `service:` / `route:` で対象を指定するか、Service・Route の下に入れ子で書きます
  （[出典 1](#参考リンク)）。
- **Kong AI Gateway** は、AI 向けのプラグイン群の呼び名です。`ai-proxy`（LLM プロバイダへの接続）、
  `ai-prompt-guard` などのガード系、`ai-rag-injector`（RAG）、`ai-mcp-proxy`（MCP）などがあります
  （[出典 2](#参考リンク)）。

**このページの前提となる知識**：[はじめに](getting-started.ja.md)の操作と、
[テンプレートを作る・使う](templates.ja.md)の読み込み手順。

---

## 2. 設定と CyberRiskScape の型の対応

取り込みは、**設定を図の要素に置き換えるだけ**です。脅威の判定は、ほかの図と同じ脅威ルールが行います。

| kong.yaml の要素 | CyberRiskScape の型・属性 | 補足 |
|---|---|---|
| Kong Gateway 本体 | `GATEWAY`（API ゲートウェイ）／`AI_GATEWAY` | AI 系プラグインを使うサービスは AI Gateway、それ以外は API ゲートウェイが受けます。両方あれば 2 つに分けて描きます |
| Admin API（管理面） | `API_CONTROL_PLANE`（API管理プレーン） | 設定ファイルがある＝管理面がある、とみなして常に置きます |
| Service（通常の API） | `BACKEND_API`（バックエンドAPI） | 名前は Service 名。転送先 URL が https なら暗号化あり、http なら平文 |
| Service ＋ `ai-proxy` | `LLM` | 名前は「プロバイダ / モデル名」。OpenAI など外部のプロバイダは Partner の境界、ollama・vllm・llama は組織内に置きます |
| Service ＋ `ai-proxy-advanced` | `LLM`（転送先ごと） | 負荷分散先のモデルをそれぞれ 1 つの LLM として描きます |
| Service ＋ `ai-mcp-proxy` | `MCP_SERVER`（MCPサーバー） | |
| Service ＋ `ai-a2a-proxy` | `AGENT`（AIエージェント） | |
| `ai-rag-injector` | `DB`（ベクターDB / RAG） | LLM への取得経路（`semantic: rag_retrieval`）として描きます |
| ガード系プラグイン | `GUARDRAIL`（ガードレール） | `ai-prompt-guard`・`ai-semantic-prompt-guard`・`ai-semantic-response-guard`・`ai-sanitizer`・`ai-lakera-guard`・`ai-azure-content-safety`・`ai-aws-guardrails`・`ai-gcp-model-armor`・`ai-custom-guardrail` |
| `vaults`／`{vault://…}` 参照 | `SECRETS_VAULT`（シークレット管理） | |
| 認証系プラグイン | クライアント → ゲートウェイの接続の「認証」 | `key-auth`・`basic-auth`・`hmac-auth`・`jwt`・`oauth2`・`openid-connect`・`ldap-auth`・`mtls-auth` など。**すべて「パスワード認証」扱い**（§7） |
| Route の `protocols` | クライアント → ゲートウェイの接続の「暗号化」 | `http` を許す Route が 1 つでもあれば平文 |
| `ip-restriction`・ログ系プラグイン | API ゲートウェイの攻撃面属性 | 送信元 IP 制限・アクセスログを「あり」にします |
| Consumer | 図にしません | 件数だけ表示します。資格情報は読みません |

**秘密情報は読み込みません。** 取り出すのは名前・種別・ホスト名・モデル名だけで、認証ヘッダの値、
Consumer の API キー、URL に含まれるユーザー名・パスワードやクエリは図に持ち込みません。

**クライアント → ゲートウェイの接続は 1 本**にまとめ、Route で到達できるサービスのうち**最も弱い認証**を
採ります。サービスごとの認証は、ゲートウェイの説明欄に一覧で残します。

---

## 3. 取り込み方

### 3.1 画面から

1. 左サイドバーの **Template** を開き、**Import（読み込み）** タブを選びます。
2. **「Kong 設定（decK）を選択」** を押して、`kong.yaml`（または JSON）を選びます。
3. 生成される図の件数と、元の設定の件数（サービス・ルート・プラグイン・コンシューマー）が表示されます。
   **「適用」** を押すと、アクティブなレイヤーが生成された図に置き換わります（Undo で戻せます）。

![Kong 設定の取り込み](../assets/guide/kong/01-import.png)

試すためのサンプルを [`templates/kong-ai-gateway.yaml`](templates/kong-ai-gateway.yaml) に置いています
（実際の資格情報は含みません。API キーは Vault 参照です）。

### 3.2 CLI から

```bash
npm ci && npm run build:cli
node dist-cli/main.js import-kong kong.yaml --out model.json
node dist-cli/main.js analyze model.json --format md
```

`import-kong` は L1 に図を置いたプロジェクト JSON を出力します。画面の「ファイル（保存 / 開く）」で開くことも、
`analyze`・`diff` にそのまま渡すこともできます。CLI 全般は [AI駆動開発のCIに組み込む](ci-integration.ja.md) を参照してください。

---

## 4. 生成される図の例

サンプルの設定には、OpenID Connect で守った通常の API（`orders-api`）、`ai-proxy` で OpenAI につなぐ
問い合わせチャット（`support-chat`：`key-auth`・`ai-prompt-guard`・`ai-rag-injector` 付き）、
社内ツールを MCP として公開する `internal-tools`（認証なし・http も許可）の 3 つのサービスがあります。

![Kong 設定から生成した構成図](../assets/guide/kong/02-overview.png)

このサンプルでは **47 件**（Critical 7・High 24・Medium 16）の脅威が検出されます（執筆時点）。

### 4.1 図の前提（取り込み後に見直す属性）

- **API ゲートウェイの Global IP・WAF・DDoS 対策・管理面の制限**は、`kong.yaml` からは分からないため
  未入力（安全でない前提）のままです。実際の構成に合わせてゲートウェイの属性を設定してください。
- **認証の強さ**：OIDC で MFA を必須にしている場合は、クライアント → ゲートウェイの接続を「MFA」に上げてください。
- **バックエンドへの接続**は「組織内のネットワーク・認証なし」としています（ゲートウェイからの転送を信用する、
  よくある構成）。相互 TLS などで認証している場合は変更してください。

---

## 5. 押さえるべき脅威

### 5.1 認証のない Route と平文の経路

`internal-tools` の Route には認証プラグインが無く、`http` も許しています。最も弱い経路を採るため、
クライアント → AI Gateway の接続は「認証なし・平文・インターネット経由」になります。

| 脅威 | 重大度 | 当たる要素 |
|---|---|---|
| 未認証の公衆網経路（`stride-edge-unauth-internet-001`） | Critical | クライアント → AI Gateway |
| 平文通信（`stride-edge-plain-encryption-001`） | High | 同上、AI Gateway → `internal-tools` |

1 つの Route の設定漏れが、同じゲートウェイを通る経路全体の評価を下げます。これは「設定の追加 1 行で
攻撃面が増える」ことの表れで、§6 の CI での見張りが効く場面です。

### 5.2 MCP として公開した社内ツール

`ai-mcp-proxy` を付けたサービスは MCPサーバーとして描かれ、MCP 特有の脅威が出ます。

| 脅威 | 重大度 |
|---|---|
| ツール記述子ポイズニング／Line jumping（`mcp-tool-descriptor-poisoning-001`） | Critical |
| MCP サーバーのなりすまし／タイポスクワッティング（`mcp-server-impersonation-typosquatting-001`） | High |

![MCP サーバーの脅威](../assets/guide/kong/03-mcp.png)

### 5.3 ガードレールは確率的な防御

`ai-prompt-guard` はガードレールとして描かれます。ガードレールがあっても、LLM には直接・間接の
プロンプトインジェクション（`owasp-llm01-prompt-injection-001`・`atlas-aml-t0051-indirect-prompt-injection-001`）が
出たままです。ガードレール自体にも「単体に依存すると迂回される」脅威が出ます。

| 脅威 | 重大度 |
|---|---|
| ガードレール単体依存（確率的防御の限界）（`zt-guardrail-probabilistic-bypass-001`） | Medium |

![ガードレールの脅威](../assets/guide/kong/05-guardrail.png)

> **ひとこと** — 現在の脅威ルールは「ガードレールがあれば LLM の脅威を対策済みにする」判定をしません。
> 正規表現の拒否リスト（`ai-prompt-guard`）は言い換えで迂回されうるため、出たままにしておくのが安全側の評価です。
> 対策の実装状況は、脅威カードの「対策実装状況」で記録してください。

### 5.4 RAG で注入する文書の来歴

`ai-rag-injector` はベクターDB → LLM の取得経路として描かれ、取得した文書に仕込まれた指示が LLM に
届く経路が評価されます。

| 脅威 | 重大度 |
|---|---|
| RAG 取得文書の来歴・署名検証欠如（`agentic-rag-retrieval-provenance-gap-001`） | High |
| ベクトル・埋め込みの弱点（`owasp-llm08-vector-embedding-weaknesses-001`） | High |

### 5.5 管理プレーンとシークレット管理

Admin API の資格情報を取られると、配下のすべての API の認証とルーティングを書き換えられます。
Vault は API キーの集約点です。

| 脅威 | 重大度 | 当たる要素 |
|---|---|---|
| API 管理プレーンの構成改ざん（`api-control-plane-config-tampering-001`） | High | API管理プレーン |
| 管理面リモートアクセス（`api-control-plane-internet-exposure-001`） | Critical | インターネット側から管理プレーンへ接続を描いたとき |
| シークレット管理への権限集中（`api-secrets-vault-concentration-001`） | High | シークレット管理 |

![管理プレーンの脅威](../assets/guide/kong/04-control-plane.png)

### 5.6 バックエンドの認可とゲートウェイ

| 脅威 | 重大度 | 当たる要素 |
|---|---|---|
| オブジェクト・プロパティ単位の認可不備（BOLA / BOPLA）（`api-backend-object-level-authorization-001`） | High | バックエンドAPI |
| 認可境界の不備（`stride-gateway-elevation-of-privilege-001`） | High | API ゲートウェイ |
| AI Gateway へのログ集中（`zt-ai-gateway-log-concentration-001`） | Medium | AI Gateway |

ゲートウェイはトークンとスコープを検証できても、**レコードの所有者が誰か**は知りません。BOLA の判定は
バックエンドでしかできない、という点が設計レビューの論点になります。

---

## 6. ユースケース：kong.yaml の変更を PR で見張る

decK の設定を Git で管理しているなら、PR のたびに変更前後の設定から構成図を作り、
**新しく出た脅威**だけを判定できます。

```bash
# 変更前（main）と変更後（PR）の設定から、それぞれプロジェクト JSON を作る
git show origin/main:kong.yaml > base-kong.yaml
node dist-cli/main.js import-kong base-kong.yaml --out base.json
node dist-cli/main.js import-kong kong.yaml --out head.json

# 新しい High 以上の脅威があれば exit 1（PR を止める）
node dist-cli/main.js diff base.json head.json --format md --fail-on High --out result.md
```

要素の ID は Service 名などから決まるため、サービスを足しても既存の要素は同じものとして突き合わされます。
たとえば外部 LLM（`ai-proxy` で Anthropic）につなぐサービスを 1 つ足すと、追加された脅威が一覧になり、
実行トリガー **T1（新しい信頼境界）・T6（新しいサードパーティ連携）・T8（モデル・学習データ・RAG ソースの変更）**
が判定されます。GitHub Actions への組み込み方は [AI駆動開発のCIに組み込む](ci-integration.ja.md) を参照してください。

---

## 7. 限界

- **プラグインがあっても「対策済み」にはなりません。** 取り込みは図を作るだけで、対策の実装状況は自動では付きません
- **認証の強さは控えめに見積もります。** 認証系プラグインはすべて「パスワード認証」扱いです。MFA かどうかは
  IdP 側の設定で決まり、`kong.yaml` からは分かりません
- **クライアント → ゲートウェイの接続は 1 本**で、最も弱い Route の評価になります。Route ごとの評価が必要なら、
  図でクライアントを分けて接続を描き直してください
- **ゲートウェイの Global IP・WAF・DDoS 対策・管理面の制限は分かりません**（§4.1）。Kong Konnect の API は呼びません
- 読むのは 1 つのファイルです。複数の decK ファイルに分けている場合は、`deck file merge` などで 1 つにまとめてから読み込んでください
- Consumer・Upstream（負荷分散先）・Workspace は図にしません
- 自動配置は簡易的で、接続が交差することがあります。必要に応じて配置を整えてください
- プラグイン名と設定の形式は執筆時点の公式ドキュメントによります。新しいプラグインは、未対応なら単に無視されます

---

## 参考リンク

1. decK（Kong の宣言設定ツール）入門 — <https://developer.konghq.com/deck/get-started/>
2. Kong の AI プラグイン一覧 — <https://developer.konghq.com/plugins/?category=ai>
3. AI Proxy プラグイン — <https://developer.konghq.com/plugins/ai-proxy/>
4. OWASP API Security Top 10 2023 — <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
5. OWASP Top 10 for LLM Applications 2025 — <https://genai.owasp.org/llm-top-10/>

---

## 次に読むもの

- 検出された脅威の読み方 — [脅威パネルの読み方](reading-threats.ja.md)
- 経路から守りどころを探す — [攻撃経路分析](attack-paths.ja.md)
- PR で構成図の更新を求める — [AI駆動開発のCIに組み込む](ci-integration.ja.md)
- 同じ流れで別の製品を扱う例 — [Salesforce Agentforce を脅威モデリングする](agentforce.ja.md)
