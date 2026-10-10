# NHI と ID 基盤を脅威モデリングする — Okta・SailPoint・CyberArk（Idira）と組み合わせる

[English](nhi-identity.md) | **日本語**

> Okta・SailPoint・CyberArk・Idira は、それぞれの所有者の商標です。このページは「CyberRiskScape で
> 非人間アイデンティティ（NHI）と ID 基盤を脅威モデル化し、各社の MCP サーバーと組み合わせる方法」を説明する
> もので、各社が提供・認定・推奨するものではありません。製品と MCP サーバーの仕様は執筆時点（2026 年 10 月）の
> 公式の情報によります。最新は各リンク先で確認してください。

---

## 1. このページで分かること・前提

- サービスアカウント・ワークロードID・OAuthクライアント・RPAボットといった **NHI（Non-Human Identity、人に紐づかない ID）**と、
  特権アクセス管理（PAM）・ID ガバナンス（IGA）を、構成図にどう描くか
- 描いた図で検出される NHI の脅威（OWASP Non-Human Identities Top 10 にもとづく）
- Okta・SailPoint・CyberArk（Idira）の **MCP サーバーを CyberRiskScape の MCP サーバーと同じ AI エージェントに登録**し、
  脅威モデルと実際の ID の状態を突き合わせる使い方
- CyberArk（Idira）Conjur の**ポリシーを読み込んで**、NHI とシークレットの読み取り経路の図を自動で作る方法
- 組み合わせるときの安全上の注意と、限界

**前提：NHI が脅威モデリングで重要な理由**

組織の中では、人のアカウントより NHI のほうが多いことが珍しくありません。NHI は MFA や異動・退職の手続きの外にあり、
権限が広く、資格情報が長期間変わらないまま残りがちです。OWASP は 2025 年に NHI 特有のリスクを
**Non-Human Identities Top 10** にまとめています（[出典 1](#参考リンク)）。AI エージェントも NHI の一種で、
エージェントが使う API キーやサービスアカウントの扱いが、そのまま被害の範囲を決めます。

**このページの前提となる知識**：[はじめに](getting-started.ja.md)の操作と、
[コーディングエージェントから使う — MCP サーバー導入ガイド](mcp-integration.ja.md)。

---

## 2. 製品・構成要素と CyberRiskScape の型の対応

型はすべて **Identity & Access** カテゴリにあります。NHI の 4 型は、内包した「認証情報」で持っている資格情報を表し、
ノードの **Identity Tier**（ID の強度）で、静的な鍵か、暗号学的な ID か、ハードウェアに束縛された ID かを宣言します。

| 構成要素（製品の例） | CyberRiskScape の型 | 設定のポイント |
|---|---|---|
| サービスアカウント・共有の技術アカウント | `SERVICE_ACCOUNT`（サービスアカウント） | パスワードや API キーで動くなら Identity Tier は未設定（ラベルのみ）のまま |
| IAM ロール・マネージド ID・ワークロード ID 連携 | `WORKLOAD_IDENTITY`（ワークロードID） | 資格情報の発行元（CI・クラウド）から線を引く |
| OAuth のサービスアプリ・M2M クライアント（Okta のサービスアプリ 等） | `OAUTH_CLIENT`（OAuthクライアント） | private key JWT・mTLS なら Identity Tier を「Cryptographic」に |
| RPA のボット | `RPA_BOT`（RPAボット） | 人のアカウントで動くなら、その旨を説明欄に書く |
| 特権アクセス管理（CyberArk / Idira PAM 等） | `PAM`（特権アクセス管理（PAM）） | 管理者 → PAM → 管理対象の向きに線を引く |
| ID ガバナンス（SailPoint Identity Security Cloud 等） | `IGA`（IDガバナンス（IGA）） | アカウントを配る先へ線を引く |
| IDaaS（Okta 等） | `IDENTITY_PROVIDER`（IdP）＋種別「IDaaS」 | 接続の「資格情報の発行元」に指定する |
| シークレット管理（CyberArk / Idira Secrets Manager 等） | `SECRETS_VAULT`（シークレット管理） | NHI からシークレット管理へ線を引く |
| AI エージェント | `AGENT`（AIエージェント） | エージェント固有の脅威は既存のルールが扱う |

**図の描き方の約束**（NHI のルールはこの向きを前提にしています）：

- **使う側 → NHI → アクセス先**の向きに線を引きます。NHI を使うワークロードや CI から NHI へ、NHI からデータや API へ。
- **人 → NHI** の線は「人が NHI を使っている」ことを表します（NHI10 が検出されます）。
- Identity Tier を設定しない NHI は「ラベルのみ」＝静的な鍵で動いているものとして扱います。

---

## 3. 構成図の例

NHI と ID 基盤の典型的な構成をまとめたテンプレートを用意しています。

| ファイル | 内容 |
|---|---|
| [`templates/nhi-identity.ja.json`](templates/nhi-identity.ja.json) | 日本語版 |
| [`templates/nhi-identity.en.json`](templates/nhi-identity.en.json) | 英語版 |

読み込み方は [テンプレートを作る・使う](templates.ja.md) を参照してください。

![NHI と ID 基盤の構成図](../assets/guide/nhi/01-overview.png)

**中身：** コンポーネント 14・データフロー 12・トラスト境界 2。運用担当が特権アクセス管理を経由する経路と、
同じサービスアカウントを手作業で直接使う経路、CI の OIDC トークンでワークロードIDに資格情報を出す経路、
受注 API が OAuthクライアントで外部 SaaS を呼ぶ経路、IGA が各システムにアカウントを配る経路を含みます。
読み込むと **41 件**の脅威が検出されます（執筆時点）。

---

## 4. 押さえるべき脅威

### 4.1 OWASP Non-Human Identities Top 10 にもとづく NHI の脅威

| 脅威 | 重大度 | 発火の条件 |
|---|---|---|
| NHI の不適切なオフボーディング（`nhi-improper-offboarding-001`、NHI1） | Medium | NHI があれば発火（所有者と期限の管理） |
| NHI の過剰な権限（`nhi-overprivileged-001`、NHI5） | High | NHI からアクセス先への線がある |
| NHI の長期の静的シークレット（`nhi-long-lived-secret-001`、NHI7） | High | Identity Tier が「ラベルのみ」（未設定を含む）。ワークロードIDは対象外 |
| NHI の環境分離の不備（`nhi-environment-isolation-001`、NHI8） | Medium | NHI があれば発火（開発と本番での共用） |
| NHI の使い回し（`nhi-reuse-001`、NHI9） | Medium | ワークロード・CI・エージェントから NHI への線がある |
| 人による NHI の利用（`nhi-human-use-001`、NHI10） | High | 人・端末から NHI への線がある |

![サービスアカウントの脅威](../assets/guide/nhi/02-service-account.png)

> **ひとこと** — 「長期の静的シークレット」は、Identity Tier を「Cryptographic」（private key JWT・mTLS・X.509 など）や
> 「HardwareBound」（HSM・TPM）にすると出なくなります。実際の認証方式を確かめてから宣言してください（§5.3 の UC2）。

### 4.2 ワークロードID・PAM・IGA の脅威

| 脅威 | 重大度 | 当たる要素 |
|---|---|---|
| ワークロード ID 連携の信頼条件が広すぎる（`nhi-workload-federation-trust-001`） | High | ワークロードID |
| 特権アクセス管理への特権の集中（`pam-privileged-concentration-001`） | High | 特権アクセス管理 |
| 特権アクセス管理を経由しない特権経路の残存（`pam-bypass-path-001`） | Medium | 特権アクセス管理 |
| IDガバナンスの接続用特権による全システムへの波及（`iga-connector-privilege-001`） | High | IDガバナンス |
| 権限の棚卸しの形骸化と NHI の管理対象外（`iga-certification-gap-001`） | Medium | IDガバナンス |

![ワークロードIDの脅威](../assets/guide/nhi/03-workload-identity.png)

このほか、既存のルールも当たります。発行元の IdP を持たない資格情報（`identity-local-credential-outside-idp-001`）、
認証情報の散在（`zt-credential-sprawl-static-secret-001`）、シークレット管理への権限集中（`api-secrets-vault-concentration-001`）などです。

---

## 5. 各社の MCP サーバーと組み合わせる

CyberRiskScape の MCP サーバーと、各社の MCP サーバーを**同じ AI エージェントに並べて登録**すると、
「図に描いた想定」と「ID 基盤にある実際の状態」を 1 つの会話の中で突き合わせられます。2 つのサーバーは互いに
通信しません。つなぐのはエージェントです（[Snyk との組み合わせ](mcp-use-cases.ja.md)と同じ形です）。

### 5.1 各社の MCP サーバー（執筆時点の公式の情報による）

| 製品 | MCP サーバー | 読み取りに使えるツール | 書き込み系のツール | 注意 |
|---|---|---|---|---|
| **Okta** | 公式の Okta MCP Server（オープンソース・一般提供）（[出典 2](#参考リンク)） | アプリ・ユーザー・グループ・ポリシー・システムログの一覧と取得（`list_applications`・`get_application`・`get_logs` など） | ユーザー・グループ・アプリ・ポリシーの作成・変更・削除 | **付与したスコープに対応するツールだけが有効**になる。`okta.*.read` だけを付ければ読み取り専用で使える。破壊的な操作は確認を求める |
| **SailPoint** | Identity Security Cloud の MCP Server（[出典 3](#参考リンク)） | 申請できるアクセスの検索（`list-requestable`）、アクセス申請の状況（`view-access-requests`） | アクセス申請の作成・取り消し（`create-access-request`・`cancel-access-request`） | 執筆時点のツールはアクセス申請まわりの 4 つで、**ID や NHI の棚卸しを読むツールは無い** |
| **CyberArk（Idira）** | Secrets Manager の MCP Server（[出典 4](#参考リンク)） | ワークロード・シークレット・リソースの一覧（`list_hosts`・`list_secrets`・`list_all_resources`）、`whoami` | ワークロード・シークレットの作成、権限の付与（`create_workload`・`create_secret`・`grant_secret_permission` など） | 公式には**開発環境向け**（本番環境はサポート対象外） |
| **CyberArk（Idira）** | Secure Cloud Access（SCA）の MCP Server（[出典 5](#参考リンク)） | — | AWS への一時的な権限昇格（`login_to_aws_default`・`elevate_aws_account_access`） | 権限を**取得する**ためのツール。脅威モデリングのエージェントには登録しない（§6） |

CyberArk は 2026 年に Palo Alto Networks が買収し、製品は **Idira** のブランドへ順次移行しています（[出典 6](#参考リンク)）。

### 5.2 登録する（Claude Code の例）

プロジェクトの `.mcp.json` に両方のサーバーを並べます。CyberRiskScape 側の設定は
[MCP サーバー導入ガイド](mcp-integration.ja.md) と同じです。Okta は読み取りのスコープだけを付けます。

```json
{
  "mcpServers": {
    "cyberriskscape": {
      "command": "node",
      "args": ["${CLAUDE_PROJECT_DIR}/dist-cli/main.js", "mcp", "--root", "${CLAUDE_PROJECT_DIR}"]
    },
    "okta-mcp-server": {
      "command": "uvx",
      "args": ["okta-mcp-server"],
      "env": {
        "OKTA_ORG_URL": "https://<your-org>.okta.com",
        "OKTA_CLIENT_ID": "<CLIENT_ID>",
        "OKTA_SCOPES": "okta.apps.read okta.users.read okta.groups.read okta.logs.read"
      }
    }
  }
}
```

この例は、ブラウザで認証する方式（Device Authorization Grant）です。秘密鍵による方式（Private Key JWT）を使う場合も、
**秘密鍵を `.mcp.json` に直接書かず**、環境変数やシークレット管理から渡してください。SailPoint・CyberArk（Idira）の
登録方法は、各社の公式の手順に従ってください（[出典 3・4](#参考リンク)）。

### 5.3 ユースケース

**UC1：図の NHI と、実在する NHI を突き合わせる（Okta・CyberArk）**

```text
threat-model/project.json の L1 にある NHI（サービスアカウント・ワークロードID・OAuthクライアント・RPAボット）を
一覧にしてください。次に Okta のアプリケーション一覧からサービスアプリ（client credentials を使うもの）を、
Secrets Manager からワークロードの一覧を取得し、図と突き合わせてください。
「図にあるが実在しない」「実在するが図に無い」ものを表にし、図に無いものは apply_model_changes を dryRun で実行して
追加した場合の脅威の増減を見せてください（実際の適用は私が確認してから）。
```

流れ：`get_model`（CyberRiskScape）→ `list_applications`（Okta）・`list_hosts`（CyberArk / Idira）→ エージェントが対応づける →
`apply_model_changes`（`dryRun`）で影響を確認。**対応づけはエージェントの推定**です。名前の一致だけで同じものと判断していないか、人が確認してください。

**UC2：Identity Tier の宣言を、実際の認証方式で確かめる（Okta）**

```text
図の OAuthクライアントごとに、対応する Okta のアプリの設定（get_application）からトークンエンドポイントの認証方式を
確認してください。client_secret_basic / client_secret_post なら Identity Tier は LabelOnly、private_key_jwt なら
Cryptographic として、図の宣言と違うものを挙げてください。
```

「長期の静的シークレット」（NHI7）が実際の状態に即して出るようになります。

**UC3：使われていない NHI を探す（Okta）**

```text
図の NHI に対応する Okta のサービスアプリについて、過去 90 日のシステムログ（get_logs）で利用があるかを調べ、
利用が無いものを、図のノード（ElementalID）と対応づけて挙げてください。
```

結果は「NHI の不適切なオフボーディング」の点検の根拠になります。無効化の判断と、脅威カードへの記録（対応方針・
対策実装状況）は人が行います（エージェントからは変更できません）。

**UC4：過剰な権限の代わりに、申請できる最小のアクセスを探す（SailPoint）**

```text
「NHI の過剰な権限」が出ている受注 API 用の NHI について、SailPoint で申請できるアクセス（list-requestable）を検索し、
用途に必要な最小のロール・アクセスプロファイルの候補を挙げてください。申請はしないでください。
```

申請（`create-access-request`）は人が行います。エージェントに申請させない設定は §6 を参照してください。

---

## 6. CyberArk（Idira）Conjur のポリシーから図を作る

CyberArk（Idira）の Secrets Manager（Conjur）は、**だれ（host・ユーザー）がどのシークレットを読めるか**を宣言的な YAML の
ポリシーで管理します。このポリシーを読み込むと、NHI とシークレットの読み取り経路の構成図を自動で作れます。
ポリシーはファイルで読むだけで、Conjur の API は呼びません。

### 6.1 対応

| ポリシーの要素 | CyberRiskScape の型・属性 |
|---|---|
| `!host`（認証方式の annotation：`authn-jwt`・`authn-k8s`・`authn-iam`・`authn-azure`・`authn-gcp`） | `WORKLOAD_IDENTITY`（ワークロードID）。Identity Tier は「Cryptographic」 |
| `!host`（上の annotation が無い＝API キーで認証） | `SERVICE_ACCOUNT`（サービスアカウント）。Identity Tier は未設定（静的な鍵） |
| `!variable` | 1 つの `SECRETS_VAULT`（Conjur）に集約。各 NHI・人からの線に「変数の取得 N 件」「変数の更新 N 件」と書く |
| `!user`・`!group` | 変数の権限を持つもの、または host のロールを付与されたものだけ `USER` として描く |
| `!grant`（host のロールを人に付与） | 人 → NHI の線（「人による NHI の利用」が検出される） |
| `!layer` | 描かずに、所属する host の説明欄に書く。権限は `!grant` の所属関係をたどって実効権限として求める |
| `!policy` | 入れ子の `id` を接頭辞にして、各要素の id を解決する |

**annotation の値は図に載せません**（認証方式の判定にだけ使います）。ポリシーはシークレットの値を持たないため、値が図に入ることもありません。
`!deny`・`!revoke`・`!delete` などの変更系の文は対象外です。

### 6.2 取り込み方

- **画面から**：Template → Import タブの **「Conjur ポリシーを選択」** で YAML を選びます。
- **CLI から**：`node dist-cli/main.js import-conjur policy.yml --out model.json`

試すためのサンプルを [`templates/conjur-policy.yml`](templates/conjur-policy.yml) に置いています（受注システムの host 3 つ・変数 4 つ・運用グループ・
host のロールを付与された運用担当）。

![Conjur ポリシーの取り込み](../assets/guide/nhi/04-conjur-import.png)

![Conjur ポリシーから作った図](../assets/guide/nhi/05-conjur-overview.png)

サンプルでは **21 件**の脅威が検出されます（執筆時点）。API キーで動く nightly-batch には「長期の静的シークレット」と、alice にロールを付与されていることによる
「人による NHI の利用」、authn-jwt・authn-k8s の host には「ワークロード ID 連携の信頼条件」、
Conjur には「シークレット管理への権限集中」が出ます。

![API キーで動く host の脅威](../assets/guide/nhi/06-conjur-batch.png)

### 6.3 使いどころ

- **権限の棚卸し**：各 NHI が取得できる変数の件数が線に出るので、用途に比べて多すぎる NHI（NHI5）や、
  シークレットを読める人の広がりが一目で分かります。
- **PR での見張り**：ポリシーを Git で管理しているなら、[Kong の場合](kong-ai-gateway.ja.md)と同じく変更前後のポリシーから
  `import-conjur` でプロジェクト JSON を作り、`diff` で新しい脅威を判定できます。要素の ID は host や変数の id から決まります。

---

## 7. 安全のための注意

- **各社の MCP サーバーは、それぞれのクラウドへ通信します。** CyberRiskScape の MCP サーバーは外部と通信しませんが、
  並べて登録した各社のサーバーは ID 基盤に接続し、取得した内容はエージェント（と、その背後の LLM）に渡ります。
  ユーザー名・アプリ名・ログなどを AI に渡してよいか、組織のルールを確認してください。
- **読み取りだけを許可します。** Okta はスコープを `okta.*.read` に絞ります。エージェントが承認なしにツールを使う設定
  （GitHub Copilot の `tools` の許可リストなど）では、書き込み系のツール（アカウント・アプリ・ポリシーの変更、
  アクセス申請の作成、ワークロード・シークレットの作成、権限の付与）を**許可しない**でください。
- **権限を取得するツールは登録しません。** CyberArk（Idira）の SCA MCP Server は、エージェントに一時的なクラウドの権限を
  与えるためのものです。脅威モデリングのエージェントに登録すると、調べるつもりの会話で権限の取得が起こりえます。
- **シークレットの値を会話に出さない。** シークレット管理の MCP で扱うのは、ワークロードやシークレットの名前（メタデータ）に
  留めます。値を取得するツールやコード生成（`generate_fetch_code`）は、この用途では使いません。
- **最終判断は人が行います。** 図の更新は `apply_model_changes` を `dryRun` で確かめてから人の確認を経て適用し、
  リスクの受容・評価・対策実装状況は CyberRiskScape の画面と PR で人が判断します（エージェントからは変更できません）。

---

## 8. 限界

- **突き合わせはエージェントの推定です。** 図のノードと ID 基盤のエンティティは名前やメモで対応づけるため、
  取り違えや見落としがありえます。根拠を示させ、人が確認してください
- **NHI のルールは図の構造で判定します。** 実際の権限の大きさや、所有者の有無を CyberRiskScape が直接知ることはありません。
  「過剰な権限」や「オフボーディング」は、該当しそうな NHI に対する点検項目として出ます
- **SailPoint の MCP は、執筆時点ではアクセス申請のツールだけです。** NHI の棚卸しや所有者の情報は、この方法では読めません
- **CyberArk（Idira）の Secrets Manager の MCP は開発環境向けです。** 本番の棚卸しには使えません。ワークロードと
  シークレットの間の権限（だれが何を読めるか）を図にするには、ポリシーの取り込み（§6）を使ってください
- 各社の MCP サーバーの仕様は変わりえます。ツールの名前と範囲は公式で確認してください

---

## 参考リンク

1. OWASP Non-Human Identities Top 10（2025） — <https://owasp.org/www-project-non-human-identities-top-10/>
2. Okta MCP Server（Okta の GitHub） — <https://github.com/okta/okta-mcp-server>
3. SailPoint MCP Server：使えるツール（SailPoint Developer Community） — <https://developer.sailpoint.com/docs/extensibility/mcp-available-tools/>
4. Secrets Manager の MCP Server（CyberArk / Idira のドキュメント。公式の記載の抜粋による） — <https://docs.cyberark.com/secrets-manager-saas/latest/en/content/conjurcloud/cc-mcp-server.htm>
5. SCA MCP Server（CyberArk / Idira のドキュメント。公式の記載の抜粋による） — <https://docs.cyberark.com/sca/latest/en/content/automation/sca-mcp-server.htm>
6. Palo Alto Networks による CyberArk の買収完了（2026 年 2 月） — <https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-completes-acquisition-of-cyberark-to-secure-the-ai-era>

---

## 次に読むもの

- MCP をつなぐ — [コーディングエージェントから使う](mcp-integration.ja.md)
- ほかのツールとの組み合わせ — [ユースケースで学ぶ MCP 連携](mcp-use-cases.ja.md)
- 連携できる製品の一覧 — [連携ガイド](integrations.ja.md)
