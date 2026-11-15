# Entra ID の外部アプリ・同意の在庫を構成図に載せる — Microsoft Graph から、外部アプリの強い権限を洗い出す

[English](entra-apps.md) | **日本語**

> このページに出てくる製品名は、各権利者の名称です。このページは「Microsoft Graph から読んだ Entra ID の外部アプリ・同意の在庫を
> CyberRiskScape に取り込む方法」を説明するもので、Microsoft が提供・認定・推奨するものではありません。記述的な使用です。
> 応答の形式・権限の名前は、執筆時点（2026 年 11 月）の公式のドキュメントによります。最新は公式の情報で確かめてください。

> **確認してよい範囲** — Microsoft Graph への接続は、**自組織が管理する、または診断を許可されたテナントだけ**に対して行ってください。
> 呼ぶのは読み取りの GET だけです。テナントの設定は変更しません。

---

## 1. このページで分かること・前提

Entra ID のテナントには、他の組織が作ったアプリ（SaaS・取引先の連携アプリなど）が、利用者や管理者の同意で入り込みます。
CyberRiskScape は Microsoft Graph（v1.0）から、サービスプリンシパル・委任の同意・Microsoft Graph のアプリ単独の権限を読み、
**外部アプリ**（所有テナントが自組織でも Microsoft のサービスでもないアプリ）のうち強い権限を持つものを**指摘**にして、図の **IdP** に載せます。
**図は変えません。**指摘を足すだけです。

BloodHound CE 連携（[BloodHound CE の結果を構成図に載せる](bloodhound.ja.md)）の Entra ID の段とは、見る角度が違います。
あちらは攻撃経路・権限の連鎖を BloodHound で分析した結果を取り込み、こちらは**外部アプリと同意の在庫**（どのアプリが何の権限・同意を持つか）を Graph から直接読みます。

**前提**

- 指摘を載せる先の、CyberRiskScape のプロジェクト JSON がある。図に **IdP** のノードがある（なければ指摘は未結合）。
- Node.js が動くこと。CLI をビルドしておきます（`npm ci && npm run build:cli`）。
- 入口は 2 つ（§4）。API で読むには、Entra ID にアプリを登録し、アプリケーションの権限 **Application.Read.All** と **Directory.Read.All**（どちらも読み取りのみ）に管理者の同意を済ませておきます。
- **CLI 専用です。**出力したプロジェクト JSON は、画面の **Template** → **Import** で読み込めます。

**このページの前提となる知識**：[はじめに](getting-started.ja.md)の操作と、[脅威パネルの読み方](reading-threats.ja.md)。

---

## 2. 何ができるか

読んだ在庫から、次の 4 つを指摘にします（観測ごとに 1 件）。

| 観測 | 対応する脅威 | 重大度 |
|---|---|---|
| 強いアプリ単独の権限（Microsoft Graph）を持つ外部アプリ | アプリ単独（app-only）でテナント全体を操作できる特権 | Critical |
| 強い権限を**テナント全体で**同意した外部アプリ | 外部アプリへの委任の同意（不正な同意の付与を含む） | High |
| 強い権限を**利用者が個別に**同意した外部アプリ | 同上 | Medium |
| 資格情報が設定された Microsoft のサービスのアプリ | 登録アプリへの資格情報の追加によるアプリの乗っ取り | High |

- 「強い権限」は、同梱の一覧（`data/finding-maps/graph-permissions.yaml`）で判定します。テナントの管理（ロール・アプリ・権限の付与）、利用者・グループ・認証方法の変更、メール・予定表、ファイル・サイト、チャットの 24 個の権限です。
- 委任の同意は、**Microsoft Graph への同意だけ**を見ます。
- 外部アプリかどうかは、サービスプリンシパルの所有テナントで判定します。自組織のテナント ID と Microsoft のサービスのテナントは、外部アプリから除きます。

### 図との突き合わせ

外部アプリの表示名を、図のアプリ系のノード（SaaS・OAuth クライアント・その他のアプリ等）のラベルと突き合わせます。
**表示名との完全一致**だけを見ます（大文字小文字・前後の空白は無視）。一致しないものには報告に「**図に無い**」の印が付きます。
これは**描き漏れの候補**であって、判定ではありません。

---

## 3. 図の準備

指摘は図の **IdP**（Identity & Access）に載せます。図に IdP がちょうど 1 つあればそこへ、無ければ未結合です。複数あるときは `--idp-node` で指定します（§4.3）。

IdP には、アプリ登録を持つ IdP 一般の脅威として、次の 3 つの脅威ルールが付いています（Entra ID に限りません）。

- アプリ単独（app-only）でテナント全体を操作できる特権
- 外部アプリへの委任の同意（不正な同意の付与を含む）
- 登録アプリへの資格情報の追加によるアプリの乗っ取り

突き合わせのために、図に外部アプリのノード（SaaS・OAuth クライアント・その他のアプリ等）をラベル付きで描いておくと、描き漏れが分かります。

---

## 4. 取り込み

入口は 2 つです。どちらか一つで足ります。

### 4.1 API で取り込む（CLI のみ）

Entra ID に登録したアプリの情報を環境変数で渡します。値は保存も出力もしません。

```bash
export MSGRAPH_TENANT_ID=<自組織のテナント ID>
export MSGRAPH_CLIENT_ID=<アプリケーション（クライアント）ID>
export MSGRAPH_CLIENT_SECRET=<クライアントシークレット>
node dist-cli/main.js import-entra-apps my-project.json --graph -o out.json
```

- クライアント資格情報フローでトークンを取り、`graph.microsoft.com` に **GET だけ**を送ります。読み取りのみです。
- 要るアプリケーションの権限は **Application.Read.All** と **Directory.Read.All** です（委任の同意の一覧に Directory.Read.All を使います）。
- 次のページの URL は `graph.microsoft.com` のものだけを辿ります。リダイレクトは辿りません。1 つの一覧で辿るページには上限があり、超えたときは打ち切ります。

### 4.2 ファイルで取り込む

Graph の応答 JSON を自分で取得し、フォルダに次の名前で置きます（1 ページでも、ページの配列でもよい）。自組織のテナント ID を `--tenant-id` で渡します。

| ファイル名 | 取得する Graph の要求（GET） |
|---|---|
| `servicePrincipals.json`（必須） | `/v1.0/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled,verifiedPublisher,passwordCredentials,keyCredentials&$top=999` |
| `graphServicePrincipal.json` | `/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')?$select=id,appId,displayName,appRoles` |
| `graphAppRoleAssignedTo.json` | `/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')/appRoleAssignedTo?$top=999` |
| `oauth2PermissionGrants.json` | `/v1.0/oauth2PermissionGrants` |

```bash
node dist-cli/main.js import-entra-apps my-project.json --in ./graph-responses --tenant-id <自組織のテナント ID> -o out.json
```

**`graphServicePrincipal.json` が無いと、アプリ単独の権限は判定できません**（その旨が報告に出ます）。

### 4.3 どのノードに載せるか・オプション

| オプション | 意味 |
|---|---|
| `--idp-node <C番号または ID>` | 指摘を載せる IdP。図にちょうど 1 つあればそれ（既定）。複数あるときに指定する。無ければ未結合 |
| `--scope <name>` | 置き換えの範囲（既定 `default`）。テナントごとに分けるときに使う。**取り込み直しは、同じ scope の指摘を置き換えます。**別の scope の指摘は残ります |
| `--report <md または json>` | 報告の形式（既定 `md`。標準出力） |
| `-o <file>` | 指摘を保存したプロジェクト JSON の出力先（省略すると保存しない） |

---

## 5. 結果の見方

- **報告**：外部アプリの件数、観測ごとの件数、そして強い権限・同意のある外部アプリの一覧（アプリ名・発行元の確認の有無・アプリ単独の権限・テナント全体の同意・利用者ごとの同意の件数・図との突き合わせ）が出ます。
- **脅威カード**：該当する脅威のカードに「**Entra の設定で確認**」の印が出ます。実際の設定を Entra ID の管理画面で確かめる手がかりです。
- **レポート**：`findings-report`・`findings-priority` に指摘として入ります。SARIF 書き出しにも入ります。
- 「図に無い」の印は、描き漏れの候補です。実在するアプリなら図に描き足し、不要な同意なら取り消しを検討してください。

---

## 6. 秘密・個人情報の扱い

| 種類 | 扱い |
|---|---|
| クライアントシークレット・トークン | 保存も出力もしません（トークンの要求にだけ使います） |
| アプリの資格情報（パスワード・証明書） | 有効期限の件数だけを読みます。**値・ヒントは保存しません** |
| 利用者ごとの同意 | **件数だけ**。利用者は特定しません |
| アプリの表示名・発行元 | 資産の情報として残します |

---

## 7. 限界

- サインインの記録（使われていないアプリの判定）は beta の API のため見ていません。
- Microsoft Graph 以外の API への同意は判定しません。
- 図との突き合わせは、名前の完全一致だけです。名前が違うだけで同じアプリは「図に無い」になります。
- **実際のテナントでは未確認です。**公式のドキュメントの応答の形と、架空のデータのテストで確かめています（2026-11-15）。

---

## 8. 参考リンク

- Microsoft Graph permissions reference：https://learn.microsoft.com/en-us/graph/permissions-reference

---

## 9. 次に読むもの

- [BloodHound CE の結果を構成図に載せる](bloodhound.ja.md) — AD・Entra ID・Azure の権限の連鎖を、BloodHound の結果で裏づける
- [脅威パネルの読み方](reading-threats.ja.md) — 脅威カードの印と根拠の見方
- [NHI とアイデンティティ基盤の脅威モデル](nhi-identity.ja.md) — ディレクトリ・IdP まわりの脅威の描き方
