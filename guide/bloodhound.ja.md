# BloodHound CE の結果を構成図に載せる — AD の権限の問題で、脅威を実データで裏づける

[English](bloodhound.md) | **日本語**

> このページに出てくる製品名は、各権利者の名称です。このページは「BloodHound Community Edition（CE）の問い合わせの結果を
> CyberRiskScape に取り込む方法」を説明するもので、BloodHound の開発者が提供・認定・推奨するものではありません。記述的な使用です。
> 応答の形式・辺の名前は、執筆時点（2026 年 11 月）の公式のソースによります。最新は公式の情報で確かめてください。

> **確認してよい範囲** — BloodHound への接続と収集は、**自組織が管理する、または診断を許可された AD だけ**に対して行ってください。
> CyberRiskScape は AD に接続せず、収集（SharpHound など）も実行しません。読むのは BloodHound CE の問い合わせの結果だけです。

---

## 1. このページで分かること・前提

BloodHound CE（SpecterOps、Apache-2.0）は、Active Directory（AD）や Entra ID の権限と攻撃経路をグラフで分析する OSS です。
CyberRiskScape は AD のオブジェクトを図には描きません。代わりに BloodHound の問い合わせ（Cypher）の結果を**指摘**として、図のディレクトリ（AD）ノードと認証局（CA）ノードに載せます。
構成から「前提」で出していた脅威（委任の悪用・複製権限の悪用など）が、**実データで裏づけられます**。

AD に加えて、Entra ID のアプリ・サービスプリンシパルの権限の問題を図の **IdP** に、Azure のリソースの権限の問題を **IaaS / PaaS** と**シークレット管理**に載せます（§2・§3）。

**前提**

- 指摘を載せる先の、CyberRiskScape のプロジェクト JSON がある。図に**ディレクトリ**（AD）のノードがある。AD CS（証明書サービス）を使っているなら**認証局（CA）**も置く（§3）。
- BloodHound CE を自分で立てて、収集済みのデータを取り込んである。**収集は BloodHound 側で行います。**Entra ID と Azure のデータは AzureHound で収集しておきます。
- Node.js が動くこと。CLI をビルドしておきます（`npm ci && npm run build:cli`）。
- **CLI 専用です。** 出力したプロジェクト JSON は、画面の **Template** → **Import** で読み込めます。

**このページの前提となる知識**：[はじめに](getting-started.ja.md)の操作と、[脅威パネルの読み方](reading-threats.ja.md)。

---

## 2. 何ができるか

同梱の 16 本の問い合わせを BloodHound に送り、該当する主体の件数を数えて、対応する脅威に結びつけます。

| 問い合わせ | 対応する脅威 | 載せる先 |
|---|---|---|
| Kerberoasting の対象になる有効なユーザー（SPN を持つ） | ディレクトリ発行チケットのオフライン解析（Kerberoasting / AS-REP ロースティング） | ディレクトリ |
| 事前認証を求めない有効なユーザー（AS-REP の対象） | 同上 | ディレクトリ |
| Tier Zero 以外で複製権限（DCSync）を持つ主体 | ディレクトリ複製権限の悪用による資格情報コーパスの一括取得 | ディレクトリ |
| Tier Zero 以外でローカル管理者パスワード（LAPS）を読める主体 | ローカル管理者パスワード（LAPS）の読み取り権限の過剰付与 | ディレクトリ |
| 制約なし委任が有効なコンピューター | Kerberos 委任の悪用（任意ユーザへのなりすまし） | ディレクトリ |
| 制約付き委任・リソースベースの委任（RBCD）を持つ主体 | 同上 | ディレクトリ |
| Tier Zero 以外で GPO を書き換えられる主体 | ディレクトリ配布ポリシーの改ざんによる横展開・永続化 | ディレクトリ |
| 証明書テンプレート・認証局の設定不備でドメインを取れる主体（AD CS の ESC 系） | 証明書テンプレートの設定不備による任意の利用者のなりすまし | 認証局 |
| 証明書の登録の窓口への NTLM リレーでドメインを取れる主体 | 証明書の登録の窓口への NTLM リレー | 認証局 |
| 認証局の鍵で証明書を偽造できる主体（GoldenCert） | 認証局の秘密鍵・管理権限の奪取による証明書の偽造 | 認証局 |
| Tier Zero 以外でアプリ・サービスプリンシパルに資格情報を追加できる主体（所有者・資格情報や所有者を追加できる権限）（Entra ID） | 登録アプリへの資格情報の追加によるアプリの乗っ取り | IdP |
| Tier Zero のサービスプリンシパル（Entra ID） | アプリ単独（app-only）でテナント全体を操作できる特権 | IdP |
| ロール・アプリの権限・所有者を付与できる Graph の権限を持つアプリ（Entra ID） | 同上 | IdP |
| Tier Zero 以外でサブスクリプション・管理グループを支配できる主体（所有者・ユーザーアクセス管理者）（Azure） | クラウドの管理権限（所有者・アクセス管理者）の過剰な付与 | IaaS / PaaS |
| Tier Zero 以外で VM・コンテナ・Web アプリ・Automation でコードを実行できる主体（Azure） | リソース上でのコード実行権限の過剰な付与（ワークロード ID の権限の奪取） | IaaS / PaaS |
| Tier Zero 以外で Key Vault の秘密・鍵・証明書を読める主体（Azure） | シークレット管理への権限集中 | シークレット管理 |

- 「Tier Zero 以外」の問い合わせでは、BloodHound の **Tier Zero の印**が付いた主体（ドメイン管理者・ディレクトリサーバーなど、正当にその権限を持つもの）は数えません。判定は BloodHound に任せています。
- 問い合わせと対応は、読み取りだけ（`MATCH … RETURN`）で書かれています。書き込みの Cypher は同梱の対応表で禁止しており、BloodHound CE 自体も既定で拒否します。

---

## 3. 図の準備

指摘は図のノードに載せます。次の種類を置きます（Entra ID・Azure を使わなければ、IdP・IaaS / PaaS・シークレット管理は不要です）。

| ノード | 置くもの |
|---|---|
| **ディレクトリ**（Identity & Access） | AD。Kerberoasting・委任・複製権限・LAPS・GPO の指摘が載る |
| **認証局（CA）**（Identity & Access。**新しい型**） | AD CS を使っている場合の認証局。証明書テンプレートと登録の窓口（Web 登録・RPC）を含む。AD CS の指摘が載る |
| **IdP**（Identity & Access） | Entra ID。アプリ・サービスプリンシパルの権限の指摘が載る |
| **IaaS** または **PaaS** | Azure のサブスクリプション。管理の範囲・コード実行の指摘が載る |
| **シークレット管理** | Azure の Key Vault。Key Vault の指摘が載る |

**IdP が図に無いと、Entra ID の指摘は未結合になります**（ディレクトリには載せません）。同じく、IaaS / PaaS が無ければ Azure の管理の範囲・コード実行の指摘、シークレット管理が無ければ Key Vault の指摘が未結合になります。

IdP には、アプリ登録を持つ IdP 一般の脅威として、次の 2 つの脅威ルールが付いています（Entra ID に限りません）。「BloodHound で確認」の印も、同じ脅威に出ます。

- 登録アプリへの資格情報の追加によるアプリの乗っ取り
- アプリ単独（app-only）でテナント全体を操作できる特権

IaaS・PaaS には、Azure に限らず AWS・Google Cloud にも当てはまる一般の脅威として、次の 2 つの脅威ルールが付いています。「BloodHound で確認」の印も、同じ脅威に出ます。

- クラウドの管理権限（所有者・アクセス管理者）の過剰な付与
- リソース上でのコード実行権限の過剰な付与（ワークロード ID の権限の奪取）

Key Vault の指摘は、シークレット管理の既存の脅威（シークレット管理への権限集中）に結びつきます。

認証局の型には、次の 3 つの脅威ルールが付いています。AD CS を使っているなら、図に置いてください。

- 証明書テンプレートの設定不備による任意の利用者のなりすまし
- 証明書の登録の窓口への NTLM リレー
- 認証局の秘密鍵・管理権限の奪取による証明書の偽造

認証局を置かなければ、AD CS の指摘はディレクトリのノードに載ります。

---

## 4. 取り込み

入口は 2 つです。どちらか一つで足ります。

### 4.1 API で取り込む（CLI のみ）

BloodHound の「API トークン」（トークン ID とトークンキー）を環境変数で渡します。トークンは保存も出力もしません。

```bash
export BLOODHOUND_TOKEN_ID=<トークン ID>
export BLOODHOUND_TOKEN_KEY=<トークンキー>
node dist-cli/main.js import-bloodhound my-project.json --api https://bloodhound.example.com -o out.json
```

- 署名付きのリクエストで `POST /api/v2/graphs/cypher` に、**同梱の問い合わせだけ**を送ります。読み取りのみです。
- `https` のみです（`localhost` は `http` も可）。

### 4.2 ファイルで取り込む

BloodHound に自分で問い合わせるときは、同梱の問い合わせを出します。

```bash
node dist-cli/main.js import-bloodhound --print-queries
```

出力は問い合わせの id・題名・Cypher の JSON です。各問い合わせを実行し、応答の JSON を `<問い合わせ id>.json` という名前でフォルダに置いて、そのフォルダを指定します。

```bash
node dist-cli/main.js import-bloodhound my-project.json --in ./bh-responses -o out.json
```

該当が 0 件のときの応答（HTTP 404 の `resource not found`）も、0 件として読みます。

### 4.3 どのノードに載せるか

| 指摘 | 載せる先 |
|---|---|
| AD CS 以外の指摘 | 図にディレクトリがちょうど 1 つあればそれ。複数あるときは `--node C1`（C 番号かノード ID） |
| AD CS の指摘 | 認証局。複数あるときは `--ca-node C2`。認証局が無ければディレクトリ |
| Entra ID の指摘 | IdP。図にちょうど 1 つあればそれ。複数あるときは `--idp-node C3`。IdP が無ければ未結合 |
| Azure の管理の範囲・コード実行の指摘 | IaaS または PaaS（どちらか、ちょうど 1 つあればそれ）。複数あるときは `--cloud-node C4`。無ければ未結合 |
| Azure の Key Vault の指摘 | シークレット管理。図にちょうど 1 つあればそれ。複数あるときは `--vault-node C5`。無ければ未結合 |

Azure の指摘は、観測ごとに 1 件で、リソースごとには分けません（サブスクリプションや Key Vault が複数あっても、1 つのノードにまとめて載ります）。

ドメインごとに分けて取り込むときは `--scope` を使います（既定は `default`）。**取り込み直しは、同じ scope の指摘を置き換えます。**別の scope の指摘は残ります。

```bash
node dist-cli/main.js import-bloodhound my-project.json --api https://bloodhound.example.com \
  --node C1 --ca-node C2 --idp-node C3 --cloud-node C4 --vault-node C5 --scope corp.example.com -o out.json
```

`--report <md|json>` で、問い合わせごとの件数の報告の形式を選べます（既定は `md`。標準出力）。

---

## 5. 結果の見方

- **脅威カード**：裏づけられた脅威のカードに「**BloodHound で確認**」の印が出ます。印は、その脅威が前提ではなく実データで確かめられたことを示します。
- **レポート**：`findings-report`・`findings-priority` に、指摘として入ります。SARIF 書き出しにも入ります。
- **件数**：指摘 1 件が 1 つの問い合わせに当たります。本文には、問題を持つ主体の件数と、資産の名前（§6）が入ります。

どの順に辿れば侵害に至るかは、BloodHound の画面で見てください（§7）。

---

## 6. 個人情報の扱い

| 種類 | 扱い |
|---|---|
| ユーザー（Entra ID・Azure のユーザーを含む）の名前 | **保存しません。**件数だけを残します |
| コンピューター・グループ・GPO・OU・証明書テンプレート・認証局・ドメイン・アプリ・サービスプリンシパル・ロール・マネージド ID・サブスクリプション・VM・Key Vault などの名前 | 資産の情報として残します（指摘 1 件に最大 20 件） |
| SID などの内部識別子 | 保存しません |

---

## 7. 限界

- **攻撃経路そのもの（どの順に辿るか）は BloodHound で見ます。** CyberRiskScape は件数と、脅威への対応づけまでです。
- BloodHound **Enterprise** 版の「攻撃経路の検出結果」の API は使いません。CE の Cypher だけです。
- 収集（SharpHound など）は、利用者が BloodHound 側で行います。
- Entra ID は、アプリ・サービスプリンシパルの権限（3 本の問い合わせ）が対象です。Azure は、サブスクリプション・管理グループの支配、コード実行、Key Vault の読み取り（3 本の問い合わせ）が対象です。それ以外のリソースの権限は対象外です。
- 動作確認は、BloodHound CE の公式の docker-compose をローカルで起動し、公式リポジトリのテスト用の収集データを取り込んで行いました（2026-11-15。API の署名・0 件の扱い・AD CS の ESC の検出（3 件）・Tier Zero の除外）。Entra ID の 3 本と Azure の 3 本の問い合わせは、BloodHound CE に受け付けられ、データが無い状態で 0 件として読めることを確かめました。**Entra ID・Azure の実データでは未確認です**（公式のテスト用の収集データに含まれないため。対応づけは架空のデータで確かめています）。**実際の組織の AD でも確かめていません。**

---

## 8. 参考リンク

- BloodHound（SpecterOps）：https://github.com/SpecterOps/BloodHound

---

## 9. 次に読むもの

- [脅威パネルの読み方](reading-threats.ja.md) — 脅威カードの印と根拠の見方
- [OSS で組む脆弱性管理](oss-vulnerability-management.ja.md) — 指摘を攻撃経路の上で優先順位付けする共通の流れ
- [NHI とアイデンティティ基盤の脅威モデル](nhi-identity.ja.md) — ディレクトリ・IdP まわりの脅威の描き方
