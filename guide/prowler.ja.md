# Prowler の検査結果を構成図に載せる — AWS の実測で「未入力のため仮定」を置き換える

[English](prowler.md) | **日本語**

> Prowler は各権利者の名称です。このページは「Prowler の検査結果（OCSF 形式）を CyberRiskScape の構成図に取り込む方法」を説明する
> もので、Prowler の開発者が提供・認定・推奨するものではありません。記述的な使用です。Prowler の出力の形式は、執筆時点（2026 年 10 月）の
> 公式のソースによります。最新は公式の情報で確かめてください。

> **検査してよい範囲** — Prowler で検査するのは、**自組織が管理する、または診断を許可された AWS アカウントだけ**にしてください。
> このページの取り込みは、検査済みの結果ファイルを読むだけです。AWS にも Prowler にも接続せず、新しく検査はしません。

---

## 1. このページで分かること・前提

- Prowler（OSS のクラウドセキュリティ検査ツール）が出力した検査結果で、図のノードの**運用状況と攻撃面属性のうち、まだ入力していない項目**を埋める方法
  （`import-prowler`）。これまで「未入力のため仮定」の印が付いていた脅威が、実測に基づく評価に変わります
- Prowler が **FAIL にした検査**を、図から検出した脅威と突き合わせて、設計と実態のずれを見る方法
- 資源（バケット・DB・ロードバランサなど）を図のノードに結びつける方法（タグ、または対応表）
- 値の決め方、対応している検査の一覧、**読み込まないもの**（秘密情報の扱い）、そして**限界**

**前提**

- Prowler で AWS を検査し、`-M json-ocsf` で出力した `*.ocsf.json` がある。
- 検査結果を載せる先の、CyberRiskScape のプロジェクト JSON（図を保存したもの）がある。
- Node.js が動くこと。CLI をビルドしておきます（`npm ci && npm run build:cli`）。
- **CLI 専用です。** 画面から Prowler のファイルを読み込むことはできません（§9）。出力したプロジェクト JSON は、画面の **Template** → **Import** で読み込めます。

**このページの前提となる知識**：[はじめに](getting-started.ja.md)の操作と、[脅威パネルの読み方](reading-threats.ja.md)。

---

## 2. 何ができるか・Prowler 自身の機能との分担

### 2.1 何ができるか

1. **未入力の項目を実測で埋める。** CyberRiskScape は、ノードの運用状況（保管時の暗号化・ログの取得・パッチの適用状況など）が未入力なら、
   危ない側の値として脅威を出し、カードに「未入力のため仮定」の印を付けます。Prowler の検査結果で値が分かる項目は、その値を入れます。
   PASS（良い値）も FAIL（悪い値）も入れるので、実態が良ければ脅威が消え、悪ければ根拠つきで残ります。
2. **FAIL の検査を図の脅威と突き合わせる。** 「Prowler が FAIL にした検査に対応する脅威は、図でも検出されているか」を調べます。
   図にも脅威がある（確認された）、図には無い（図に無い候補＝描き漏れや設計の見落としの手がかり）、のどちらかが分かります。

### 2.2 Prowler 自身の機能との分担

| やりたいこと | 使うもの |
|---|---|
| 検査結果の一覧・推移を見る、Security Hub や Jira に連携する、修正の担当を割り振る | **Prowler 側**（ダッシュボード・出力の連携・Prowler App） |
| AWS の実環境で、権限昇格の連鎖がどうつながっているかを調べる | **Prowler 側**（Prowler App の Attack Paths） |
| 設計段階の図に対して脅威を洗い出す。オンプレ・SaaS・AI エージェント・利用者など、**クラウドの外**を含む脅威と経路を見る | **CyberRiskScape** |
| 検査結果を、図の属性に載せて脅威の評価を実態に合わせる | このページの取り込み |

**公式の仕組みで足りるなら、そちらを先に使ってください。** このページの取り込みは、Prowler の代わりではなく、Prowler の実測を
設計の図に戻して、脅威の評価に反映するためのものです。

---

## 3. 手順

### 3.1 資源に図のノードを結びつける（タグ）

Prowler は資源の**タグ**を OCSF の `resources[].labels` に入れます。AWS の資源に、次のタグを付けてください。

| タグのキー | タグの値 |
|---|---|
| `crs-node` | 図のノードの**ノード ID**、または画面に出ている **C 番号**（例：`C3`） |

- 値は画面の要素 ID（`C3` など）が便利です。同じ C 番号が複数のレイヤーにある場合は「複数のレイヤーに該当」として結びつけず、
  報告に出ます。そのときはノード ID を使ってください。
- **1 つのノードに複数の資源を結びつけて構いません**（バケット 3 つを 1 つの「文書ストレージ」ノードに、など）。
- 1 つの資源が結びつくノードは 1 つだけです。

### 3.2 タグを付けられない資源（`--map`）

タグを付けられない資源は、資源とノードの対応表（JSON）で補います。キーは**資源の uid（ARN など）**または**資源の名前**で、
値はノード ID または C 番号です。

```json
{
  "chat-db-1": "n-db",
  "chat-db-2": "C2"
}
```

- 資源の uid を先に探し、無ければ名前で探します。
- **タグが優先**です。タグが付いている資源は、この表を見ません。
- この表はあなたが書くファイルです。ARN にアカウント ID が入るので、**公開リポジトリに置かないでください**。名前をキーにすれば避けられます。

### 3.3 Prowler を実行する

```bash
prowler aws -M json-ocsf -o ./prowler-out
```

- `*.ocsf.json` が出力先に作られます（ファイル名は Prowler が決めます）。
- **FAIL だけに絞る設定にしないでください。** PASS の結果も値を決めるのに使うため、PASS が無いと良い値を入れられません。
- OCSF のファイルは**顧客の情報**（アカウント ID・資源の設定が入っています）です。リポジトリに置かないでください。

### 3.4 取り込む

```bash
npm run build:cli
node dist-cli/main.js import-prowler my-project.json --ocsf prowler-out/<出力>.ocsf.json \
  --map prowler-map.json -o my-project.filled.json
```

| オプション | 意味 |
|---|---|
| `<project.json>` | 載せる先のプロジェクト JSON（必須） |
| `--ocsf <file>` | Prowler の OCSF（必須） |
| `--map <file>` | §3.2 の対応表（任意） |
| `--report <md\|json>` | 報告の形式。既定は `md`。標準出力に出ます |
| `-o, --out <file>` | 未入力の項目を埋めたプロジェクト JSON の出力先。**指定しなければ書き出しません**（報告だけ見たいとき） |

- **入力のプロジェクト JSON は書き換えません。** 埋めた結果は `-o` の新しいファイルに出ます。
- 報告の文面は日本語です（`--report json` のキーは英語固定で、機械処理に使えます）。
- 終了コードは、検査結果が FAIL でも食い違いがあっても 0 です（ファイルが読めないなどのエラーのときだけ 1）。CI で止めたい場合は、報告の JSON を見て判定してください。
- 標準エラー出力に、適用・同じ値・食い違い・適用できない・対応するノードが無い資源の件数が 1 行で出ます。

### 3.5 報告の実例

同梱のサンプル（§8）で実行した出力です。

```bash
node dist-cli/main.js import-prowler src/features/prowler-import/__fixtures__/sample-project.json \
  --ocsf src/features/prowler-import/__fixtures__/sample.ocsf.json \
  --map src/features/prowler-import/__fixtures__/sample-map.json -o filled.json
```

```text
# Prowler 取り込みレポート

- Prowler の検査結果を図のノードに載せた結果。入力済みの値は上書きしない（食い違いは下に出す）。
- 検査結果 16 件（検査 12 種を対応表で処理 / 対応表に無い 1 種 / MANUAL 1 件）（読めなかった 0 件・ミュート済み 1 件は除外）
- 適用 8 / 同じ値 0 / 食い違い 1 / 適用できない 1 / 対応するノードが無い資源 2
- 図の脅威との突き合わせは、結びついたノード自身の脅威とだけ行う（ノードに結びつかない資源の FAIL 2 件は突き合わせていない）

## 適用した値（未入力だった項目）

- C3 文書ストレージ の encryptionAtRest = ProviderManagedKey ← docs-bucket（s3_bucket_default_encryption=ProviderManagedKey）
- C3 文書ストレージ の logCollection = NotCollected ← docs-bucket（s3_bucket_server_access_logging_enabled=NotCollected）
- C2 会話ログDB の encryptionAtRest = None ← chat-db-1（rds_instance_storage_encrypted=ProviderManagedKey） / chat-db-2（rds_instance_storage_encrypted=None）
- C2 会話ログDB の accountReview = Irregular ← batch（iam_user_accesskey_unused=Irregular）
- C1 公開Web の attackSurface.hasGlobalIp = true ← web-alb（elbv2_internet_facing=true）
- C1 公開Web の attackSurface.hasAccessLog = true ← web-alb（elbv2_logging_enabled=true）
- C1 公開Web の logRetention = OneYearOrMore ← /web（cloudwatch_log_group_retention_policy_specific_days_enabled=OneYearOrMore）
- C1 公開Web の patchStatus = UpToDate ← i-0abc（ssm_managed_compliant_patching=UpToDate）

## 食い違い（入力済みの値と Prowler の値が違うため適用していない）

- C5 旧ストレージ の encryptionAtRest: 現在 None / Prowler ProviderManagedKey ← legacy-bucket（s3_bucket_default_encryption=ProviderManagedKey）

## 適用できない（ノードの型がその項目を持たない）

- C4 社内ツール（TOOL）の encryptionAtRest: Prowler CustomerManagedKey ← m1（bedrock_custom_model_encrypted_with_cmk=CustomerManagedKey）

## 鍵の種類を確認してください（Prowler では判別できない。CMK なら顧客管理の鍵に変更）

- C3 文書ストレージ の encryptionAtRest = ProviderManagedKey ← docs-bucket（s3_bucket_default_encryption）

## 対応するノードが無い資源

- vol-0aaa（ec2 / AwsEc2Volume / ap-northeast-1）: タグ crs-node も --map の対応も無い — 検査 ec2_ebs_volume_encryption
- ghost-bucket（s3 / AwsS3Bucket / ap-northeast-1）: 指定されたノードが図に無い（指定: n-missing） — 検査 s3_bucket_default_encryption

## 図の脅威と突き合わせ（FAIL の検査）

### 確認された（結びついたノードの脅威に Prowler の FAIL の裏付けがある）

- **data-at-rest-unencrypted** — 図の脅威: [Medium] 保管時に暗号化していない（媒体・バックアップ・スナップショットの持ち出しで読まれる）
  - chat-db-2（C2 会話ログDB） — rds_instance_storage_encrypted
- **log-not-collected** — 図の脅威: [Medium] ログを取得していない（侵害の検知・調査ができない）
  - docs-bucket（C3 文書ストレージ） — s3_bucket_server_access_logging_enabled
- **storage-public-access-misconfiguration** — 図の脅威: [High] ストレージの公開設定の誤りによるデータ露出
  - docs-bucket（C3 文書ストレージ） — s3_bucket_public_access
- **web-global-ip-exposure** — 図の脅威: [High] グローバルIP直接公開
  - web-alb（C1 公開Web） — elbv2_internet_facing

### 図に無い候補（Prowler は FAIL だが図からは検出されていない）

- **nhi-long-lived-secret**
  - batch（C2 会話ログDB） — iam_user_accesskey_unused

### ノードに結びつかないため突き合わせていない（FAIL）

- **data-at-rest-unencrypted**
  - vol-0aaa — ec2_ebs_volume_encryption
  - ghost-bucket — s3_bucket_default_encryption

### 対応づけできない（FAIL だが脅威の対応が無い検査）

- some_unknown_check [Medium] title of some_unknown_check × 1
```

読み方（見出しの意味）：

| 見出し | 意味 |
|---|---|
| 適用した値 | 未入力だった項目に、Prowler の値を入れた。「←」の右が根拠（資源と検査 ID ごとの値） |
| 食い違い | すでに入力してある値と Prowler の値が違う。**適用していない**ので、どちらが実態かを確かめて直す |
| 適用できない | ノードの型がその項目を持たない（例：社内ツール型には「保管時の暗号化」が無い）。適用せず報告だけ |
| 対応するノードが無い資源 | タグも `--map` も無い、またはタグが指すノードが図に無い。**図に描き足す・タグを直す**手がかり |
| 鍵の種類を確認してください | 鍵の種類を判別できない検査で「事業者管理の鍵」を入れた項目。**CMK を使っているなら顧客管理の鍵に直す** |
| 確認された | FAIL の検査に対応する脅威が、結びついたノード自身の脅威として図でも検出されている |
| 図に無い候補 | Prowler は FAIL だが、結びついたノードでその脅威が検出されていない（そのノードに属性・線が足りない可能性） |
| 結びつかないため突き合わせていない | ノードに結びつかない資源の FAIL。確認された・図に無い候補のどちらにも数えない。**図に描き足す・タグを直す**と突き合わせられる |
| 対応づけできない | FAIL だが、対応表に脅威の対応が無い検査 |

> 突き合わせは、**資源が結びついたノード自身の脅威**とだけ行います（そのノードにつながる線の脅威は見ません）。
> ノードに結びつかない資源（上の例の `vol-0aaa`・`ghost-bucket`）の FAIL は、図のどこかに同じ種類の脅威があっても確認扱いにせず、「突き合わせていない」に件数と一覧を出します。

### 3.6 埋めた図を画面で見る

`-o` で出したプロジェクト JSON は、そのまま画面に読み込めます。**Template** → **Import** タブで「JSON ファイルを選択」し、「置き換えて適用」を押します
（手順は [作業ディレクトリを脅威モデルにする](repo-import.ja.md) の §3 と同じです）。埋めた項目はノードの運用状況・攻撃面属性に入り、
その分の「未入力のため仮定」の印が消えます。

---

## 4. 値の決め方

- **PASS も FAIL も入れる。** 対応表に値がある結果なら、どちらも属性の値になります。
- **1 つの資源の中では、検査どうしで最も良い値。** 同じ資源に同じ項目の検査が複数あれば、一番良い値を採ります
  （例：バケット 1 つで、ある検査は事業者管理の鍵、別の検査は自組織管理の鍵なら、後者）。
- **ノードでは、資源どうしで最も悪い値。** 1 つのノードに資源が複数結びつくときは、一番悪い値を採ります
  （上の例：`C2` は RDS 2 台のうち 1 台が暗号化なし → 「なし」）。
- **入力済みの値は上書きしない。** ノードにすでに値があって、Prowler の値と違えば「食い違い」として報告に出すだけです。同じ値なら「同じ値」に入ります。
- **型が持たない項目は適用しない。** 「適用できない」に出ます。
- **棚卸し（アカウント棚卸し）は FAIL のときだけ「不定期」。** 未使用・ローテーションの検査に通っても、棚卸しの運用が「定期的に実施」とは言えないため、PASS では何も入れません。
- **値を入れない結果もあります。** 顧客管理鍵（CMK）の検査は、PASS のときだけ「自組織管理の鍵」を入れます。FAIL は既定の暗号化が有効かどうかを示さないため、値を入れません。
  KMS の暗号化の検査も、AWS 管理鍵と CMK を区別しないので、PASS でも「事業者管理の鍵」までです。DynamoDB は既定で暗号化済みのため、FAIL を「なし」にしません。
- **「事業者管理の鍵」は鍵の種類が未確認です。** 既定の暗号化・KMS の検査は、CMK でも PASS になるため、値は入れますが報告の「鍵の種類を確認してください」に出します。
  ノードに入力済みの値が「自組織管理の鍵」なら、食い違いにせず上書きもしません（「なし」なら食い違い）。1 つの資源で CMK を判別できる検査（Bedrock の 3 件）が PASS なら、そちらの「自組織管理の鍵」を優先します。
- **ミュート済みは除外。** Prowler でミュートした（`Suppressed`）検査結果は読みません。**MANUAL**（人の確認が要る検査）は件数を数えるだけで、値にも突き合わせにも使いません。
- 対応表に載っていない検査は、値にも突き合わせにも使いません。FAIL のものは「対応づけできない」に出ます。

属性の値の良し悪し（悪い → 良い）：

| 属性（画面の表示名） | 悪い → 良い |
|---|---|
| 保管時の暗号化 | なし → あり（事業者管理の鍵）→ あり（自組織管理の鍵） |
| ログの取得 | 取得していない → 取得している |
| ログの保持期間 | 90日未満 → 1年未満 → 1年以上 |
| パッチの適用状況 | 未適用あり → 最新 |
| アカウント棚卸し | 実施していない → 不定期 → 定期的に実施 |
| アクセスログ（攻撃面属性） | 無し → 有り |
| グローバル IP（攻撃面属性） | 有り → 無し |

---

## 5. 対応している検査の一覧

対応表は `data/finding-maps/prowler.yaml` です（脅威の知識と同じく、コードではなく YAML にあります）。第 1 段として **AWS の一部の検査**に対応しています。

| 分類 | 検査 ID | 入る属性（結果ごとの値） | 突き合わせる脅威（canonicalId） |
|---|---|---|---|
| 保管時の暗号化（既定。鍵の種類は未確認） | `s3_bucket_default_encryption`<br>`rds_instance_storage_encrypted`<br>`rds_cluster_storage_encrypted`<br>`rds_snapshots_encrypted`<br>`ec2_ebs_volume_encryption`<br>`ec2_ebs_snapshots_encrypted`<br>`efs_encryption_at_rest_enabled`<br>`redshift_cluster_encrypted_at_rest`<br>`opensearch_service_domains_encryption_at_rest_enabled` | 保管時の暗号化：PASS → 事業者管理の鍵 / FAIL → なし | `data-at-rest-unencrypted` |
| KMS による暗号化（鍵の種別は区別しない。種類は未確認） | `s3_bucket_kms_encryption`<br>`dynamodb_tables_kms_cmk_encryption_enabled` | 保管時の暗号化：PASS → 事業者管理の鍵 | — |
| Bedrock の顧客管理鍵（CMK を判別できる） | `bedrock_custom_model_encrypted_with_cmk`<br>`bedrock_knowledge_base_encrypted_with_cmk`<br>`bedrock_prompt_encrypted_with_cmk` | 保管時の暗号化：PASS → 自組織管理の鍵 | — |
| ログの取得 | `s3_bucket_server_access_logging_enabled`<br>`cloudtrail_multi_region_enabled`<br>`bedrock_model_invocation_logging_enabled`<br>`rds_instance_integration_cloudwatch_logs`<br>`rds_cluster_integration_cloudwatch_logs`<br>`redshift_cluster_audit_logging`<br>`opensearch_service_domains_audit_logging_enabled` | ログの取得：PASS → 取得している / FAIL → 取得していない | `log-not-collected` |
| Bedrock の入出力本文のログ | `bedrock_model_invocation_logging_text_data_enabled` | — | `log-not-collected` |
| API・ロードバランサのアクセスログ | `apigateway_restapi_logging_enabled`<br>`apigatewayv2_api_access_logging_enabled`<br>`elb_logging_enabled`<br>`elbv2_logging_enabled` | アクセスログ（攻撃面）：PASS → 有り / FAIL → 無し | `web-missing-access-log` |
| ログの保持期間（既定のしきい値 365 日） | `cloudwatch_log_group_retention_policy_specific_days_enabled` | ログの保持期間：PASS → 1年以上 | `log-retention-insufficient` |
| パッチ準拠（SSM） | `ssm_managed_compliant_patching` | パッチの適用状況：PASS → 最新 / FAIL → 未適用あり | `known-vulnerability-unpatched` |
| 未使用・ローテーションされないアクセスキー | `iam_user_accesskey_unused`<br>`iam_rotate_access_key_90_days` | アカウント棚卸し：FAIL → 不定期 | `nhi-long-lived-secret` |
| 未使用のコンソールアクセス | `iam_user_console_access_unused` | アカウント棚卸し：FAIL → 不定期 | — |
| シークレットのローテーション | `secretsmanager_automatic_rotation_enabled`<br>`secretsmanager_secret_rotated_periodically` | — | `nhi-long-lived-secret` |
| インターネットからの到達性 | `ec2_instance_public_ip`<br>`elb_internet_facing`<br>`elbv2_internet_facing`<br>`apigateway_restapi_public` | グローバル IP（攻撃面）：PASS → 無し / FAIL → 有り | `web-global-ip-exposure` |
| ストレージ・DB の公開 | `s3_bucket_public_access`<br>`s3_bucket_level_public_access_block`<br>`s3_bucket_policy_public_write_access`<br>`s3_bucket_public_list_acl`<br>`s3_bucket_public_write_acl`<br>`s3_bucket_object_public`<br>`rds_instance_no_public_access`<br>`rds_snapshots_public_access`<br>`cloudtrail_logs_s3_bucket_is_not_publicly_accessible` | — | `storage-public-access-misconfiguration` |
| MFA | `iam_user_mfa_enabled_console_access`<br>`iam_user_hardware_mfa_enabled`<br>`iam_root_mfa_enabled` | — | `password-only-internet-channel` |
| 過大な IAM 権限 | `iam_role_administratoraccess_policy`<br>`iam_user_administrator_access_policy`<br>`iam_aws_attached_policy_no_administrative_privileges`<br>`iam_policy_allows_privilege_escalation` | — | `nhi-overprivileged` |
| Bedrock のガードレール | `bedrock_guardrails_configured`<br>`bedrock_guardrail_prompt_attack_filter_enabled`<br>`bedrock_guardrail_sensitive_information_filter_enabled`<br>`bedrock_guardrail_sensitive_information_filter_enforced`<br>`bedrock_guardrail_contextual_grounding_filter_enabled`<br>`bedrock_agent_guardrail_enabled` | — | `guardrail-probabilistic-bypass`, `direct-prompt-injection` |
| Bedrock エージェントのロール | `bedrock_agent_role_least_privilege`<br>`bedrock_agent_role_not_shared_across_agents`<br>`bedrock_full_access_policy_attached` | — | `excessive-agency`, `nhi-overprivileged` |
| Bedrock API キーの権限 | `bedrock_api_key_no_administrative_privileges` | — | `nhi-overprivileged` |
| Bedrock API キーの有効期間 | `bedrock_api_key_no_long_term_credentials` | — | `nhi-long-lived-secret`, `credential-sprawl` |
| Bedrock の VPC エンドポイント | `bedrock_vpc_endpoints_configured` | — | `private-endpoint-data-exfiltration` |

- 「—」は、その欄に当てはまるものが無いことを表します。属性が「—」の検査は、**突き合わせだけ**に使います（MFA など、ノードの属性ではなく線や運用の話のもの）。
- 突き合わせる脅威は、脅威ライブラリの `canonicalId` です。FAIL の検査が、同じ `canonicalId` の脅威が図で検出されているかを見ます。
- 検査 ID は Prowler のリポジトリ（`prowler/providers/aws/services/`）にあるものだけを載せています。検査の説明文は転載していません。

---

## 6. 秘密情報の扱い

OCSF のファイルには、アカウント ID や資源の設定の中身が入っています。取り込みは次のように扱います。

- **読まないもの**：`resources[].data`（資源の設定全体）・`cloud.account`・`cloud.org`（アカウント ID・組織）・`risk_details` などの長い説明文。
- **URL の userinfo とクエリ・フラグメントは捨てる。** 資源の名前や uid に URL が入っていても、`user:pass@` や `?token=…` は残しません。
- **報告の資源名は名前を優先。** 名前が無いときだけ uid（ARN）を使い、12 桁のアカウント ID は `*` に伏せます。
- ARN（uid）は、資源とノードの対応付けにだけ使います。
- **出力するプロジェクト JSON に入るのは、運用状況・攻撃面属性の値だけです。** 資源名・ARN は入りません（報告にだけ出ます）。
- **OCSF ファイルと `--map` のファイルは顧客の情報です。** 公開のリポジトリ・チケット・チャットに置かないでください。

---

## 7. ユースケース

- **設計レビューの前に、実測を図に反映する。** タグを付けて取り込み、「未入力のため仮定」で出ていた脅威のうち、実測で良いと分かったものを消します。
  FAIL のものは、根拠つきで対策の優先順位を決める材料になります。
- **食い違いを手がかりに、図か実態のどちらかを直す。** 図に「暗号化あり」と入れてあるのに Prowler が FAIL なら、図が間違っているか、実態が設計から外れています。
- **「対応するノードが無い資源」「図に無い候補」から、描き漏れを見つける。** 検査では見えているのに図に無い資源は、脅威の洗い出しから漏れている資産です。
- 取り込み後の図で、攻撃経路を調べる — [攻撃経路分析](attack-paths.ja.md)

> **ひとこと** — 実測は「いま」の値です。取り込んだ値は図の属性として残りますが、その後の構成の変更には自動では追従しません。
> 定期的に Prowler を実行して取り込み直すか、変更のたびに図を直してください。

---

## 8. 同梱のサンプル

Prowler の出力処理（`prowler/lib/outputs/ocsf/ocsf.py`）の形に合わせた**架空の**サンプルを置いています（アカウント ID・資源名はすべてダミーです）。

| ファイル | 内容 |
|---|---|
| [`sample.ocsf.json`](../src/features/prowler-import/__fixtures__/sample.ocsf.json) | Prowler の OCSF の形のサンプル（17 件。ミュート済み 1・MANUAL 1・対応表に無い検査 1 を含む） |
| [`sample-project.json`](../src/features/prowler-import/__fixtures__/sample-project.json) | 載せる先の図（5 ノード） |
| [`sample-map.json`](../src/features/prowler-import/__fixtures__/sample-map.json) | タグの無い資源の対応表 |

---

## 9. 限界

- **動作確認は、Prowler の出力処理（`ocsf.py`）に合わせた架空のサンプルで行っています。実環境の Prowler の出力では確かめていません。**
  項目の名前や形が異なると、読み込めない項目は「読めなかった」件数として報告に出ます。最初は件数が想定どおりかを確かめてください。
- **対応するのは AWS の一部の検査だけです。** Azure・GCP・Kubernetes など、ほかのプロバイダーと、載っていない検査は、値にも突き合わせにも使いません。
- **MFA などの、線（エッジ）の属性には入れません。** 突き合わせの報告にだけ出ます。
- **ログの保持期間は、Prowler の設定の既定（365 日）が前提です。** しきい値を変えていると、PASS が 1 年以上を意味しません。そのときは対応表を直してください。
- **画面からの取り込みと、Prowler の API・Prowler App からの取得には対応していません。** CLI でファイルを読む方式だけです。
- **検査は検査した時点のものです。** 図の属性に入れた値は、その後の構成の変更に自動では追従しません。
- **ノードを新しく作ることはしません。** タグも対応表も無い資源は、「対応するノードが無い資源」として報告に出るだけです。

---

## 参考リンク

1. Prowler（GitHub） — <https://github.com/prowler-cloud/prowler>
2. Prowler のドキュメント — <https://docs.prowler.com/>
3. Prowler Hub（検査の一覧） — <https://hub.prowler.com/>

---

## 次に読むもの

- 脅威の読み方 — [脅威パネルの読み方](reading-threats.ja.md)
- 属性の入力と脅威の消し方 — [はじめに](getting-started.ja.md)
- 突き合わせの考え方が近い連携 — [Veracode の指摘を AI で直す](veracode-remediation.ja.md)
- 外部露出の観測を図にする — [ScopeSentry の観測結果を構成図にする](scopesentry.ja.md)
- 診断の計画を作る — [脅威モデルからペネトレーションテスト計画書を作る](pentest-plan.ja.md)
