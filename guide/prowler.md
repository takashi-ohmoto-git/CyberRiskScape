# Put Prowler Findings on the Diagram — Replace "Assumed Because Unset" with AWS Measurements

**English** | [日本語](prowler.ja.md)

> Prowler is a name of its respective owners. This page explains how to import Prowler findings (OCSF format) into a CyberRiskScape diagram.
> It is not provided, certified, or endorsed by the developers of Prowler; the use of the name is descriptive. The output format of
> Prowler follows the official sources as of the time of writing (October 2026). Check the official information for the latest.

> **Scope of scanning** — Scan with Prowler only **AWS accounts you manage or are authorized to assess**. The import on this page only reads a
> result file that already exists. It does not connect to AWS or Prowler and does not run any new scan.

---

## 1. What this page covers and prerequisites

- How to use the findings output by Prowler (an OSS cloud security scanner) to fill in the **operational posture and attack surface
  attributes that are still unset** on diagram nodes (`import-prowler`). Threats that carried an "assumed because unset" mark are
  re-evaluated on measured values
- How to cross-check the checks Prowler marked **FAIL** against the threats detected from the diagram, and see where design and reality differ
- How to tie resources (buckets, databases, load balancers, and so on) to nodes on the diagram (tags, or a mapping file)
- How values are decided, the list of supported checks, **what is not read** (handling of secrets), and the **limits**

**Prerequisites**

- You have scanned AWS with Prowler and have the `*.ocsf.json` written by `-M json-ocsf`.
- You have the CyberRiskScape project JSON (a saved diagram) to put the findings on.
- Node.js runs. Build the CLI first (`npm ci && npm run build:cli`).
- **This is CLI only.** You cannot load a Prowler file from the screen (§9). The project JSON the command writes can be loaded from **Template** → **Import**.

**Background knowledge for this page**: the basics in [Getting Started](getting-started.md) and [Reading the Threat Panel](reading-threats.md).

---

## 2. What you can do, and how it divides with Prowler's own features

### 2.1 What you can do

1. **Fill unset items with measurements.** When a node's operational posture (encryption at rest, log collection, patch status, and so on) is unset,
   CyberRiskScape raises threats as if the value were the risky one and marks the card "assumed because unset". For an item whose value Prowler's
   findings reveal, that value is entered. Both PASS (good value) and FAIL (bad value) are entered, so the threat disappears when reality is good
   and stays, with its evidence, when it is bad.
2. **Cross-check FAIL checks against the threats on the diagram.** It checks "is the threat that corresponds to a check Prowler marked FAIL also
   detected on the diagram?" You see either that the diagram has the threat too (confirmed) or that it does not (candidate not in the diagram: a clue to
   something missing from the drawing or overlooked in the design).

### 2.2 How it divides with Prowler's own features

| What you want | What to use |
|---|---|
| See the list and trend of findings, integrate with Security Hub or Jira, assign fixes | **Prowler** (dashboards, output integrations, Prowler App) |
| Investigate how privilege escalation chains connect in your real AWS environment | **Prowler** (Attack Paths in Prowler App) |
| Find threats against a design-stage diagram, including threats and paths **outside the cloud**: on-premises, SaaS, AI agents, users | **CyberRiskScape** |
| Put findings on the diagram's attributes so the threat evaluation matches reality | The import on this page |

**If the official features are enough, use them first.** The import on this page does not replace Prowler. It brings Prowler's measurements back
to the design diagram so they are reflected in the threat evaluation.

---

## 3. Steps

### 3.1 Tie resources to diagram nodes (tags)

Prowler puts a resource's **tags** into `resources[].labels` of the OCSF. Add this tag to the AWS resource.

| Tag key | Tag value |
|---|---|
| `crs-node` | The **node ID** of the diagram node, or the **C number** shown on the screen (for example `C3`) |

- The element ID on the screen (such as `C3`) is convenient. If the same C number exists in more than one layer, the resource is not tied ("matches more than one layer")
  and appears in the report. In that case use the node ID.
- **You may tie several resources to one node** (three buckets to one "document storage" node, for example).
- One resource ties to exactly one node.

### 3.2 Resources you cannot tag (`--map`)

Cover resources you cannot tag with a resource-to-node mapping file (JSON). The key is the **resource uid (such as the ARN)** or the **resource name**, and
the value is a node ID or a C number.

```json
{
  "chat-db-1": "n-db",
  "chat-db-2": "C2"
}
```

- The resource uid is looked up first, then the name.
- **Tags take priority.** A resource that has the tag does not consult this file.
- You write this file yourself. ARNs contain the account ID, so **do not put it in a public repository**. Using names as keys avoids that.

### 3.3 Run Prowler

```bash
prowler aws -M json-ocsf -o ./prowler-out
```

- A `*.ocsf.json` is created in the output directory (Prowler decides the file name).
- **Do not narrow the run to FAIL only.** PASS results are also used to decide values; without PASS, good values cannot be entered.
- An OCSF file is **customer information** (it holds account IDs and resource configuration). Do not put it in a repository.

### 3.4 Import

```bash
npm run build:cli
node dist-cli/main.js import-prowler my-project.json --ocsf prowler-out/<output>.ocsf.json \
  --map prowler-map.json -o my-project.filled.json
```

| Option | Meaning |
|---|---|
| `<project.json>` | The project JSON to put the findings on (required) |
| `--ocsf <file>` | The Prowler OCSF file (required) |
| `--map <file>` | The mapping file from §3.2 (optional) |
| `--report <md\|json>` | Report format. Default `md`. Written to standard output |
| `-o, --out <file>` | Where to write the project JSON with unset items filled. **Nothing is written if you omit it** (when you only want the report) |

- **The input project JSON is not modified.** The filled result goes to the new file given by `-o`.
- The text of the report is in Japanese (the keys of `--report json` are fixed in English and suit machine processing).
- The exit code is 0 even if there are FAIL results or conflicts (1 only for errors such as an unreadable file). To stop a CI job, judge from the JSON report.
- Standard error carries a one-line count of applied, unchanged, conflicts, not applicable, and resources without a node.

### 3.5 A real report

This is the output from running the bundled sample (§8). The report text is in Japanese; the table below the output explains the headings.

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

## 対応するノードが無い資源

- vol-0aaa（ec2 / AwsEc2Volume / ap-northeast-1）: タグ crs-node も --map の対応も無い — 検査 ec2_ebs_volume_encryption
- ghost-bucket（s3 / AwsS3Bucket / ap-northeast-1）: 指定されたノードが図に無い（指定: n-missing） — 検査 s3_bucket_default_encryption

## 図の脅威と突き合わせ（FAIL の検査）

### 確認された（図の脅威に Prowler の FAIL の裏付けがある）

- **data-at-rest-unencrypted** — 図の脅威: [Medium] 保管時に暗号化していない（媒体・バックアップ・スナップショットの持ち出しで読まれる）
  - chat-db-2（C2 会話ログDB） — rds_instance_storage_encrypted
  - vol-0aaa — ec2_ebs_volume_encryption
  - ghost-bucket — s3_bucket_default_encryption
- **log-not-collected** — 図の脅威: [Medium] ログを取得していない（侵害の検知・調査ができない）
  - docs-bucket（C3 文書ストレージ） — s3_bucket_server_access_logging_enabled
- **storage-public-access-misconfiguration** — 図の脅威: [High] ストレージの公開設定の誤りによるデータ露出
  - docs-bucket（C3 文書ストレージ） — s3_bucket_public_access
- **web-global-ip-exposure** — 図の脅威: [High] グローバルIP直接公開
  - web-alb（C1 公開Web） — elbv2_internet_facing

### 図に無い候補（Prowler は FAIL だが図からは検出されていない）

- **nhi-long-lived-secret**
  - batch（C2 会話ログDB） — iam_user_accesskey_unused

### 対応づけできない（FAIL だが脅威の対応が無い検査）

- some_unknown_check [Medium] title of some_unknown_check × 1
```

How to read it (what the headings mean):

| Heading | Meaning |
|---|---|
| 適用した値 (Applied values) | Prowler's value was entered into an item that was unset. The right of "←" is the evidence (value per resource and check ID) |
| 食い違い (Conflicts) | The value already entered differs from Prowler's. It is **not applied**; check which is the truth and fix it |
| 適用できない (Not applicable) | The node's type does not have that item (for example the internal tool type has no "encryption at rest"). Reported only |
| 対応するノードが無い資源 (Resources without a node) | No tag and no `--map` entry, or the tag points to a node that is not on the diagram. A clue to **add it to the diagram or fix the tag** |
| 確認された (Confirmed) | The threat for a FAIL check is also detected on the diagram |
| 図に無い候補 (Candidates not in the diagram) | Prowler says FAIL but the diagram does not detect that threat (that node may lack attributes or links) |
| 対応づけできない (Cannot be mapped) | FAIL, but the mapping has no threat for the check |

> Under "Confirmed", a resource that is not tied to a node (`vol-0aaa` and `ghost-bucket` in the example above) counts as confirmed **if the same kind of threat exists anywhere on the diagram**.
> It does not check which node the threat belongs to, so read it together with "Resources without a node".

### 3.6 See the filled diagram on the screen

The project JSON written by `-o` can be loaded as is. In **Template** → the **Import** tab, press "Select JSON file" and then "Replace and apply"
(the steps are the same as §3 of [Turn a working directory into a threat model](repo-import.md)). The filled items go into the nodes' operational posture and
attack surface attributes, and the "assumed because unset" mark disappears for them.

---

## 4. How values are decided

- **Both PASS and FAIL are entered.** For a result that has a value in the mapping, either becomes the attribute value.
- **Within one resource, the best value across checks.** If one resource has several checks for the same item, the best value is used
  (for example, for one bucket, if one check says provider-managed key and another says customer-managed key, the latter).
- **For a node, the worst value across resources.** When several resources are tied to one node, the worst value is used
  (in the example above, `C2` has two RDS instances and one is unencrypted, so "None").
- **Values already entered are never overwritten.** If the node already has a value that differs from Prowler's, it only appears in the report as a "conflict". If it is the same, it goes under "unchanged".
- **Items the type does not have are not applied.** They appear under "not applicable".
- **Account review becomes "Irregular" only on FAIL.** Passing an unused-key or rotation check does not show that the review process is "Periodic", so PASS enters nothing.
- **Some results enter no value.** A customer-managed key (CMK) check enters "customer-managed key" only on PASS. A FAIL does not show whether default encryption is on, so it enters nothing.
  KMS encryption checks do not distinguish AWS-managed keys from CMKs, so even PASS goes only as far as "provider-managed key". DynamoDB is encrypted by default, so a FAIL is not turned into "None".
- **Muted results are excluded.** Findings muted in Prowler (`Suppressed`) are not read. **MANUAL** (checks that need a human) are only counted, and used neither for values nor for cross-checking.
- Checks not in the mapping are used neither for values nor for cross-checking. The FAIL ones appear under "cannot be mapped".

Which values are better (worse → better):

| Attribute (name on screen) | Worse → better |
|---|---|
| Encryption at rest | None → Yes (provider-managed key) → Yes (customer-managed key) |
| Log collection | Not collected → Collected |
| Log retention period | Under 90 days → Under 1 year → 1 year or more |
| Patch status | Missing patches → Up to date |
| Account review | None → Irregular → Periodic |
| Access log (attack surface attribute) | No → Yes |
| Global IP (attack surface attribute) | Yes → No |

---

## 5. Supported checks

The mapping is `data/finding-maps/prowler.yaml` (like threat knowledge, it lives in YAML, not in code). The first stage supports **some AWS checks**.

| Group | Check IDs | Attribute set (value per result) | Threats cross-checked (canonicalId) |
|---|---|---|---|
| Encryption at rest (default) | `s3_bucket_default_encryption`<br>`rds_instance_storage_encrypted`<br>`rds_cluster_storage_encrypted`<br>`rds_snapshots_encrypted`<br>`ec2_ebs_volume_encryption`<br>`ec2_ebs_snapshots_encrypted`<br>`efs_encryption_at_rest_enabled`<br>`redshift_cluster_encrypted_at_rest`<br>`opensearch_service_domains_encryption_at_rest_enabled` | Encryption at rest：PASS → provider-managed key / FAIL → None | `data-at-rest-unencrypted` |
| KMS encryption (key type not distinguished) | `s3_bucket_kms_encryption`<br>`dynamodb_tables_kms_cmk_encryption_enabled` | Encryption at rest：PASS → provider-managed key | — |
| Bedrock customer-managed keys | `bedrock_custom_model_encrypted_with_cmk`<br>`bedrock_knowledge_base_encrypted_with_cmk`<br>`bedrock_prompt_encrypted_with_cmk` | Encryption at rest：PASS → customer-managed key | — |
| Log collection | `s3_bucket_server_access_logging_enabled`<br>`cloudtrail_multi_region_enabled`<br>`bedrock_model_invocation_logging_enabled`<br>`rds_instance_integration_cloudwatch_logs`<br>`rds_cluster_integration_cloudwatch_logs`<br>`redshift_cluster_audit_logging`<br>`opensearch_service_domains_audit_logging_enabled` | Log collection：PASS → Collected / FAIL → Not collected | `log-not-collected` |
| Bedrock prompt/response body logging | `bedrock_model_invocation_logging_text_data_enabled` | — | `log-not-collected` |
| API and load balancer access logs | `apigateway_restapi_logging_enabled`<br>`apigatewayv2_api_access_logging_enabled`<br>`elb_logging_enabled`<br>`elbv2_logging_enabled` | Access log (attack surface)：PASS → Yes / FAIL → No | `web-missing-access-log` |
| Log retention (default threshold 365 days) | `cloudwatch_log_group_retention_policy_specific_days_enabled` | Log retention period：PASS → 1 year or more | `log-retention-insufficient` |
| Patch compliance (SSM) | `ssm_managed_compliant_patching` | Patch status：PASS → Up to date / FAIL → Missing patches | `known-vulnerability-unpatched` |
| Unused or unrotated access keys | `iam_user_accesskey_unused`<br>`iam_rotate_access_key_90_days` | Account review：FAIL → Irregular | `nhi-long-lived-secret` |
| Unused console access | `iam_user_console_access_unused` | Account review：FAIL → Irregular | — |
| Secret rotation | `secretsmanager_automatic_rotation_enabled`<br>`secretsmanager_secret_rotated_periodically` | — | `nhi-long-lived-secret` |
| Reachability from the Internet | `ec2_instance_public_ip`<br>`elb_internet_facing`<br>`elbv2_internet_facing`<br>`apigateway_restapi_public` | Global IP (attack surface)：PASS → No / FAIL → Yes | `web-global-ip-exposure` |
| Public storage / databases | `s3_bucket_public_access`<br>`s3_bucket_level_public_access_block`<br>`s3_bucket_policy_public_write_access`<br>`s3_bucket_public_list_acl`<br>`s3_bucket_public_write_acl`<br>`s3_bucket_object_public`<br>`rds_instance_no_public_access`<br>`rds_snapshots_public_access`<br>`cloudtrail_logs_s3_bucket_is_not_publicly_accessible` | — | `storage-public-access-misconfiguration` |
| MFA | `iam_user_mfa_enabled_console_access`<br>`iam_user_hardware_mfa_enabled`<br>`iam_root_mfa_enabled` | — | `password-only-internet-channel` |
| Overly broad IAM permissions | `iam_role_administratoraccess_policy`<br>`iam_user_administrator_access_policy`<br>`iam_aws_attached_policy_no_administrative_privileges`<br>`iam_policy_allows_privilege_escalation` | — | `nhi-overprivileged` |
| Bedrock guardrails | `bedrock_guardrails_configured`<br>`bedrock_guardrail_prompt_attack_filter_enabled`<br>`bedrock_guardrail_sensitive_information_filter_enabled`<br>`bedrock_guardrail_sensitive_information_filter_enforced`<br>`bedrock_guardrail_contextual_grounding_filter_enabled`<br>`bedrock_agent_guardrail_enabled` | — | `guardrail-probabilistic-bypass`, `direct-prompt-injection` |
| Bedrock agent roles | `bedrock_agent_role_least_privilege`<br>`bedrock_agent_role_not_shared_across_agents`<br>`bedrock_full_access_policy_attached` | — | `excessive-agency`, `nhi-overprivileged` |
| Bedrock API key permissions | `bedrock_api_key_no_administrative_privileges` | — | `nhi-overprivileged` |
| Bedrock API key lifetime | `bedrock_api_key_no_long_term_credentials` | — | `nhi-long-lived-secret`, `credential-sprawl` |
| Bedrock VPC endpoints | `bedrock_vpc_endpoints_configured` | — | `private-endpoint-data-exfiltration` |

- "—" means nothing applies in that column. A check whose attribute is "—" is used **only for cross-checking** (things like MFA that concern links or operations, not a node attribute).
- The threat is the `canonicalId` in the threat library. A FAIL check is looked up as "is a threat with the same `canonicalId` detected on the diagram?"
- Only check IDs that exist in Prowler's repository (`prowler/providers/aws/services/`) are listed. Descriptions of the checks are not reproduced.

---

## 6. Handling of secrets

An OCSF file contains account IDs and the content of resource configuration. The import handles them as follows.

- **Not read**: `resources[].data` (the whole resource configuration), `cloud.account`, `cloud.org` (account ID and organization), and long text such as `risk_details`.
- **The userinfo, query, and fragment of a URL are discarded.** Even if a resource name or uid contains a URL, `user:pass@` and `?token=…` are not kept.
- **Resource names in the report prefer the name.** The uid (ARN) is used only when there is no name, and a 12-digit account ID is masked as `*`.
- The ARN (uid) is used only to tie a resource to a node.
- **Only the operational posture and attack surface values go into the project JSON the command writes.** Resource names and ARNs do not (they appear only in the report).
- **The OCSF file and the `--map` file are customer information.** Do not put them in a public repository, ticket, or chat.

---

## 7. Use cases

- **Reflect measurements in the diagram before a design review.** Tag, import, and clear the threats that carried "assumed because unset" and that the measurements show to be fine.
  The FAIL ones become evidence for deciding the priority of countermeasures.
- **Use conflicts as a clue to fix either the diagram or reality.** If the diagram says "encrypted" but Prowler says FAIL, the diagram is wrong or reality has drifted from the design.
- **Find what was missed in the drawing from "resources without a node" and "candidates not in the diagram".** A resource that the scan sees but the diagram lacks is an asset left out of the threat analysis.
- To investigate attack paths on the imported diagram — [Attack Path Analysis](attack-paths.md)

> **A note** — Measurements are values from "now". The imported values stay as attributes of the diagram, but they do not follow later configuration changes automatically.
> Run Prowler regularly and import again, or fix the diagram with every change.

---

## 8. Bundled sample

A **fictional** sample shaped after Prowler's output code (`prowler/lib/outputs/ocsf/ocsf.py`) is included (account IDs and resource names are all dummies).

| File | Content |
|---|---|
| [`sample.ocsf.json`](../src/features/prowler-import/__fixtures__/sample.ocsf.json) | A sample in the shape of Prowler's OCSF (17 entries, including 1 muted, 1 MANUAL, and 1 check not in the mapping) |
| [`sample-project.json`](../src/features/prowler-import/__fixtures__/sample-project.json) | The diagram to put findings on (5 nodes) |
| [`sample-map.json`](../src/features/prowler-import/__fixtures__/sample-map.json) | A mapping file for resources without tags |

---

## 9. Limits

- **It was verified with fictional samples shaped after Prowler's output code (`ocsf.py`). It has not been verified against real Prowler output.**
  If field names or shapes differ, entries that cannot be read are counted as "unreadable" in the report. At first, check that the counts are what you expect.
- **Only some AWS checks are supported.** Other providers such as Azure, GCP, and Kubernetes, and checks not listed, are used neither for values nor for cross-checking.
- **Attributes of links (edges), such as MFA, are not filled.** They appear only in the cross-check report.
- **Log retention assumes Prowler's default setting (365 days).** If you changed the threshold, PASS does not mean one year or more. In that case, fix the mapping.
- **Import from the screen, and retrieval from Prowler's API or Prowler App, are not supported.** Only reading a file with the CLI.
- **A scan reflects the moment it ran.** Values put into the diagram's attributes do not follow later configuration changes automatically.
- **It never creates nodes.** A resource with neither a tag nor a mapping entry appears in the report as a "resource without a node".

---

## References

1. Prowler (GitHub) — <https://github.com/prowler-cloud/prowler>
2. Prowler documentation — <https://docs.prowler.com/>
3. Prowler Hub (list of checks) — <https://hub.prowler.com/>

---

## What to read next

- How to read threats — [Reading the Threat Panel](reading-threats.md)
- Entering attributes and clearing threats — [Getting Started](getting-started.md)
- An integration with a similar way of cross-checking — [Fixing Veracode Findings with AI](veracode-remediation.md)
- Turn external-exposure observations into a diagram — [Turning ScopeSentry Results into a Diagram](scopesentry.md)
- Build a test plan — [Creating a Penetration Test Plan from the Threat Model](pentest-plan.md)
