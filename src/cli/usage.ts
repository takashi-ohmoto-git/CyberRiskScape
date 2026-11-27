/**
 * CLI の使い方（`--help` と引数エラー時に表示するテキスト）。
 */

export const USAGE = `使い方:
  analyze <project.json> [options]
  diff <base.json> <head.json> [options]
  triggers [options]
  indicators <project.json> [--weights <file>] [--out <file>]
  export-scope <project.json> [--kind <host|domain|cidr|url-prefix>] [--format <text|json>] [--out <file>]
  checklist <project.json> --id <checklistId> [options]
  import-kong <kong.yaml> [options]
  import-kongctl <kongctl.yaml> [options]
  import-tm7 <file.tm7> [options]
  migration-report <project.json> [options]
  import-repo <dir> [options]
  import-prowler <project.json> --ocsf <file> [options]
  import-findings <project.json> --format <xccdf|arf|oval> --in <file> [options]
  import-pentest <project.json> --in <registry.yaml> [options]
  convert-cyberstrikeai [<vulns.json>] [--api <base-url>] --scope <scope> [options]
  convert-strix <findings.sarif | strix_runs/<run>> --scope <scope> [options]
  convert-metasploit <export.xml> --scope <scope> [--host-node <IP>=<C番号|ID> ...] [options]
  import-sarif <project.json> --sarif <file> --scope <scope> [options]
  import-openapi <project.json> --in <openapi.yaml|json> --scope <scope> [options]
  import-ocsf <project.json> --in <findings.ocsf.json> --scope <scope> [options]
  import-nuclei <project.json> --in <results.jsonl> --scope <scope> [options]
  import-security-audit <project.json> --in <findings.json> [options]
  import-bloodhound <project.json> (--in <dir> | --api <base-url>) [options]
  import-entra-apps <project.json> (--in <dir> --tenant-id <id> | --graph) [options]
  import-business-context <project.json> --in <table.csv|json> [options]
  convert-celonis --api <base-url> --km <id> --record <id> --system-field <id> --map-value <値>=<C番号|ID> ... [options]
  import-kev <project.json> --kev <file> [options]
  import-epss <project.json> --epss <epss_scores.csv[.gz]> [options]
  fill-patch-status <project.json> [options]
  findings-priority <project.json> [options]
  asm-reconcile <project.json> [options]
  sbom-report <project.json> [options]
  context <project.json> (--ip <ip> | --host <name> | --purl <purl>) [options]
  import-aipentest-assets <project.json> --format <artex|cyberstrikeai|ai-asm> --scope <scope> [--services <file>] [--endpoints <file>] [--assets <file> ...] [options]
  import-metasploit-assets <project.json> --xml <export.xml> --scope <scope> [--host-node <IP>=<C番号|ID> ...] [options]
  import-sbom <project.json> --sbom <file> --scope <scope> [options]
  import-conjur <policy.yml> [options]
  import-shodan <export.json[.gz]> [options]
  import-scopesentry <export.json> [options]
  import-scopesentry --api <base-url> [options]
  export-postman <project.json> [options]
  export-sbom-ai <project.json> [options]
  export-spdx <project.json> [options]
  export-test-plan <project.json> [options]
  export-roe <project.json> [options]
  export-attack-navigator <project.json> [options]
  export-investigation-plan <project.json> [options]
  export-detection-requirements <project.json> [options]
  export-contractor-paths <project.json> [options]
  export-requirements <project.json> [options]
  export-event-log --repo <dir> --path <model.json> [options]
  export-triage-patterns [options]
  investigation-report <project.json> --evidence <dir|file> --hosts <hosts.json> [options]
  findings-report <project.json> (--veracode <file> | --skill-scanner <file> | --mcp-scanner <file>) [options]
  pqc-sbom-report <project.json> --sbom <file> --node <C番号> [options]
  mcp [options]

analyze のオプション:
  --format <json|sarif|md>                     出力形式（既定: json）
  --layer <L0|L1|L2|L3|PQC>                     対象レイヤー（既定: ノードがある全レイヤー）
  --framework <STRIDE|AI|AgenticAI|ALL>         対象フレームワーク（既定: ALL）
  --fail-on <Critical|High|Medium|Low>          指定した重大度以上の未抑制脅威があれば exit 1
  --fail-on-findings <Critical|High|Medium|Low> 保存済みの指摘で、指定重大度以上（試行のみ・受容済みを除く）があれば exit 1
  --with-findings                               --format sarif のとき、プロジェクトに保存された外部製品の指摘（import-prowler で保存）を製品ごとの run として追加
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

diff のオプション:
  --format <md|json>                            出力形式（既定: md）
  --fail-on <Critical|High|Medium|Low>          新規かつ未抑制の脅威が指定重大度以上なら exit 1
  --triggers <file>                             実行トリガー定義 YAML（既定: 同梱の T1〜T8。指定時は翻訳オーバーレイ非適用）
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

indicators（脅威モデル単位の指標：設定率・検討率・実装済みの割合を JSON で出す）:
  全レイヤー・全フレームワークの脅威が対象。重大度で重みを付け、誤検知と適用外は対象から外す。
  同梱ルールのみで評価する（カスタムルールの脅威は入らない）。
  --weights <file>                              重みの YAML（既定: 同梱の data/indicators/weights.yaml と同じ形）
  --out <file>                                  出力先ファイル（既定: 標準出力）

export-scope（サービスの担当範囲を、ASM・DAST・ペンテストの探索の起点として書き出す）:
  担当範囲は Project Edit の「担当範囲」で入力する。値は正規化して出し、解釈できない値は出さない（json の invalid に並べる）。
  --kind <host|domain|cidr|url-prefix>          種類を絞る（text では値だけを 1 行 1 件で出す）
  --format <text|json>                          出力形式（既定: text。種類を絞らない text は「種類<TAB>値」）
  --out <file>                                  出力先ファイル（既定: 標準出力）

import-bloodhound のオプション（BloodHound CE の問い合わせの結果を、図のディレクトリ・認証局・IdP（Entra ID）・IaaS / PaaS とシークレット管理（Azure）に指摘として保存する。ユーザーの名前・SID は保存しない）:
  --in <dir>                                    問い合わせの応答 JSON（POST /api/v2/graphs/cypher の応答）を「<問い合わせ id>.json」で置いたフォルダ
  --api <base-url>                              BloodHound CE の URL。同梱の問い合わせだけを POST /api/v2/graphs/cypher に送る（読み取りのみ）。
                                                API トークンは環境変数 BLOODHOUND_TOKEN_ID・BLOODHOUND_TOKEN_KEY で渡す（保存・出力しない）。https のみ（localhost は http 可）
  --print-queries                               同梱の問い合わせ（id・題名・Cypher）を JSON で出して終わる（手で実行するとき用）
  --node <C番号|ID>                             指摘を載せるディレクトリ（既定: 図にちょうど 1 つあればそれ）
  --ca-node <C番号|ID>                          AD CS の指摘を載せる認証局（既定: 図にちょうど 1 つあればそれ。無ければディレクトリ）
  --idp-node <C番号|ID>                         Entra ID の指摘を載せる IdP（既定: 図にちょうど 1 つあればそれ。無ければ未結合）
  --cloud-node <C番号|ID>                       Azure の管理の範囲・コード実行の指摘を載せる IaaS / PaaS（既定: 図にちょうど 1 つあればそれ）
  --vault-node <C番号|ID>                       Key Vault の指摘を載せるシークレット管理（既定: 図にちょうど 1 つあればそれ）
  --scope <name>                                置き換えの範囲（既定: default。ドメインごとに分けて取り込むときに使う）
  --report <md|json>                            報告の形式（既定: md。標準出力）
  -o, --out <file>                              指摘を保存したプロジェクト JSON の出力先（省略時は保存しない）

import-entra-apps のオプション（Microsoft Graph の外部アプリ・同意の在庫を、図の IdP に指摘として保存し、外部アプリと図のアプリ系のノードを突き合わせる。図は変えない。資格情報の値・利用者は保存しない）:
  --in <dir>                                    Graph の応答 JSON のフォルダ。servicePrincipals.json（必須）・graphServicePrincipal.json・
                                                graphAppRoleAssignedTo.json・oauth2PermissionGrants.json（1 ページでもページの配列でもよい）
  --tenant-id <id>                              自組織のテナント ID（--in のとき必須。外部アプリの判定に使う）
  --graph                                       Microsoft Graph から読む（GET のみ）。環境変数 MSGRAPH_TENANT_ID・MSGRAPH_CLIENT_ID・
                                                MSGRAPH_CLIENT_SECRET（保存・出力しない）。要る権限：Application.Read.All・Directory.Read.All
  --idp-node <C番号|ID>                         指摘を載せる IdP（既定: 図にちょうど 1 つあればそれ。無ければ未結合）
  --scope <name>                                置き換えの範囲（既定: default。テナントごとに分けるときに使う）
  --report <md|json>                            報告の形式（既定: md。標準出力）
  -o, --out <file>                              指摘を保存したプロジェクト JSON の出力先（省略時は保存しない）

import-openapi のオプション（OpenAPI 3.x・Swagger 2.0 の定義の操作を、API の定義の資産として保存する。asm-reconcile で観測した API と突き合わせ、定義に無い API を出す）:
  --in <file>                                   OpenAPI の定義（JSON・YAML。16 MB まで）
  --scope <scope>                               置き換えの範囲（必須。同じ scope の API の定義を置き換える。API ごとに分ける）
  --base-url <url>                              サーバーの URL（定義に servers が無い・相対のとき。あれば上書き）
  --node <C番号|ID>                             すべてのエンドポイントを結びつけるノード（任意）
  --report <md|json>                            報告の形式（既定: md。認証の指定が無い操作の一覧を含む）
  -o, --out <file>                              資産を保存したプロジェクト JSON の出力先（指定しなければ報告のみ）

import-ocsf のオプション（OCSF の検査結果〔Detection Finding・Compliance Finding。製品を問わない〕の FAIL を指摘として、出てきたクラウドのリソースを資産として保存する。運用状況は埋めない〔Prowler で埋めるときは import-prowler〕）:
  --in <file>                                   OCSF の検査結果（JSON の配列）
  --scope <scope>                               置き換えの範囲（必須。同じ製品 × scope の指摘・リソースを置き換える。アカウントごと等に分ける）
  --map <file>                                  {"<リソースの ID または名前>": "<ノード ID>"} の JSON（タグ crs-node が無いリソースの対応）
  --report <md|json>                            報告の形式（既定: md。脅威と結ばなかった検査の一覧を含む）
  -o, --out <file>                              指摘・資産を保存したプロジェクト JSON の出力先（指定しなければ報告のみ）
  ※ リソースの ID はアカウント ID を含む完全な形で保存する。図に無いリソースは asm-reconcile で出る

triggers のオプション:
  --format <md|json>                            出力形式（既定: md）
  --triggers <file>                             実行トリガー定義 YAML（既定: 同梱の T1〜T8。指定時は翻訳オーバーレイ非適用）
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

checklist のオプション（注意喚起チェックリストを構成図に当てはめ、項目ごとの状態を出す。実機の点検の代わりではない）:
  --id <checklistId>                            チェックリスト ID（必須。例: ipa-alert-2026-10）
  --format <md|json|csv>                        出力形式（既定: md）
  --layer <L0|L1|L2|L3|PQC>                     対象レイヤー（既定: ノードがある最初のレイヤー）
  --as-of <YYYY-MM-DD>                          「点検が古い」判定の基準日（既定: 今日）
  --fail-on-action                              状態が「要対応」の項目があれば exit 1
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

import-kong のオプション（Kong の宣言設定から構成図の下書きを L1 に作り、プロジェクト JSON を出力）:
  --locale <ja|en>                              ノード名の言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

import-kongctl のオプション（Kong AI Gateway 2.x の kongctl 宣言ファイルから構成図の下書きを L1 に作り、プロジェクト JSON を出力）:
  --locale <ja|en>                              ノード名の言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

import-tm7 のオプション（Microsoft Threat Modeling Tool の .tm7 から、構成図・脅威・対策の状況を含むプロジェクト JSON を出力。移行用）:
  --locale <ja|en>                              ノード名・説明の言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）
  --report <file>                               移行レポート（Markdown。migration-report と同じ内容）も出力

migration-report のオプション（TMT から取り込んだ脅威と、検出した脅威の重なりと差。import-tm7 の出力に使う。framework は ALL 固定）:
  --format <md|json>                            出力形式（既定: md）
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

import-repo のオプション（コーディングエージェントの作業ディレクトリ（リポジトリ）の package.json・requirements*.txt・.env*・.mcp.json・.claude/ から、開発環境と依存パッケージの構成図の下書きを L1 に作り、プロジェクト JSON を出力。.env の値・認証情報は読み取り後に捨てる）:
  --locale <ja|en>                              ノード名の言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）
  --dashboard <file>                            エージェント（スキル・コマンド・MCP・依存・.env の名前）のダッシュボードを単体の HTML で出力（.claude/ が無ければ出さない）

import-prowler のオプション（Prowler の OCSF 出力（*.ocsf.json）の検査結果を、図のノードの運用状況・攻撃面属性の未入力の項目に載せる。入力済みの値は上書きせず、食い違いを報告に出す。ファイル入力のみ）:
  --ocsf <file>                                 Prowler の OCSF（必須。json-ocsf の出力）
  --map <file>                                  資源とノードの対応表（任意。JSON {"<資源の uid または名前>": "<ノード ID または C 番号>"}）。
                                                資源のタグ crs-node=<ノード ID> が優先され、タグの無い資源をこの表で補う
  --report <md|json>                            報告の形式（既定: md。標準出力）
  -o, --out <file>                              未入力の項目を埋めたプロジェクト JSON の出力先（指定しなければ書き出さない）

import-findings のオプション（SCAP の結果（XCCDF 1.1/1.2・ARF 1.1・OVAL 5 の結果。OpenSCAP 等の出力）の fail・脆弱性を、共通モデルの指摘としてプロジェクト JSON に保存する。取り込み直しはホスト単位で置き換える。ファイル入力のみ）:
  --format <xccdf|arf|oval>                     入力の形式（必須。ファイルの中身と違えばエラー）
  --in <file>                                   SCAP の結果の XML（必須。64 MB まで）
  --node <C番号|ID>                             ファイル内のすべてのホストをこのノードに結びつける（--map より優先）
  --map <file>                                  ホストとノードの対応表（任意。JSON {"<ホスト名|FQDN|IP>": "<ノード ID または C 番号>"}）
  --report <md|json>                            報告の形式（既定: md。標準出力）
  -o, --out <file>                              指摘を保存したプロジェクト JSON の出力先（指定しなければ書き出さない）。
                                                保存した指摘は analyze --format sarif --with-findings で書き出せる

import-pentest のオプション（ペンテストの指摘の台帳 YAML のうち status が open の指摘を、共通モデルの指摘としてプロジェクト JSON に保存する。取り込み直しは scope 単位で置き換える。既存の脅威カードに載らない指摘は手動脅威（STRIDE）として足す。証拠・鍵は台帳に含めない）:
  --in <registry.yaml>                          指摘の台帳 YAML（必須。64 MB まで）
  --scope <scope>                               この scope の項目だけ取り込む（任意。他の scope の指摘は触らない）
  --report <md|json>                            報告の形式（既定: md。標準出力）
  -o, --out <file>                              指摘を保存したプロジェクト JSON の出力先（指定しなければ書き出さない）

import-aipentest-assets のオプション（AI ペンテストのツールが観測した資産の JSON から、サービスとエンドポイントを Asset タブ用に保存する。パラメータの値・担当者や部署は保存しない）:
  --format <artex|cyberstrikeai|ai-asm>         入力の形（必須）
  --assets <file>                               cyberstrikeai: GET /api/assets?page=N&page_size=100 の JSON（必須。ページごとに繰り返し可）。手で登録した資産（manual）と inactive は読まない
  --services <file>                             artex: GET /api/assets?type=service&task_id=N の JSON（--endpoints とどちらか必須）
  --endpoints <file>                            artex: GET /api/assets?type=endpoint&task_id=N の JSON。ai-asm: AI-ASM の endpoints.json（必須）
  --scope <scope>                               置き換えの範囲（必須。例: task-3）
  --map <file>                                  ホストとノードの対応表（任意。JSON {"<IP|ドメイン>": "<C番号|ノード ID>"}）。
                                                キーは <IP|ホスト名>:<ポート>/<tcp|udp> でもよい（完全一致のときだけ。IP・ホスト名だけのキーより優先）
  --node <C番号|ID>                             対応表に無いホストを結びつけるノード（任意。無ければ未対応）
  --report <md|json>                            報告の形式（既定: md。標準出力）
  -o, --out <file>                              資産を保存したプロジェクト JSON の出力先（指定しなければ報告のみ）

convert-metasploit のオプション（Metasploit の db_export -f xml を import-pentest の台帳 YAML に変換する。重大度は Metasploit に無いので、実証（exploited-at あり、または試行が成功）は High、試行のみは Medium とする（人が直す）。CVE の参照があれば「既知の脆弱性に対するパッチの未適用」を入れる（要確認）。資格情報・loot・session・notes・各種詳細・info は読まず写さない）:
  --scope <scope>                               台帳の範囲（必須。import-pentest の置き換え単位）
  --host-node <IP>=<C番号|ID>                   そのホストの指摘を結びつけるノード（任意。繰り返し可。無ければ人が埋める）
  -o, --out <registry.yaml>                     台帳 YAML の出力先（既定: 標準出力）

import-metasploit-assets のオプション（Metasploit の db_export -f xml のホストのサービス（state が open）を Asset タブ用に保存する。同じ scope の Metasploit の資産は置き換える）:
  --xml <export.xml>                            db_export -f xml のファイル（必須）
  --scope <scope>                               置き換えの範囲（必須）
  --host-node <IP>=<C番号|ID>                   そのホストを結びつけるノード（任意。繰り返し可。無ければ未対応）
  --report <md|json>                            報告の形式（既定: md。標準出力）
  -o, --out <file>                              資産を保存したプロジェクト JSON の出力先（指定しなければ報告のみ）

convert-cyberstrikeai のオプション（CyberStrikeAI の脆弱性を import-pentest の台帳 YAML に変換する。confirmed は実証、open は試行のみ、ignored は出さない。証跡・再現手順・説明は写さない。target は URL のクエリを落としてコメントにだけ残す。node と canonicalIds は人が埋めてから import-pentest に渡す）:
  --api <base-url>                              ファイルの代わりに <base-url>/api/vulnerabilities から取得する（GET のみ）。
                                                トークンは環境変数 CYBERSTRIKEAI_TOKEN で渡す（保存・出力しない）。https のみ（localhost は http 可）
  --scope <scope>                               台帳の範囲（必須。import-pentest の置き換え単位）
  --project-id <id>                             --api のとき、このプロジェクトの脆弱性だけ取得する
  --task-id <id>                                --api のとき、このタスクの脆弱性だけ取得する
  -o, --out <registry.yaml>                     台帳 YAML の出力先（既定: 標準出力）

convert-strix のオプション（Strix の findings.sarif を import-pentest の台帳 YAML に変換する。確信度 high だけ実証、それ以外は試行のみ。カバレッジ（pass / open 等）は除く。CVE があれば「既知の脆弱性に対するパッチの未適用」、無ければ CWE の対応表で canonicalIds を入れる（要確認）。PoC・証跡・分析・修正の本文は写さない。エンドポイントは URL のクエリを落としてコメントにだけ残す）:
  --scope <scope>                               台帳の範囲（必須。import-pentest の置き換え単位）
  --node <C番号|ID>                             すべての指摘を結びつけるノード（任意。無ければ人が埋める）
  -o, --out <registry.yaml>                     台帳 YAML の出力先（既定: 標準出力）

import-nuclei のオプション（Nuclei の JSONL（-j / -jle）または JSON（-je）の結果を指摘として保存する。info と一致しなかった結果は件数のみ。CVE を持つ指摘は「既知の脆弱性に対するパッチの未適用」に対応づけ、CVE が無い指摘は CWE の対応表で脅威に対応づける。要求・応答・curl・抽出値は保存しない。場所は URL のクエリを落とす）:
  --in <file>                                   Nuclei の結果ファイル（必須）
  --scope <scope>                               置き換えの範囲（必須。同じ製品・同じ scope の指摘を置き換える）
  --node <C番号|ID>                             すべての指摘を結びつけるノード（任意。無ければ未結合）
  --report <md|json>                            報告の形式（既定: md。標準出力）
  -o, --out <file>                              指摘を保存したプロジェクト JSON の出力先（指定しなければ報告のみ）

import-sarif のオプション（汎用の SARIF 2.1.0（Semgrep・CodeQL 等の SAST）の結果を指摘として保存する。抑制済み・解消済み（absent）・合格／対象外／情報の結果は除く。message の本文・コード片・codeFlows は保存しない。場所は相対的な表記に落とす）:
  --sarif <file>                                SARIF の JSON（必須）
  --scope <scope>                               置き換えの範囲（必須。同じ製品・同じ scope の指摘を置き換える）
  --node <C番号|ID>                             すべての指摘を結びつけるノード（任意。無ければ未結合）
  --category <secrets>                          SARIF の分類。secrets＝秘密の走査の結果として扱い、すべての結果を「認証材料の静的保管・スプロール」に結ぶ
                                                （秘密の値・message は保存しない。認証材料のノードを --node で指定するとカードに結びつく）
  --show-secrets                                --category secrets のとき、報告に生の情報（場所・コミットの情報・秘密の値）を出す。既定は件数だけ。
                                                生の情報はプロジェクト JSON・書き出し・画面には入れない
  --report <md|json>                            報告の形式（既定: md。標準出力）
  -o, --out <file>                              指摘を保存したプロジェクト JSON の出力先（指定しなければ報告のみ）

import-security-audit のオプション（AI によるソース監査（Cloudflare security-audit スキル）の findings.json を指摘として保存する。confirmed は成立を確認した指摘、needs_validation は重大度なしの要確認として保存し、rejected は保存しない。payloads・修正コード・evidence・root_cause の本文は保存しない）:
  --in <findings.json>                          findings.json（必須。16 MB まで）
  --ledger <coverage-ledger.json>               coverage-ledger.json（任意。攻撃クラスから脅威へ対応づける。16 MB まで）
  --scope <scope>                               置き換えの範囲（既定: default。同じ製品・同じ scope の指摘を置き換える）
  --node <C番号|ID>                             すべての指摘を結びつけるノード（任意。無ければ未結合）
  --report <md|json>                            報告の形式（既定: md。標準出力）
  -o, --out <file>                              指摘を保存したプロジェクト JSON の出力先（指定しなければ報告のみ）

import-business-context のオプション（業務の文脈の表（CSV: node,process,cases,value,currency,period,criticality ／ JSON: kind "cyberriskscape-business-context"）を読み、ノードが担う業務プロセスと重要度（High / Medium / Low）を記録する。重要度は行の criticality（最大値）、無ければ表全体の金額（無ければ件数）に占める割合（30% 以上 High・10% 以上 Medium）から決める。High のノードは推奨標的に加わり、SSVC の Mission & Well-being に効く。脅威ルールの発火には使わない。ネットワークにも出ない）:
  --in <table.csv|json>                         業務の文脈の表（必須）
  --format <text|json>                          標準エラー出力の報告の形式（既定: text）
  -o, --out <file>                              更新したプロジェクト JSON の出力先（既定: 標準出力）

convert-celonis のオプション（Celonis（プロセスマイニング）の Knowledge Model の Record のデータを GET し、業務の文脈の表（JSON）に変換する。読み取りのみ。最大 1,000 行。資格情報は環境変数 CELONIS_CLIENT_ID と CELONIS_CLIENT_SECRET（または CELONIS_TOKEN）で渡す。引数では受け取らず、保存・出力しない）:
  --api <base-url>                              https://<team>.<cluster>.celonis.cloud/intelligence/api（必須。https のみ）
  --km <id>                                     Knowledge Model の ID（必須）
  --record <id>                                 Record の ID（必須）
  --system-field <id>                           ノードに対応づけるシステム名の項目 ID（必須）
  --map-value <値>=<C番号|ID>                    システム名の値とノードの対応（必須・繰り返し可。対応のない値の行は除外して報告する）
  --process <name> | --process-field <id>       プロセス名（固定値、または項目 ID。どちらか必須）
  --value-field <id>                            金額の項目 ID（任意）
  --cases-field <id>                            件数の項目 ID（任意）
  --currency <code>                             通貨（任意。例: JPY）
  --period <text>                               集計期間（任意。例: 2026-10）
  -o, --out <table.json>                        表の出力先（既定: 標準出力）

import-kev のオプション（CISA の KEV カタログ JSON（https://www.cisa.gov/known-exploited-vulnerabilities-catalog）を指摘の CVE と照合し、載っている指摘に kev の印を付ける。載っていない指摘からは印を外す＝取り込み直しで最新になる。カタログは同梱せず、ネットワークにも出ない。KEV に載っている＝CISA が悪用を確認した事実）:
  --kev <file>                                  KEV カタログの JSON（必須）
  --report <md|json>                            報告の形式（既定: md。標準出力）
  -o, --out <file>                              印を付けたプロジェクト JSON の出力先（指定しなければ報告のみ）

fill-patch-status のオプション（CVE を持つ保存済みの指摘（試行のみは除く）があるノードのうち、型がパッチ状況を持ち patchStatus が未入力のものを「未適用（Missing）」にする。入力済みは上書きしない。「更新済み」は書かない）:
  --report <md|json>                            報告の形式（既定: md。標準出力）
  -o, --out <file>                              補完したプロジェクト JSON の出力先（指定しなければ報告のみ）
  --dry-run                                     出力先を指定しても保存しない

context のオプション（アラートの IP・ホスト名・purl から、図のノード・前段・脅威・指摘・露出・届く標的を引く。読み取り専用で、プロジェクトは書き換えない。優先度は推奨であり、判断は人。「悪用できる」とは言わない。--ip / --host / --purl のうち 1 つだけ指定する）:
  --ip <ip>                                     資産の IP アドレスで引く
  --host <name>                                 資産のホスト名・FQDN、またはノードのラベルで引く（大文字小文字を区別しない）
  --purl <purl>                                 部品の purl で引く（版を省くと版違いも含む）
  --attacker <C番号|ID>                         攻撃者（AI エージェント攻撃者）のノード（既定: 図の攻撃者ノードの先頭）
  --format <md|json>                            出力形式（既定: md）
  -o, --out <file>                              出力先ファイル（既定: 標準出力）

asm-reconcile のオプション（ASM（Shodan・ScopeSentry）が観測した資産と、図の「外部公開」（Global IP）の入力の食い違いを並べる読み取り専用の報告。判定はしない。終了コードは常に 0）:
  担当範囲（Project Edit）を入力していれば、観測と観測した API のエンドポイントを担当範囲の中・外に分けて出す。
  API の定義（import-openapi）があれば、観測した API のうち定義に無いものを出す。
  クラウドのリソース（import-ocsf）があれば、図のノードに結びついていないものを出す。
  --previous <old-project.json>                 前回のプロジェクト JSON（新しく見えた・見えなくなった観測を比較。保存はしない）
  --format <md|json>                            出力形式（既定: md）
  -o, --out <file>                              出力先ファイル（既定: 標準出力）

sbom-report のオプション（保存済みの SBOM の検収レポート。図との結びつき・新しさ・指摘の件数・ライセンス欄の空を並べる読み取り専用の報告。合否・ライセンスの適否は判定しない。終了コードは常に 0）:
  --max-age-days <n>                            BOM 作成時刻がこの日数より古いものに印を付ける（既定: 90）
  --format <md|json>                            出力形式（既定: md）
  -o, --out <file>                              出力先ファイル（既定: 標準出力）

import-epss のオプション（FIRST の EPSS（https://www.first.org/epss/）の日次 CSV を指摘の CVE と照合して epss を付ける。一覧に無い CVE の指摘からは外す。ネットワークに出ない。EPSS は 30 日以内に悪用が観測される確率の推定で、悪用の事実ではない）:
  --epss <file>                                 epss_scores の CSV（.csv または .csv.gz。必須）
  --report <md|json>                            レポート形式（既定: md）
  -o, --out <file>                              更新したプロジェクト JSON の出力先

findings-priority のオプション（保存済みの指摘を攻撃経路に載せ、推奨の優先度 P1〜P4 と根拠（露出・届く標的・KEV・EPSS・連鎖）を出す。推奨と根拠であり、判断は人。「悪用できる」とは言わない。元の深刻度は変えない）:
  --attacker <C番号|ID>                         攻撃者（AI エージェント攻撃者）のノード（既定: 図の攻撃者ノードの先頭。無ければ露出を評価できない）
  --layer <L0|L1|L2|L3|PQC>                     対象レイヤー（既定: ノードがある全レイヤー。そのレイヤーの指摘と未結合の指摘だけ評価）
  --epss-threshold <0-1>                        EPSS がこの値以上の指摘は、入口・入口の奥にあれば優先度を 1 段上げる（既定: 0.1。KEV の指摘・届かない指摘は対象外）
  --format <md|json>                            出力形式（既定: md。json には SSVC との用語の対応を含む）
  -o, --out <file>                              出力先ファイル（既定: 標準出力）

import-sbom のオプション（CycloneDX または SPDX 2.x の JSON の部品を保存する。形式は中身で判定する。ライセンスは ID か式だけ保存し適否は判定しない。CycloneDX の vulnerabilities は指摘として保存し、VEX で not_affected・false_positive・resolved のものは除く。依存関係・鍵の値は保存しない）:
  --sbom <file>                                 BOM の JSON（必須）
  --scope <scope>                               置き換えの範囲（必須。同じ形式・同じ scope の部品を置き換える）
  --node <C番号|ID>                             すべての部品を結びつけるノード（任意。無ければ未対応）
  --report <md|json>                            報告の形式（既定: md。標準出力）
  -o, --out <file>                              部品を保存したプロジェクト JSON の出力先（指定しなければ報告のみ）

export-spdx のオプション（取り込んだ部品と依存パッケージのインベントリを SPDX 2.3 JSON で出力する。暗号資産は SPDX 2.3 に載らないので出さない）:
  --out <file>                                  出力先ファイル（既定: 標準出力）

import-conjur のオプション（Conjur / Secrets Manager のポリシーから NHI と読み取り経路の図を L1 に作り、プロジェクト JSON を出力）:
  --locale <ja|en>                              ノード名の言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

import-shodan のオプション（Shodan の書き出し（.json.gz または JSON）から外部露出サービスの図を L1 に作り、プロジェクト JSON を出力）:
  --into <project.json>                         図の下書きの代わりに、観測したサービス（ip:port/transport）を資産として既存のプロジェクトに保存する。
                                                製品が報告した CVE は識別子（cve・未検証・最大 10 件）として残す。指定しなければ従来どおり図の下書きを出す
  --scope <scope>                               --into のとき必須。置き換えの範囲（同じ製品・同じ scope の資産を置き換える）
  --map <file>                                  --into のとき、IP・ホスト名とノードの対応表（任意。JSON {"<IP|ホスト名>": "<C番号|ノード ID>"}。無ければ未対応）。
                                                キーは <IP|ホスト名>:<ポート>/<tcp|udp> でもよい（完全一致のときだけ。IP・ホスト名だけのキーより優先）
  --node <C番号|ID>                             --into のとき、対応表に無いサービスを結びつけるノード（任意）
  --name <text>                                 --into を使わないとき、下書きのプロジェクト名（1〜200 文字）
  --report <json>                               機械向けの結果を標準出力に JSON で出す（--out の指定が必要。件数・未対応のホスト等）
  --locale <ja|en>                              ノード名の言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

import-scopesentry のオプション（ScopeSentry の書き出し JSON、または MCP 経由の取得から外部露出サービスの図を L1 に作り、プロジェクト JSON を出力）:
  --api <base-url>                              ファイルの代わりに <base-url>/mcp から取得する（読み取り専用の list_assets のみ呼ぶ）。
                                                API キーは環境変数 SCOPESENTRY_API_KEY で渡す（保存・出力しない）。許可された範囲にだけ使うこと
  --project <ObjectID>                          --api のとき、このプロジェクトの資産だけ取得する
  --search <expr>                               --api のとき、ScopeSentry の検索式で絞り込む
  --into <project.json>                         図の下書きの代わりに、観測したサービス（ip:port/transport）を資産として既存のプロジェクトに保存する。
                                                製品が報告した CVE は識別子（cve・未検証・最大 10 件）として残す。指定しなければ従来どおり図の下書きを出す
  --scope <scope>                               --into のとき必須。置き換えの範囲（同じ製品・同じ scope の資産を置き換える）
  --map <file>                                  --into のとき、IP・ホスト名とノードの対応表（任意。JSON {"<IP|ホスト名>": "<C番号|ノード ID>"}。無ければ未対応）。
                                                キーは <IP|ホスト名>:<ポート>/<tcp|udp> でもよい（完全一致のときだけ。IP・ホスト名だけのキーより優先）
  --node <C番号|ID>                             --into のとき、対応表に無いサービスを結びつけるノード（任意）
  --name <text>                                 --into を使わないとき、下書きのプロジェクト名（1〜200 文字）
  --report <json>                               機械向けの結果を標準出力に JSON で出す（--out の指定が必要。件数・未対応のホスト等）
  --product <name>                              --into のとき、資産の製品名（既定: ScopeSentry。同じ形で書き出す別の製品のとき。例: AI-ASM）
  --locale <ja|en>                              ノード名の言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

export-postman のオプション（検出脅威を確かめる確認リクエストを Postman Collection v2.1 で出力）:
  --layer <L0|L1|L2|L3|PQC>                     対象レイヤー（既定: ノードがある最初のレイヤー）
  --framework <STRIDE|AI|AgenticAI|ALL>         対象フレームワーク（既定: ALL）
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）
  --vars <file.json>                            変数の値（{"C7_host": "..."} 形式）を埋める。token_ を埋めると出力に認証情報が入る
  --base-url <url>                              この URL 配下へのリクエストだけ残す（DAST の base URL 用）。未使用の変数も除く

export-sbom-ai のオプション（脅威モデルから SBOM for AI（G7 Minimum Elements）を CycloneDX 1.7 JSON で出力。図に無い要素は unknown と記録する。env インベントリは出さない）:
  --layer <L0|L1|L2|L3|PQC>                     対象レイヤー（既定: ノードがある最初のレイヤー）
  --include-threats                             未抑制の脅威も vulnerabilities に載せる（既定: 載せない。実装済みの対策だけ declarations に出す）
  --author <name>                               metadata.authors に載せる作成者名（既定: 載せない）
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

export-test-plan のオプション（脅威モデルからペネトレーションテスト計画書（ベンダー中立）を出力）:
  --format <md|json>                            出力形式（既定: md）
  --layer <L0|L1|L2|L3|PQC>                     対象レイヤー（既定: ノードがある最初のレイヤー）
  --framework <STRIDE|AI|AgenticAI|ALL>         対象フレームワーク（既定: ALL）
  --changed-from <old-project.json>             前回のモデルとの差分で発火した実行トリガーの対象と追加ノードだけに絞った再診断計画にする
  --triggers <file>                             --changed-from で使う実行トリガー定義 YAML（既定: 同梱の T1〜T8）
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

export-roe のオプション（脅威モデルから交戦規定（RoE）／スコープ宣言（ベンダー中立）を出力。エージェント型ペンテストツールを自社運用する際の許可対象・スコープ外・承認方針）:
  --format <md|json>                            出力形式（既定: md）
  --layer <L0|L1|L2|L3|PQC>                     対象レイヤー（既定: ノードがある最初のレイヤー）
  --framework <STRIDE|AI|AgenticAI|ALL>         対象フレームワーク（既定: ALL）
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

export-attack-navigator のオプション（検出脅威の参照から MITRE ATT&CK Navigator レイヤー（JSON）を出力。CTEM / BAS / SOC での取り込み用。ATLAS は説明文に併記）:
  --node <C番号>                                攻撃者ノードの ID。指定すると、その攻撃シナリオ（攻撃者 → 標的）の上位経路上の脅威だけで出力（例: C1）
  --layer <L0|L1|L2|L3|PQC>                     対象レイヤー（既定: ノードがある最初のレイヤー）
  --framework <STRIDE|AI|AgenticAI|ALL>         対象フレームワーク（既定: ALL）
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

export-investigation-plan のオプション（侵害の疑いがあるとき、脅威モデルから「どこを・何を調べるか」と「調べられない恐れ」をノードごとにまとめた調査計画（ベンダー中立）を出力。侵害の有無は判定しない）:
  --format <md|json>                            出力形式（既定: md）
  --layer <L0|L1|L2|L3|PQC>                     対象レイヤー（既定: ノードがある最初のレイヤー）
  --tool <velociraptor>                         指定したツールでの確認の手がかり（アーティファクト名など）も載せる（既定: 載せない）
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

export-contractor-paths のオプション（委託先の接続経路の一覧を MFA 切り替えの優先順に出力。判別はヒューリスティックで各行は確認すべき候補。委託先の評価はしない）:
  --format <md|csv|json>                        出力形式（既定: md）
  --layer <L0|L1|L2|L3|PQC>                     対象レイヤー（既定: ノードがある最初のレイヤー）
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

export-event-log のオプション（git の履歴（1 コミット＝1 版）から、脅威・指摘への対応の経過をプロセスマイニング用のイベントログ（OCEL 2.0 JSON か、脅威を案件とする CSV）にする。全ての版を現在の脅威ライブラリで解析するため、脅威の出現・解消は図の変更だけで起きる。要素名と変更した人（コミットの作者）を含む。読み取りのみ）:
  --repo <dir>                                  git のリポジトリ（必須）
  --path <model.json>                           リポジトリ内のプロジェクト JSON（必須）
  --since <YYYY-MM-DD>                          この日以降のコミットだけ
  --max-commits <n>                             読む版の最大数（既定: 500・上限 5000。新しい側から）
  --format <ocel|csv>                           出力形式（既定: ocel）
  --out <file>                                  出力先ファイル（既定: 標準出力。CSV をファイルに書くときは BOM 付き）

export-requirements のオプション（脅威モデルから、設計段階で明確にするセキュリティ要件の一覧（たたき台）を出力。緩和策の段階・対象ノード・工程・NIST CSF・委託先への要求を載せる。採否は人間が決める）:
  --format <md|csv|json>                        出力形式（既定: md）
  --layer <L0|L1|L2|L3|PQC>                     対象レイヤー（既定: ノードがある最初のレイヤー）
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

export-detection-requirements のオプション（攻撃経路上のノードごとに「監視すべき振る舞い」「必要なログ」と、ログが監視先に届かない区間をまとめる。検知できることは示さない）:
  --format <md|json|sigma>                      出力形式（既定: md。sigma は要件ごとの Sigma ルールの下書き〔複数文書の YAML〕。検知の条件は空欄で status: unsupported）
  --layer <L0|L1|L2|L3|PQC>                     対象レイヤー（既定: ノードがある最初のレイヤー）
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

export-triage-patterns のオプション（tools/triage/crs_triage.py の --patterns に渡す検索パターンを JSON で書き出す。モデルは不要）:
  --out <file>                                  出力先ファイル（既定: 標準出力）

investigation-report のオプション（集めた証拠をノードに重ね、「痕跡あり／痕跡なし（調べた期間つき）／否定できない／未調査」と図に無いホストを報告。侵害の有無は判定しない。JSON だけ読む）:
  --evidence <dir|file>                         証拠（必須・複数指定可）。トリアージの JSON、または Velociraptor の収集結果を展開したフォルダー（results/ を持つフォルダーを再帰的に探す。zip・CSV は読まない）
  --hosts <hosts.json>                          ホスト名とノードの対応表（必須。{"hosts":[{"host":"web01","node":"C3"}]}。大文字小文字を無視し、FQDN の先頭ラベルでも照合）
  --format <md|json>                            出力形式（既定: md）
  --layer <L0|L1|L2|L3|PQC>                     対象レイヤー（既定: ノードがある最初のレイヤー）
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

findings-report のオプション（スキャン結果の指摘を、対応表（Veracode は CWE、skill-scanner / mcp-scanner は AITech）を介して検出脅威と突き合わせる。ファイル入力のみ）:
  --veracode <file>                             Veracode の結果（Pipeline Scan の results.json または Findings API v2 の応答 JSON）
  --skill-scanner <file>                        Cisco AI Defense skill-scanner の結果（--format json。scan-all の出力も可）
  --mcp-scanner <file>                          Cisco AI Defense mcp-scanner の結果（--format raw / --raw / known-configs --raw）
                                                上の 3 つのうちちょうど 1 つを指定する
  --node <C番号>                                対象のノードの ID（任意。指定時はそのノード・接する線・線の先のノード・内包の親子の脅威とだけ突き合わせる）
  --format <md|json>                            出力形式（既定: md）
  --layer <L0|L1|L2|L3|PQC>                     対象レイヤー（既定: ノードがある全レイヤー）
  --framework <STRIDE|AI|AgenticAI|ALL>         対象フレームワーク（既定: ALL）
  --fail-on <Critical|High|Medium|Low>          Veracode の指摘で裏付けられた未抑制の脅威が指定重大度以上なら exit 1
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

pqc-sbom-report のオプション（CycloneDX の SBOM／CBOM（JSON）から、指定したノードの暗号を確認するレポートを出す。図は変えない。ファイル入力のみ）:
  --sbom <file>                                 CycloneDX の JSON（必須。1.6 / 1.7。XML は読めない）
  --node <C番号>                                対象のノードの ID（必須。例: C3）
  --format <md|json>                            出力形式（既定: md）
  --layer <L0|L1|L2|L3|PQC>                     対象レイヤー（既定: ノードがある PQC レイヤー、無ければノードがある最初のレイヤー）
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

mcp のオプション（stdio の MCP サーバーとして起動。stdout は MCP プロトコル専用）:
  --root <dir>                                  読み書きを許可するディレクトリ（既定: カレントディレクトリ）
  --triggers <file>                             実行トリガー定義 YAML（既定: 同梱の T1〜T8。指定時は翻訳オーバーレイ非適用）
  --locale <ja|en>                              表示言語（既定: ja。起動中は固定）

共通:
  --help                                        このヘルプを表示

終了コード: 0=成功 / 1=--fail-on / --fail-on-findings / --fail-on-action によるゲート不合格 / 2=入力・引数エラー`;
