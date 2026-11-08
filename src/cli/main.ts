import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { basename, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';
import { z } from 'zod';
import {
  analyzeProject,
  analyzeResolvedProject,
  evaluateGate,
  resolveProject,
  type LayerAnalysisResult,
  type ResolvedProject,
} from './analyze';
import { toSarif } from './sarif';
import { evaluateSavedFindingsGate, formatGateFinding } from './findingsGate';
import {
  diffProjects,
  diffToJson,
  diffToMarkdown,
  evaluateDiffGate,
  type DiffGateResult,
  type ProjectDiff,
} from './diff';
import { triggersToJson, triggersToMarkdown } from './triggers';
import {
  collectModelThreats,
  countNodeMatches,
  findingsReportToJson,
  findingsReportToMarkdown,
  type FindingsGateResult,
  type FindingsSource,
} from './findingsReport';
import { parseVeracodeFindings } from '../features/findings-report/parseVeracode';
import { parseSkillScannerFindings } from '../features/findings-report/parseSkillScanner';
import { parseMcpScannerFindings } from '../features/findings-report/parseMcpScanner';
import { parseProwlerOcsf } from '../features/prowler-import/parseProwlerOcsf';
import { importSarif, sarifReportToJson, sarifReportToMarkdown } from './importSarif';
import { importNuclei, nucleiReportToJson, nucleiReportToMarkdown } from './importNuclei';
import { parseNuclei } from '../features/nuclei-import/parseNuclei';
import { importKev, kevReportToJson, kevReportToMarkdown } from './importKev';
import { fillPatchStatusToMarkdown, runFillPatchStatus } from './fillPatchStatus';
import { parseKevCatalog } from '../features/kev-import/applyKev';
import { importEpss, epssReportToJson, epssReportToMarkdown } from './importEpss';
import { parseEpssCsv } from '../features/epss-import/applyEpss';
import { findingsPriority, priorityToJson, priorityToMarkdown } from './findingsPriority';
import { asmReconcile, reconcileToJson, reconcileToMarkdown } from './asmReconcile';
import { sbomReport, sbomReportToJson, sbomReportToMarkdown } from './sbomReport';
import { contextLookup, contextToMarkdown } from './context';
import { parseSarif } from '../features/sarif-import/parseSarif';
import { importProwler, prowlerReportToJson, prowlerReportToMarkdown } from './importProwler';
import {
  findingsReportToJson as importFindingsReportToJson,
  findingsReportToMarkdown as importFindingsReportToMarkdown,
  importFindings,
} from './importFindings';
import { parseScap } from '../features/scap-import/parseScap';
import { importPentest, pentestReportToJson, pentestReportToMarkdown } from './importPentest';
import { parseRegistry } from '../features/pentest-import/parseRegistry';
import { importSecurityAudit, securityAuditReportToJson, securityAuditReportToMarkdown } from './importSecurityAudit';
import {
  SECURITY_AUDIT_MAX_BYTES,
  parseCoverageLedger,
  parseSecurityAudit,
} from '../features/security-audit-import/parseSecurityAudit';
import { parseArtexEndpoints, parseArtexServices } from '../features/asset-import/artexAssets';
import { parseCyberStrikeAiAssets } from '../features/asset-import/cyberstrikeaiAssets';
import type { PentestEndpointRecord, PentestServiceRecord } from '../features/asset-import/pentestAssetRecord';
import { parseBom } from '../features/bom-import/parseBom';
import { deserializeProject } from '../features/persistence/serialize';
import { version as APP_VERSION } from '../../package.json';
import { buildSpdx } from '../features/bom-import/buildSpdx';
import { listBomComponents } from '../features/bom-import/listBomComponents';
import { bomReportToJson, bomReportToMarkdown, importBom } from './importBom';
import { importAsmAssets } from './importAsmAssets';
import {
  AIPENTEST_ASSET_TOOL_KEYS,
  aipentestAssetsReportToJson,
  aipentestAssetsReportToMarkdown,
  importAipentestAssets,
} from './importAipentestAssets';
import { MAX_FILE_BYTES } from './readEvidence';
import { buildFindingsReport, evaluateFindingsGate } from '../features/findings-report/buildFindingsReport';
import { BUNDLED_AITECH_MAP, BUNDLED_FINDING_MAP } from '../features/findings-report/findingMap';
import { buildThreatReport, toDCRHThreatModelMarkdown, toJsonObject } from '../features/export/threatReport';
import { effectiveSeverity } from '../core/model/risk';
import { setLocale, translate, type Locale } from '../i18n';
import { ATTACK_OBJECTIVE_APPLICABLE, LAYER_KEYS, MAX_FINDINGS, type Asset, type Finding, type FrameworkView, type Severity } from '../core/model/types';
import { formatElementalId } from '../core/model/elementalId';
import { getChangeTriggers } from '../change-triggers/loader/bundledChangeTriggers';
import { loadChangeTriggers } from '../change-triggers/loader/loadChangeTriggers';
import type { ChangeTrigger } from '../change-triggers/schema/trigger';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createCrsMcpServer } from '../mcp/server';
import { BRANDING } from '../core/branding';
import { kongToLayer } from '../features/kong-import/kongToLayer';
import { layerToProject } from '../features/kong-import/toProject';
import { kongctlToLayer } from '../features/kongctl-import/kongctlToLayer';
import { collectRepo } from '../features/repo-import/collectRepo';
import { repoToLayer } from '../features/repo-import/repoToLayer';
import { buildRepoDashboard } from '../features/repo-import/buildRepoDashboard';
import { renderRepoDashboardHtml } from '../features/repo-import/renderRepoDashboardHtml';
import { conjurToLayer } from '../features/conjur-import/conjurToLayer';
import { shodanToLayer } from '../features/shodan-import/shodanToLayer';
import { scopesentryRecordsToLayer, scopesentryToLayer, type ScopesentryImportResult } from '../features/scopesentry-import/scopesentryToLayer';
import { apiKeyFromEnv, fetchViaMcp, MAX_RECORDS } from '../features/scopesentry-import/fetchViaMcp';
import { cyberStrikeToRegistry, parseCyberStrikeVulns, registryToYaml } from '../features/pentest-import/cyberStrikeToRegistry';
import { fetchCyberStrikeVulns, tokenFromEnv } from '../features/pentest-import/fetchCyberStrike';
import { strixToRegistry, strixToYaml } from '../features/pentest-import/strixToRegistry';
import { metasploitToRegistry, metasploitToYaml } from '../features/pentest-import/metasploitToRegistry';
import { parseHostNodeArgs, parseMetasploit } from '../features/metasploit-import/parseMetasploit';
import { importMetasploitAssets, metasploitAssetsReportToJson, metasploitAssetsReportToMarkdown } from './importMetasploitAssets';
import { toPostmanCollection } from '../features/postman-export/toPostmanCollection';
import { buildSbomForAi } from '../features/sbom-ai/buildSbomForAi';
import { VarsFileSchema, applyVariableValues, filterByBaseUrl } from '../features/postman-export/dastOptions';
import { buildTestPlan } from '../features/test-plan/buildTestPlan';
import { computeRetestScope } from '../features/test-plan/retestScope';
import { detectTriggers } from '../change-triggers/detectTriggers';
import { parseSbomText } from '../features/sbom-crypto/parseCycloneDx';
import {
  buildSbomCryptoReport,
  edgesTouchingNode,
  nodeElementalId,
} from '../features/sbom-crypto/buildSbomCryptoReport';
import { sbomCryptoToJson, sbomCryptoToMarkdown } from '../features/sbom-crypto/sbomCryptoOutput';
import { BUNDLED_ALGORITHM_TABLE, getCryptoLibraries } from '../crypto-behavior/bundled';
import { testPlanToJson, testPlanToMarkdown } from '../features/test-plan/testPlanOutput';
import { buildRoe } from '../features/roe-export/buildRoe';
import { roeToJson, roeToMarkdown } from '../features/roe-export/roeOutput';
import { buildNavigatorLayer, navigatorLayerToJson } from '../features/attack-navigator/buildNavigatorLayer';
import { buildInvestigationPlan } from '../features/investigation-plan/buildInvestigationPlan';
import { buildDetectionRequirements } from '../features/detection-requirements/buildDetectionRequirements';
import {
  detectionRequirementsToJson,
  detectionRequirementsToMarkdown,
} from '../features/detection-requirements/detectionRequirementsOutput';
import { buildContractorPaths } from '../features/contractor-paths/buildContractorPaths';
import {
  contractorPathsToCsv,
  contractorPathsToJson,
  contractorPathsToMarkdown,
} from '../features/contractor-paths/contractorPathsOutput';
import { buildRequirements } from '../features/requirements-export/buildRequirements';
import {
  requirementsToCsv,
  requirementsToJson,
  requirementsToMarkdown,
} from '../features/requirements-export/requirementsOutput';
import { buildInvestigationReport, parseHostMap } from '../features/investigation-report/buildInvestigationReport';
import {
  investigationReportToJson,
  investigationReportToMarkdown,
} from '../features/investigation-report/investigationReportOutput';
import { readEvidence } from './readEvidence';
import { buildTriagePatterns } from '../features/investigation-plan/triagePatterns';
import { getInvestigationViewpoints } from '../features/investigation-plan/viewpoints';
import {
  investigationPlanToJson,
  investigationPlanToMarkdown,
} from '../features/investigation-plan/investigationPlanOutput';
import { getChecklists } from '../checklist/bundled';
import { evaluateChecklist } from '../checklist/evaluate';
import { toChecklistCsv, toChecklistJson, toChecklistMarkdown } from '../checklist/report';
import { formatLocalDate } from '../core/model/localDate';

/**
 * CyberRiskScape ヘッドレス CLI。
 * 保存済みプロジェクト JSON を入力に、ブラウザなしで脅威を検出してレポートを出す
 * （`analyze`）か、2 版を比較して実行トリガー・脅威差分・ゲート判定を出す（`diff`）。
 * カスタムルール（IndexedDB 別保存）は含まれないため、同梱ルールのみで評価する。
 */

const ANALYZE_FORMATS = ['json', 'sarif', 'md'] as const;
const DIFF_FORMATS = ['md', 'json'] as const;
const TRIGGERS_FORMATS = ['md', 'json'] as const;
const CHECKLIST_FORMATS = ['md', 'json', 'csv'] as const;
const FINDINGS_REPORT_FORMATS = ['md', 'json'] as const;
const IMPORT_PROWLER_REPORTS = ['md', 'json'] as const;
const IMPORT_FINDINGS_FORMATS = ['xccdf', 'arf', 'oval'] as const;
const TEST_PLAN_FORMATS = ['md', 'json'] as const;
const REQUIREMENTS_FORMATS = ['md', 'csv', 'json'] as const;
const INVESTIGATION_TOOLS = ['velociraptor'] as const;
const SBOM_CRYPTO_FORMATS = ['md', 'json'] as const;

const FRAMEWORKS: readonly FrameworkView[] = ['STRIDE', 'AI', 'AgenticAI', 'ALL'];
const SEVERITIES: readonly Severity[] = ['Low', 'Medium', 'High', 'Critical'];
const LOCALES: readonly Locale[] = ['ja', 'en'];

const USAGE = `使い方:
  analyze <project.json> [options]
  diff <base.json> <head.json> [options]
  triggers [options]
  checklist <project.json> --id <checklistId> [options]
  import-kong <kong.yaml> [options]
  import-kongctl <kongctl.yaml> [options]
  import-repo <dir> [options]
  import-prowler <project.json> --ocsf <file> [options]
  import-findings <project.json> --format <xccdf|arf|oval> --in <file> [options]
  import-pentest <project.json> --in <registry.yaml> [options]
  convert-cyberstrikeai [<vulns.json>] [--api <base-url>] --scope <scope> [options]
  convert-strix <findings.sarif | strix_runs/<run>> --scope <scope> [options]
  convert-metasploit <export.xml> --scope <scope> [--host-node <IP>=<C番号|ID> ...] [options]
  import-sarif <project.json> --sarif <file> --scope <scope> [options]
  import-nuclei <project.json> --in <results.jsonl> --scope <scope> [options]
  import-security-audit <project.json> --in <findings.json> [options]
  import-kev <project.json> --kev <file> [options]
  import-epss <project.json> --epss <epss_scores.csv[.gz]> [options]
  fill-patch-status <project.json> [options]
  findings-priority <project.json> [options]
  asm-reconcile <project.json> [options]
  sbom-report <project.json> [options]
  context <project.json> (--ip <ip> | --host <name> | --purl <purl>) [options]
  import-aipentest-assets <project.json> --format <artex|cyberstrikeai> --scope <scope> [--services <file>] [--endpoints <file>] [--assets <file> ...] [options]
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
  --format <artex|cyberstrikeai>                入力の形（必須）
  --assets <file>                               cyberstrikeai: GET /api/assets?page=N&page_size=100 の JSON（必須。ページごとに繰り返し可）。手で登録した資産（manual）と inactive は読まない
  --services <file>                             artex: GET /api/assets?type=service&task_id=N の JSON（--endpoints とどちらか必須）
  --endpoints <file>                            artex: GET /api/assets?type=endpoint&task_id=N の JSON
  --scope <scope>                               置き換えの範囲（必須。例: task-3）
  --map <file>                                  ホストとノードの対応表（任意。JSON {"<IP|ドメイン>": "<C番号|ノード ID>"}）
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
  --report <md|json>                            報告の形式（既定: md。標準出力）
  -o, --out <file>                              指摘を保存したプロジェクト JSON の出力先（指定しなければ報告のみ）

import-security-audit のオプション（AI によるソース監査（Cloudflare security-audit スキル）の findings.json を指摘として保存する。confirmed は成立を確認した指摘、needs_validation は重大度なしの要確認として保存し、rejected は保存しない。payloads・修正コード・evidence・root_cause の本文は保存しない）:
  --in <findings.json>                          findings.json（必須。16 MB まで）
  --ledger <coverage-ledger.json>               coverage-ledger.json（任意。攻撃クラスから脅威へ対応づける。16 MB まで）
  --scope <scope>                               置き換えの範囲（既定: default。同じ製品・同じ scope の指摘を置き換える）
  --node <C番号|ID>                             すべての指摘を結びつけるノード（任意。無ければ未結合）
  --report <md|json>                            報告の形式（既定: md。標準出力）
  -o, --out <file>                              指摘を保存したプロジェクト JSON の出力先（指定しなければ報告のみ）

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
  --map <file>                                  --into のとき、IP・ホスト名とノードの対応表（任意。JSON {"<IP|ホスト名>": "<C番号|ノード ID>"}。無ければ未対応）
  --node <C番号|ID>                             --into のとき、対応表に無いサービスを結びつけるノード（任意）
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
  --map <file>                                  --into のとき、IP・ホスト名とノードの対応表（任意。JSON {"<IP|ホスト名>": "<C番号|ノード ID>"}。無ければ未対応）
  --node <C番号|ID>                             --into のとき、対応表に無いサービスを結びつけるノード（任意）
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

export-requirements のオプション（脅威モデルから、設計段階で明確にするセキュリティ要件の一覧（たたき台）を出力。緩和策の段階・対象ノード・工程・NIST CSF・委託先への要求を載せる。採否は人間が決める）:
  --format <md|csv|json>                        出力形式（既定: md）
  --layer <L0|L1|L2|L3|PQC>                     対象レイヤー（既定: ノードがある最初のレイヤー）
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

export-detection-requirements のオプション（攻撃経路上のノードごとに「監視すべき振る舞い」「必要なログ」と、ログが監視先に届かない区間をまとめる。検知できることは示さない）:
  --format <md|json>                            出力形式（既定: md）
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

function fail(message: string): never {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}

function parseEnum<T extends string>(
  value: string | undefined,
  allowed: readonly T[],
  optionName: string,
): T | undefined {
  if (value === undefined) return undefined;
  if (!(allowed as readonly string[]).includes(value)) {
    fail(`不正な --${optionName} の値です: "${value}"（指定可能: ${allowed.join(' | ')}）`);
  }
  return value as T;
}

function readJsonFile(file: string): unknown {
  let text: string;
  try {
    text = readFileSync(file, 'utf-8');
  } catch (e) {
    fail(`ファイルを読み込めません: ${file}（${e instanceof Error ? e.message : String(e)}）`);
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    fail(`JSON の解析に失敗しました（${file}）: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/**
 * `--triggers <file>` を読む共通処理（`diff` / `triggers` サブコマンドで共有）。
 * 未指定なら同梱の T1〜T8（指定 locale の翻訳オーバーレイ適用）を返す。
 */
function resolveTriggers(values: CliValues, locale: Locale): ChangeTrigger[] {
  if (!values.triggers) return getChangeTriggers(locale).triggers;

  const triggersFile = values.triggers;
  let yamlText: string;
  try {
    yamlText = readFileSync(triggersFile, 'utf-8');
  } catch (e) {
    fail(
      `トリガー定義ファイルを読み込めません: ${triggersFile}（${e instanceof Error ? e.message : String(e)}）`,
    );
  }
  try {
    // カスタムファイルには翻訳オーバーレイを適用しない（原文のまま使う）。
    return loadChangeTriggers([{ source: triggersFile, text: yamlText }]).triggers;
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
}

function writeOutput(output: string, outFile: string | undefined): void {
  if (outFile) {
    writeFileSync(outFile, output, 'utf-8');
  } else {
    process.stdout.write(`${output}\n`);
  }
}

/** `parseArgs` の呼び出しを切り出す（options リテラルを直接渡して戻り値の型を具体化するため）。 */
function parseCliArgs() {
  return parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    strict: true,
    options: {
      format: { type: 'string' },
      layer: { type: 'string' },
      framework: { type: 'string' },
      'fail-on': { type: 'string' },
      'fail-on-action': { type: 'boolean' },
      'fail-on-findings': { type: 'string' },
      'changed-from': { type: 'string' },
      id: { type: 'string' },
      'as-of': { type: 'string' },
      triggers: { type: 'string' },
      locale: { type: 'string' },
      tool: { type: 'string' },
      out: { type: 'string', short: 'o' },
      dashboard: { type: 'string' },
      ocsf: { type: 'string' },
      in: { type: 'string' },
      map: { type: 'string' },
      services: { type: 'string' },
      endpoints: { type: 'string' },
      assets: { type: 'string', multiple: true },
      report: { type: 'string' },
      root: { type: 'string' },
      vars: { type: 'string' },
      veracode: { type: 'string' },
      'skill-scanner': { type: 'string' },
      'mcp-scanner': { type: 'string' },
      evidence: { type: 'string', multiple: true },
      hosts: { type: 'string' },
      sbom: { type: 'string' },
      sarif: { type: 'string' },
      ledger: { type: 'string' },
      kev: { type: 'string' },
      epss: { type: 'string' },
      'epss-threshold': { type: 'string' },
      'dry-run': { type: 'boolean' },
      previous: { type: 'string' },
      'max-age-days': { type: 'string' },
      attacker: { type: 'string' },
      ip: { type: 'string' },
      host: { type: 'string' },
      purl: { type: 'string' },
      node: { type: 'string' },
      xml: { type: 'string' },
      'host-node': { type: 'string', multiple: true },
      'base-url': { type: 'string' },
      author: { type: 'string' },
      'include-threats': { type: 'boolean' },
      'with-findings': { type: 'boolean' },
      api: { type: 'string' },
      project: { type: 'string' },
      'project-id': { type: 'string' },
      'task-id': { type: 'string' },
      search: { type: 'string' },
      scope: { type: 'string' },
      into: { type: 'string' },
      help: { type: 'boolean' },
    },
  });
}

type CliValues = ReturnType<typeof parseCliArgs>['values'];

function runAnalyze(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。\n\n${USAGE}`);
  }

  const format = parseEnum(values.format, ANALYZE_FORMATS, 'format') ?? 'json';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const framework = parseEnum(values.framework, FRAMEWORKS, 'framework');
  const failOn = parseEnum(values['fail-on'], SEVERITIES, 'fail-on');
  const failOnFindings = parseEnum(values['fail-on-findings'], SEVERITIES, 'fail-on-findings');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  if (values['with-findings'] && format !== 'sarif') fail('--with-findings は --format sarif のときだけ使えます。');

  const raw = readJsonFile(file);

  // 脅威本文のテンプレート展開（`renderTemplate`）とレポート生成はどちらも `getLocale()`
  // （モジュール内グローバル）を読むため、検出より前に揃える（App.tsx の JA/EN 切替と同じ経路）。
  setLocale(locale);

  let results: LayerAnalysisResult[];
  let findings: Finding[] | undefined;
  try {
    const resolved = resolveProject(raw);
    results = analyzeResolvedProject(resolved, { layer, framework, locale });
    if (values['with-findings'] || failOnFindings) findings = resolved.findings;
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }

  const artifactUri = file.replace(/\\/g, '/');
  let output: string;
  if (format === 'sarif') {
    output = JSON.stringify(
      toSarif(results, { artifactUri, findings: values['with-findings'] ? findings : undefined }),
      null,
      2,
    );
  } else if (format === 'md') {
    const exportDate = formatLocalDate(new Date());
    output = results.map((r) => toDCRHThreatModelMarkdown(r.input, exportDate)).join('\n\n');
  } else {
    output = JSON.stringify(results.map((r) => toJsonObject(buildThreatReport(r.input))), null, 2);
  }

  writeOutput(output, values.out);

  if (failOn) {
    const offenders = evaluateGate(results.flatMap((r) => r.threats), failOn);
    if (offenders.length > 0) {
      process.stderr.write(
        `--fail-on ${failOn}: 未抑制の脅威が ${offenders.length} 件しきい値以上です。\n`,
      );
      for (const t of offenders) {
        process.stderr.write(`  - [${effectiveSeverity(t)}] ${t.category}: ${t.description}\n`);
      }
      // process.exit() はパイプ先への stdout 書き込みを打ち切り得るため、終了コードだけ設定する。
      process.exitCode = 1;
    }
  }

  if (failOnFindings) {
    // --layer 指定時は、そのレイヤーの指摘と未結合の指摘だけを判定する（他レイヤーの受容を判定できないため）
    const targets = (findings ?? []).filter((f) => !layer || !f.subject || f.subject.layer === layer);
    const offenders = evaluateSavedFindingsGate(targets, results, failOnFindings);
    if (offenders.length > 0) {
      process.stderr.write(
        `--fail-on-findings ${failOnFindings}: 保存済みの指摘が ${offenders.length} 件しきい値以上です（試行のみ・受容済みを除く）。\n`,
      );
      for (const f of offenders) process.stderr.write(`  - ${formatGateFinding(f, results)}\n`);
      process.exitCode = 1;
    }
  }
}

function runDiff(values: CliValues, positionals: string[]): void {
  const baseFile = positionals[1];
  const headFile = positionals[2];
  if (!baseFile || !headFile) {
    fail(`base.json と head.json を指定してください。\n\n${USAGE}`);
  }

  const format = parseEnum(values.format, DIFF_FORMATS, 'format') ?? 'md';
  const failOn = parseEnum(values['fail-on'], SEVERITIES, 'fail-on');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';

  const baseRaw = readJsonFile(baseFile);
  const headRaw = readJsonFile(headFile);

  const triggers: ChangeTrigger[] = resolveTriggers(values, locale);

  setLocale(locale);

  let diff: ProjectDiff;
  try {
    diff = diffProjects(baseRaw, headRaw, { locale, triggers });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }

  const gate: DiffGateResult | undefined = failOn
    ? { failOn, offenders: evaluateDiffGate(diff, failOn) }
    : undefined;

  const output = format === 'json' ? diffToJson(diff, gate) : diffToMarkdown(diff, gate);
  writeOutput(output, values.out);

  if (gate && gate.offenders.length > 0) {
    process.stderr.write(
      `${translate('diff.gate.stderr', locale, { failOn: gate.failOn, count: gate.offenders.length })}\n`,
    );
    for (const { threat, asset } of gate.offenders) {
      process.stderr.write(`  - [${effectiveSeverity(threat)}] ${asset} ${threat.name ?? threat.category}\n`);
    }
    process.exitCode = 1;
  }
}

/**
 * `triggers`：実行トリガー（T1〜T8 等）をチェックリストとして出す。
 * PR テンプレートや AI レビュアーの観点表にそのまま使える。ゲート判定は無い（exit 0 固定、
 * 入力・引数エラーのみ 2）。
 */
function runTriggers(values: CliValues): void {
  const format = parseEnum(values.format, TRIGGERS_FORMATS, 'format') ?? 'md';
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';

  const triggers = resolveTriggers(values, locale);

  setLocale(locale);

  const output = format === 'json' ? triggersToJson(triggers) : triggersToMarkdown(triggers);
  writeOutput(output, values.out);
}

/**
 * `checklist`：注意喚起チェックリスト（`data/checklists/`）を構成図に当てはめ、項目ごとの状態
 * （要対応 / 未入力 / リスク受容 / 問題なし / 対象なし）と、点検が古い・未記録のノードを出す。
 * 同梱ルールのみで評価する（カスタムルール・誤検知やリスク受容の記録はプロジェクト JSON のものを使う）。
 */
function runChecklist(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const format = parseEnum(values.format, CHECKLIST_FORMATS, 'format') ?? 'md';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  const checklists = getChecklists(locale);
  const checklist = checklists.find((c) => c.checklist.id === values.id);
  if (!checklist) {
    fail(translate('checklist.cli.unknownId', locale, {
      id: values.id ?? '',
      ids: checklists.map((c) => c.checklist.id).join(' | '),
    }));
  }

  const asOf = values['as-of'] ?? new Date().toISOString().slice(0, 10);
  const asOfDate = /^\d{4}-\d{2}-\d{2}$/.test(asOf) ? new Date(`${asOf}T00:00:00Z`) : undefined;
  if (!asOfDate || Number.isNaN(asOfDate.getTime()) || asOfDate.toISOString().slice(0, 10) !== asOf) {
    fail(translate('checklist.cli.invalidAsOf', locale, { value: asOf }));
  }

  const raw = readJsonFile(file);
  let resolved: ResolvedProject;
  let results: LayerAnalysisResult[];
  try {
    resolved = resolveProject(raw);
    results = analyzeResolvedProject(resolved, { layer, framework: 'ALL', locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail(translate('checklist.cli.noNodes', locale));

  const result = evaluateChecklist({ checklist, nodes: target.input.nodes, threats: target.threats, asOf });
  const ctx = { result, project: resolved.projectMeta, layer: target.layer, locale };
  const output =
    format === 'json'
      ? JSON.stringify(toChecklistJson(ctx), null, 2)
      : format === 'csv'
        ? toChecklistCsv(ctx)
        : toChecklistMarkdown(ctx);
  writeOutput(output, values.out);

  if (values['fail-on-action'] && result.summary.action > 0) {
    process.stderr.write(`${translate('checklist.cli.failOnAction', locale, { count: result.summary.action })}
`);
    process.exitCode = 1;
  }
}

/**
 * `import-kong`：Kong の宣言設定（decK の kong.yaml / JSON）から構成図の下書きを作り、
 * プロジェクト JSON を出力する。出力は `analyze` / `diff` の入力やアプリでの読み込みにそのまま使える。
 * 認証ヘッダ・資格情報の値は読まない（`kongToLayer` 参照）。
 */
function runImportKong(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let text: string;
  try {
    text = readFileSync(file, 'utf-8');
  } catch (e) {
    fail(`ファイルを読み込めません: ${file}（${e instanceof Error ? e.message : String(e)}）`);
  }
  const result = kongToLayer(text);
  if (!result.ok) fail(result.error);

  writeOutput(JSON.stringify(layerToProject(result.layer), null, 2), values.out);
  const { services, routes, plugins, consumers } = result.summary;
  process.stderr.write(
    `Kong 設定を取り込みました（サービス ${services} / ルート ${routes} / プラグイン ${plugins} / コンシューマー ${consumers}）
`,
  );
}

/**
 * `import-kongctl`：Kong AI Gateway 2.x の kongctl 宣言ファイルから構成図の下書きを作り、
 * プロジェクト JSON を出力する。`!secret` の中身・認証情報は読まない（`kongctlToLayer` 参照）。
 */
function runImportKongctl(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let text: string;
  try {
    text = readFileSync(file, 'utf-8');
  } catch (e) {
    fail(`ファイルを読み込めません: ${file}（${e instanceof Error ? e.message : String(e)}）`);
  }
  const result = kongctlToLayer(text);
  if (!result.ok) fail(result.error);

  writeOutput(JSON.stringify(layerToProject(result.layer), null, 2), values.out);
  const s = result.summary;
  process.stderr.write(
    `kongctl 設定を取り込みました（ゲートウェイ ${s.gateways} / モデル ${s.models} / MCP サーバー ${s.mcpServers} / エージェント ${s.agents} / ポリシー ${s.policies} / コンシューマー ${s.consumers}）
`,
  );
}

/**
 * `import-repo`：コーディングエージェントの作業ディレクトリ（リポジトリ）から、開発環境と依存パッケージの
 * 構成図の下書きを作り、プロジェクト JSON を出力する。`.env` の値・認証情報は出力しない（`repoToLayer` 参照）。
 */
function runImportRepo(values: CliValues, positionals: string[]): void {
  const dir = positionals[1];
  if (!dir) {
    fail(`ディレクトリを指定してください。

${USAGE}`);
  }
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let isDir = false;
  try {
    isDir = statSync(dir).isDirectory();
  } catch {
    // 下の fail で報告する
  }
  if (!isDir) fail(`ディレクトリを読み込めません: ${dir}`);

  const collected = collectRepo(dir);
  const result = repoToLayer(collected.files, {
    collectedAt: new Date().toISOString(),
    gitIgnored: collected.gitIgnored,
    repoName: collected.repoName,
  });
  if (!result.ok) fail(result.error);

  writeOutput(JSON.stringify(layerToProject(result.layer), null, 2), values.out);
  const s = result.summary;
  const warnings = [...collected.warnings, ...s.warnings];
  process.stderr.write(
    `リポジトリを取り込みました（マニフェスト ${s.manifests} / パッケージ ${s.packages} / インストールスクリプトあり ${s.installScriptPackages} / .env ${s.envFiles} / MCP サーバー ${s.mcpServers} / スキル ${s.skills} / コマンド ${s.commands}）
`,
  );
  for (const w of warnings) process.stderr.write(`警告: ${w}
`);

  if (values.dashboard) {
    const agent = result.layer.nodes.find((n) => n.inventory?.kind === 'agent');
    const data = agent ? buildRepoDashboard(result.layer, agent.id) : undefined;
    if (!data) {
      process.stderr.write('警告: エージェントの設定（.claude/）が見つからないため、ダッシュボードは出力しません\n');
    } else {
      writeFileSync(values.dashboard, renderRepoDashboardHtml(data, locale), 'utf-8');
      process.stderr.write(`ダッシュボードを出力しました: ${values.dashboard}\n`);
    }
  }
}

/**
 * `import-prowler`：Prowler の OCSF 出力の検査結果を、プロジェクト JSON のノードの運用状況・攻撃面属性に載せる。
 * 未入力の項目だけ埋めて `-o` に書き出し、報告（既定 md）は標準出力。API は呼ばない。
 */
function runImportProwler(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  if (!values.ocsf) fail('--ocsf <file> を指定してください（Prowler の *.ocsf.json）。');
  const report = parseEnum(values.report, IMPORT_PROWLER_REPORTS, 'report') ?? 'md';
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  const parsed = parseProwlerOcsf(readJsonFile(values.ocsf));
  if (!parsed.ok) fail(`${parsed.error}（${values.ocsf}）`);
  let nodeMap: Record<string, string> = {};
  if (values.map) {
    const m = z.record(z.string(), z.string()).safeParse(readJsonFile(values.map));
    if (!m.success) fail(`--map は {"<資源の uid または名前>": "<ノード ID>"} の JSON にしてください（${values.map}）`);
    nodeMap = m.data;
  }

  let out: ReturnType<typeof importProwler>;
  try {
    out = importProwler(readJsonFile(file), parsed, nodeMap, undefined, new Date().toISOString());
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (values.out) writeFileSync(values.out, JSON.stringify(out.project, null, 2), 'utf-8');
  process.stdout.write(
    `${report === 'json' ? JSON.stringify(prowlerReportToJson(out), null, 2) : prowlerReportToMarkdown(out)}
`,
  );
  const s = out.result.summary;
  process.stderr.write(
    `Prowler の検査結果を取り込みました（適用 ${s.applied} / 同じ値 ${s.unchanged} / 食い違い ${s.conflicts} / 適用できない ${s.notApplicable} / 対応するノードが無い資源 ${s.unmatchedResources}）
`,
  );
}

/**
 * `import-findings`：SCAP の結果（XCCDF・ARF・OVAL）を指摘としてプロジェクト JSON に保存する。
 * 指摘を保存した JSON は `-o` に書き出し、報告（既定 md）は標準出力。
 */
function runImportFindings(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const format = parseEnum(values.format, IMPORT_FINDINGS_FORMATS, 'format');
  if (!format) fail(`--format <${IMPORT_FINDINGS_FORMATS.join('|')}> を指定してください。`);
  if (!values.in) fail('--in <file> を指定してください（SCAP の結果の XML）。');
  const report = parseEnum(values.report, IMPORT_PROWLER_REPORTS, 'report') ?? 'md';
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let xml = '';
  try {
    if (statSync(values.in).size > MAX_FILE_BYTES) {
      fail(`ファイルが大きすぎます（上限 ${MAX_FILE_BYTES / 1024 / 1024} MB）: ${values.in}`);
    }
    xml = readFileSync(values.in, 'utf-8');
  } catch (e) {
    fail(`ファイルを読み込めません: ${values.in}（${e instanceof Error ? e.message : String(e)}）`);
  }
  const parsed = parseScap(xml);
  if (!parsed.ok) fail(`${parsed.error}（${values.in}）`);
  if (parsed.format !== format) {
    fail(`--format ${format} と入力の形式（${parsed.format}）が一致しません（${values.in}）`);
  }
  let nodeMap: Record<string, string> = {};
  if (values.map) {
    const m = z.record(z.string(), z.string()).safeParse(readJsonFile(values.map));
    if (!m.success) fail(`--map は {"<ホスト名|FQDN|IP>": "<ノード ID>"} の JSON にしてください（${values.map}）`);
    nodeMap = m.data;
  }

  let out: ReturnType<typeof importFindings>;
  try {
    out = importFindings(readJsonFile(file), parsed, { nodeMap, nodeRef: values.node });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (values.out) writeFileSync(values.out, JSON.stringify(out.project, null, 2), 'utf-8');
  process.stdout.write(
    `${report === 'json' ? JSON.stringify(importFindingsReportToJson(out), null, 2) : importFindingsReportToMarkdown(out)}
`,
  );
  process.stderr.write(
    `SCAP の結果を取り込みました（ホスト ${out.hosts.length} / 保存した指摘 ${out.stored} / 未結合のホスト ${out.hosts.filter((h) => !h.linked).length}）
`,
  );
}

/**
 * `import-pentest`：ペンテストの指摘の台帳（YAML）を指摘としてプロジェクト JSON に保存する。
 * 指摘を保存した JSON は `-o` に書き出し、報告（既定 md）は標準出力。
 */
function runImportPentest(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  if (!values.in) fail('--in <registry.yaml> を指定してください（指摘の台帳 YAML）。');
  const report = parseEnum(values.report, IMPORT_PROWLER_REPORTS, 'report') ?? 'md';

  let text = '';
  try {
    if (statSync(values.in).size > MAX_FILE_BYTES) {
      fail(`ファイルが大きすぎます（上限 ${MAX_FILE_BYTES / 1024 / 1024} MB）: ${values.in}`);
    }
    text = readFileSync(values.in, 'utf-8');
  } catch (e) {
    fail(`ファイルを読み込めません: ${values.in}（${e instanceof Error ? e.message : String(e)}）`);
  }
  const parsed = parseRegistry(text);
  if (!parsed.ok) fail(`${parsed.error}（${values.in}）`);

  let out: ReturnType<typeof importPentest>;
  try {
    out = importPentest(readJsonFile(file), parsed.registry, { scope: values.scope });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (values.out) writeFileSync(values.out, JSON.stringify(out.project, null, 2), 'utf-8');
  process.stdout.write(
    `${report === 'json' ? JSON.stringify(pentestReportToJson(out), null, 2) : pentestReportToMarkdown(out)}
`,
  );
  process.stderr.write(
    `ペンテストの指摘を取り込みました（保存 ${out.stored} / 手動脅威 ${out.manualAdded} / 未結合 ${out.unlinked.length}）
`,
  );
}

/** `import-kev`：KEV カタログを指摘の CVE と照合して kev の印を付け外しする（docs/attack-tree-analysis.md §12）。 */
function runImportKev(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。

${USAGE}`);
  if (!values.kev) fail('--kev <file> を指定してください。');
  const report = parseEnum(values.report, IMPORT_PROWLER_REPORTS, 'report') ?? 'md';

  const parsed = parseKevCatalog(readJsonFile(values.kev));
  if (!parsed.ok) fail(`${parsed.error}（${values.kev}）`);

  let out: ReturnType<typeof importKev>;
  try {
    out = importKev(readJsonFile(file), parsed.catalog);
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (values.out) writeFileSync(values.out, JSON.stringify(out.project, null, 2), 'utf-8');
  process.stdout.write(`${report === 'json' ? JSON.stringify(kevReportToJson(out), null, 2) : kevReportToMarkdown(out)}
`);
  process.stderr.write(`KEV と照合しました（対象 ${out.checked} / 印を付けた ${out.marked} / 外した ${out.cleared}）
`);
}

/** `import-epss`：FIRST の EPSS の CSV を指摘の CVE と照合して epss を付け外しする（docs/architecture.md §8.11）。 */
function runImportEpss(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。

${USAGE}`);
  if (!values.epss) fail('--epss <file> を指定してください。');
  const report = parseEnum(values.report, IMPORT_PROWLER_REPORTS, 'report') ?? 'md';

  let text: string;
  try {
    if (statSync(values.epss).size > MAX_FILE_BYTES) {
      fail(`ファイルが大きすぎます（上限 ${MAX_FILE_BYTES / 1024 / 1024} MB）: ${values.epss}`);
    }
    const buf = readFileSync(values.epss);
    // 展開後の上限も MAX_FILE_BYTES（超えると例外）。
    text = (buf[0] === 0x1f && buf[1] === 0x8b ? gunzipSync(buf, { maxOutputLength: MAX_FILE_BYTES }) : buf).toString('utf-8');
  } catch (e) {
    fail(`ファイルを読み込めません: ${values.epss}（${e instanceof Error ? e.message : String(e)}）`);
  }
  const parsed = parseEpssCsv(text);
  if (!parsed.ok) fail(`${parsed.error}（${values.epss}）`);

  let out: ReturnType<typeof importEpss>;
  try {
    out = importEpss(readJsonFile(file), parsed);
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (values.out) writeFileSync(values.out, JSON.stringify(out.project, null, 2), 'utf-8');
  process.stdout.write(`${report === 'json' ? JSON.stringify(epssReportToJson(out), null, 2) : epssReportToMarkdown(out)}
`);
  process.stderr.write(`EPSS と照合しました（対象 ${out.checked} / 付けた ${out.matched} / 外した ${out.removed} / 読めなかった行 ${out.invalid}）
`);
}

/** `fill-patch-status`：CVE 付きの保存済み指摘があるノードの patchStatus 未入力を Missing で埋める。 */
function runFillPatchStatusCommand(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。

${USAGE}`);
  const report = parseEnum(values.report, IMPORT_PROWLER_REPORTS, 'report') ?? 'md';
  const dryRun = values['dry-run'] === true;

  let out: ReturnType<typeof runFillPatchStatus>;
  try {
    out = runFillPatchStatus(readJsonFile(file));
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (values.out && !dryRun) writeFileSync(values.out, JSON.stringify(out.project, null, 2), 'utf-8');
  const json = { schemaVersion: 1, kind: 'cyberriskscape-fill-patch-status-report', dryRun, filled: out.filled, skipped: out.skipped };
  process.stdout.write(`${report === 'json' ? JSON.stringify(json, null, 2) : fillPatchStatusToMarkdown(out, dryRun)}
`);
  process.stderr.write(`パッチ状況を補完しました（${dryRun ? '対象' : '補完'} ${out.filled.length} 件）
`);
}

/** `findings-priority`：保存済みの指摘を攻撃経路に載せて推奨の優先度を出す（docs/attack-tree-analysis.md §12）。 */
function runFindingsPriority(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。

${USAGE}`);
  const format = parseEnum(values.format, IMPORT_PROWLER_REPORTS, 'format') ?? 'md';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  let epssThreshold: number | undefined;
  if (values['epss-threshold'] !== undefined) {
    epssThreshold = Number(values['epss-threshold']);
    if (values['epss-threshold'].trim() === '' || !Number.isFinite(epssThreshold) || epssThreshold < 0 || epssThreshold > 1) {
      fail(`--epss-threshold は 0 以上 1 以下の数値で指定してください: ${values['epss-threshold']}`);
    }
  }

  let out: ReturnType<typeof findingsPriority>;
  try {
    out = findingsPriority(readJsonFile(file), {
      ...(values.attacker ? { attacker: values.attacker } : {}),
      ...(layer ? { layer } : {}),
      ...(epssThreshold !== undefined ? { epssThreshold } : {}),
    });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  writeOutput(format === 'json' ? JSON.stringify(priorityToJson(out), null, 2) : priorityToMarkdown(out), values.out);
}

/** `context`：IP・ホスト名・purl から図の文脈を引く（読み取り専用）。 */
function runContext(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。

${USAGE}`);
  const given = [values.ip, values.host, values.purl].filter((v) => v !== undefined);
  if (given.length !== 1) fail('--ip / --host / --purl のうち 1 つだけを指定してください。');
  const format = parseEnum(values.format, IMPORT_PROWLER_REPORTS, 'format') ?? 'md';

  let out: ReturnType<typeof contextLookup>;
  try {
    out = contextLookup(
      readJsonFile(file),
      { ...(values.ip ? { ip: values.ip } : {}), ...(values.host ? { host: values.host } : {}), ...(values.purl ? { purl: values.purl } : {}) },
      values.attacker ? { attacker: values.attacker } : {},
    );
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  writeOutput(format === 'json' ? JSON.stringify(out, null, 2) : contextToMarkdown(out), values.out);
}

/** `asm-reconcile`：ASM の観測と図の「外部公開」の入力の食い違いを並べる（読み取り専用）。 */
function runAsmReconcile(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。

${USAGE}`);
  const format = parseEnum(values.format, IMPORT_PROWLER_REPORTS, 'format') ?? 'md';
  let out: ReturnType<typeof asmReconcile>;
  try {
    out = asmReconcile(readJsonFile(file), values.previous ? readJsonFile(values.previous) : undefined);
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  writeOutput(format === 'json' ? JSON.stringify(reconcileToJson(out), null, 2) : reconcileToMarkdown(out), values.out);
}

/** `sbom-report`：保存済みの SBOM の検収レポート（読み取り専用）。 */
function runSbomReport(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。

${USAGE}`);
  const format = parseEnum(values.format, IMPORT_PROWLER_REPORTS, 'format') ?? 'md';
  const maxAgeDays = values['max-age-days'] === undefined ? undefined : Number(values['max-age-days']);
  if (maxAgeDays !== undefined && (!Number.isFinite(maxAgeDays) || maxAgeDays < 0)) fail('--max-age-days は 0 以上の数で指定してください。');
  let out: ReturnType<typeof sbomReport>;
  try {
    out = sbomReport(readJsonFile(file), maxAgeDays === undefined ? {} : { maxAgeDays });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  writeOutput(format === 'json' ? JSON.stringify(sbomReportToJson(out), null, 2) : sbomReportToMarkdown(out), values.out);
}

/** `import-sarif`：汎用の SARIF 2.1.0 の結果を指摘としてプロジェクト JSON に保存する（docs/architecture.md §8.6）。 */
function runImportSarif(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。

${USAGE}`);
  if (!values.sarif) fail('--sarif <file> を指定してください。');
  if (!values.scope) fail('--scope を指定してください。');
  const report = parseEnum(values.report, IMPORT_PROWLER_REPORTS, 'report') ?? 'md';

  const parsed = parseSarif(readJsonFile(values.sarif));
  if (!parsed.ok) fail(`${parsed.error}（${values.sarif}）`);

  let out: ReturnType<typeof importSarif>;
  try {
    out = importSarif(readJsonFile(file), parsed, { scope: values.scope, ...(values.node ? { node: values.node } : {}) });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (values.out) writeFileSync(values.out, JSON.stringify(out.project, null, 2), 'utf-8');
  process.stdout.write(`${report === 'json' ? JSON.stringify(sarifReportToJson(out), null, 2) : sarifReportToMarkdown(out)}
`);
  process.stderr.write(`SARIF の結果を取り込みました（run ${out.runs.length} / 保存した指摘 ${out.stored} / 上限で除外 ${out.truncated}）
`);
}

/** `import-nuclei`：Nuclei の結果（JSONL / JSON）を指摘としてプロジェクト JSON に保存する（docs/architecture.md §8.6）。 */
function runImportNuclei(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。

${USAGE}`);
  if (!values.in) fail('--in <results.jsonl> を指定してください。');
  if (!values.scope) fail('--scope を指定してください。');
  const report = parseEnum(values.report, IMPORT_PROWLER_REPORTS, 'report') ?? 'md';

  let text = '';
  try {
    if (statSync(values.in).size > MAX_FILE_BYTES) {
      fail(`ファイルが大きすぎます（上限 ${MAX_FILE_BYTES / 1024 / 1024} MB）: ${values.in}`);
    }
    text = readFileSync(values.in, 'utf-8');
  } catch (e) {
    fail(`ファイルを読み込めません: ${values.in}（${e instanceof Error ? e.message : String(e)}）`);
  }
  const parsed = parseNuclei(text);
  if (!parsed.ok) fail(`${parsed.error}（${values.in}）`);

  let out: ReturnType<typeof importNuclei>;
  try {
    out = importNuclei(readJsonFile(file), parsed, { scope: values.scope, invalid: parsed.invalid, ...(values.node ? { node: values.node } : {}) });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (values.out) writeFileSync(values.out, JSON.stringify(out.project, null, 2), 'utf-8');
  process.stdout.write(`${report === 'json' ? JSON.stringify(nucleiReportToJson(out), null, 2) : nucleiReportToMarkdown(out)}
`);
  process.stderr.write(`Nuclei の結果を取り込みました（結果 ${out.report.results} / 保存した指摘 ${out.stored} / 上限で除外 ${out.truncated}）
`);
}

/** `import-security-audit`：ソース監査（Cloudflare security-audit スキル）の指摘を保存する（docs/architecture.md §8.9）。 */
function runImportSecurityAudit(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。

${USAGE}`);
  if (!values.in) fail('--in <findings.json> を指定してください。');
  const report = parseEnum(values.report, IMPORT_PROWLER_REPORTS, 'report') ?? 'md';

  const readCapped = (path: string): unknown => {
    try {
      if (statSync(path).size > SECURITY_AUDIT_MAX_BYTES) {
        fail(`ファイルが大きすぎます（上限 ${SECURITY_AUDIT_MAX_BYTES / 1024 / 1024} MB）: ${path}`);
      }
    } catch (e) {
      fail(`ファイルを読み込めません: ${path}（${e instanceof Error ? e.message : String(e)}）`);
    }
    return readJsonFile(path);
  };
  const parsed = parseSecurityAudit(readCapped(values.in));
  if (!parsed.ok) fail(`${parsed.error}（${values.in}）`);
  let ledger: ReturnType<typeof parseCoverageLedger> | undefined;
  if (values.ledger) {
    ledger = parseCoverageLedger(readCapped(values.ledger));
    if (!ledger.ok) fail(`${ledger.error}（${values.ledger}）`);
  }

  let out: ReturnType<typeof importSecurityAudit>;
  try {
    out = importSecurityAudit(readJsonFile(file), parsed.items, {
      ...(values.scope ? { scope: values.scope } : {}),
      ...(values.node ? { node: values.node } : {}),
      ...(ledger?.ok ? { ledger: ledger.units } : {}),
      invalid: parsed.invalid,
    });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (values.out) writeFileSync(values.out, JSON.stringify(out.project, null, 2), 'utf-8');
  process.stdout.write(`${report === 'json' ? JSON.stringify(securityAuditReportToJson(out), null, 2) : securityAuditReportToMarkdown(out)}
`);
  process.stderr.write(`ソース監査の指摘を取り込みました（保存 ${out.stored} / 要確認 ${out.report.unverified} / 反証 ${out.report.rejected}）
`);
}

/** `import-sbom`：CycloneDX・SPDX の部品をプロジェクト JSON に保存する（docs/architecture.md §8.8）。 */
function runImportSbom(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。\n\n${USAGE}`);
  if (!values.sbom) fail('--sbom <file> を指定してください。');
  if (!values.scope) fail('--scope を指定してください。');
  const report = parseEnum(values.report, IMPORT_PROWLER_REPORTS, 'report') ?? 'md';

  const parsed = parseBom(readJsonFile(values.sbom));
  if (!parsed.ok) fail(`${parsed.error}（${values.sbom}）`);

  let out: ReturnType<typeof importBom>;
  try {
    out = importBom(readJsonFile(file), parsed, { scope: values.scope, ...(values.node ? { node: values.node } : {}) });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (values.out) writeFileSync(values.out, JSON.stringify(out.project, null, 2), 'utf-8');
  process.stdout.write(`${report === 'json' ? JSON.stringify(bomReportToJson(out), null, 2) : bomReportToMarkdown(out)}\n`);
  process.stderr.write(`部品を取り込みました（保存 ${out.stored} / 上限で除外 ${out.truncated}、指摘 ${out.findings.stored} / VEX 等で除外 ${out.findings.excluded}）\n`);
}

/** `export-spdx`：部品を SPDX 2.3 JSON で出力する（docs/architecture.md §8.8）。 */
function runExportSpdx(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。\n\n${USAGE}`);
  const raw = readJsonFile(file);
  const loaded = deserializeProject(raw);
  if (!loaded) fail('プロジェクト JSON の形式が不正です。');
  const resolved = resolveProject(raw);
  const parts = listBomComponents(
    loaded.bomComponents ?? [],
    LAYER_KEYS.flatMap((layer) => resolved.layers[layer].nodes.map((node) => ({ node, layer }))),
  );
  const meta = loaded.projectMeta;
  const out = buildSpdx(parts, {
    name: meta?.systemName.trim() || meta?.name.trim() || 'unknown',
    created: new Date().toISOString(),
    documentNamespace: `urn:uuid:${randomUUID()}`,
    toolVersion: APP_VERSION,
  });
  writeOutput(JSON.stringify(out.document, null, 2), values.out);
  process.stderr.write(`SPDX 2.3 を出力しました（パッケージ ${out.packages} / SPDX に載らず除外した暗号資産 ${out.omittedCrypto}）\n`);
}

/**
 * `import-aipentest-assets`：AI ペンテストのツール（ARTEX・CyberStrikeAI）が観測した資産の JSON をプロジェクト JSON に保存する
 * （docs/architecture.md §8.7）。
 */
function runImportAipentestAssets(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。\n\n${USAGE}`);
  const tool = parseEnum(values.format, AIPENTEST_ASSET_TOOL_KEYS, 'format');
  if (!tool) fail('--format を指定してください（artex か cyberstrikeai）。');
  if (!values.scope) fail('--scope を指定してください（例: task-3）。');
  const report = parseEnum(values.report, IMPORT_PROWLER_REPORTS, 'report') ?? 'md';

  const services: PentestServiceRecord[] = [];
  const endpoints: PentestEndpointRecord[] = [];
  let skippedBySource = 0;
  if (tool === 'artex') {
    if (!values.services && !values.endpoints) fail('--services か --endpoints のどちらかを指定してください。');
    if (values.services) {
      const parsed = parseArtexServices(readJsonFile(values.services));
      if (!parsed.ok) fail(`${parsed.error}（${values.services}）`);
      services.push(...parsed.records);
      skippedBySource += parsed.skippedBySource;
    }
    if (values.endpoints) {
      const parsed = parseArtexEndpoints(readJsonFile(values.endpoints));
      if (!parsed.ok) fail(`${parsed.error}（${values.endpoints}）`);
      endpoints.push(...parsed.records);
      skippedBySource += parsed.skippedBySource;
    }
  } else {
    if (!values.assets || values.assets.length === 0) fail('--assets を指定してください（ページごとに繰り返し可）。');
    for (const f of values.assets) {
      const parsed = parseCyberStrikeAiAssets(readJsonFile(f));
      if (!parsed.ok) fail(`${parsed.error}（${f}）`);
      services.push(...parsed.records);
      skippedBySource += parsed.skippedBySource;
    }
  }

  let nodeMap: Record<string, string> = {};
  if (values.map) {
    const m = z.record(z.string(), z.string()).safeParse(readJsonFile(values.map));
    if (!m.success) fail('--map は {"<IP|ドメイン>": "<C番号|ノード ID>"} の JSON にしてください。');
    nodeMap = m.data;
  }

  let out: ReturnType<typeof importAipentestAssets>;
  try {
    out = importAipentestAssets(
      readJsonFile(file),
      { services, endpoints, skippedBySource },
      { tool, scope: values.scope, nodeMap, ...(values.node ? { node: values.node } : {}) },
    );
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (values.out) writeFileSync(values.out, JSON.stringify(out.project, null, 2), 'utf-8');
  process.stdout.write(`${report === 'json' ? JSON.stringify(aipentestAssetsReportToJson(out), null, 2) : aipentestAssetsReportToMarkdown(out)}\n`);
  process.stderr.write(`資産を取り込みました（サービス ${out.services} / エンドポイント ${out.endpoints} / 未対応のホスト ${out.unlinkedHosts.length}）\n`);
}

/**
 * `import-conjur`：CyberArk（Idira）Conjur / Secrets Manager のポリシー YAML から NHI とシークレットの読み取り経路の
 * 構成図を作り、プロジェクト JSON を出力する。annotation の値・シークレットの値は読まない（`conjurToLayer` 参照）。
 */
function runImportConjur(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。\n\n${USAGE}`);
  }
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let text: string;
  try {
    text = readFileSync(file, 'utf-8');
  } catch (e) {
    fail(`ファイルを読み込めません: ${file}（${e instanceof Error ? e.message : String(e)}）`);
  }
  const result = conjurToLayer(text);
  if (!result.ok) fail(result.error);

  writeOutput(JSON.stringify(layerToProject(result.layer), null, 2), values.out);
  const s = result.summary;
  process.stderr.write(
    `Conjur ポリシーを取り込みました（host ${s.hosts} / layer ${s.layers} / variable ${s.variables} / user ${s.users} / group ${s.groups} / permit ${s.permits} / grant ${s.grants}）\n`,
  );
}

/**
 * `import-shodan` / `import-scopesentry` の `--into`：観測サービスを資産として既存プロジェクトに保存する。
 * ノードとの結合は `--map` / `--node` の明示だけ（推測しない）。
 */
function saveAsmAssets(
  values: CliValues,
  exposed: Parameters<typeof importAsmAssets>[1],
  product: { format: 'shodan' | 'scopesentry'; product: string },
): void {
  if (!values.into) return;
  if (!values.scope) fail('--into のときは --scope を指定してください（例: 2026-11）。');
  let nodeMap: Record<string, string> = {};
  if (values.map) {
    const m = z.record(z.string(), z.string()).safeParse(readJsonFile(values.map));
    if (!m.success) fail('--map は {"<IP|ホスト名>": "<C番号|ノード ID>"} の JSON にしてください。');
    nodeMap = m.data;
  }
  let out: ReturnType<typeof importAsmAssets>;
  try {
    out = importAsmAssets(readJsonFile(values.into), exposed, { ...product, scope: values.scope, nodeMap, ...(values.node ? { node: values.node } : {}) });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  writeOutput(JSON.stringify(out.project, null, 2), values.out);
  process.stderr.write(
    `${product.product} のサービスを資産として保存しました（サービス ${out.services} / CVE の識別子 ${out.cves} / 未対応のホスト ${out.unlinkedHosts.length}）
`,
  );
  if (out.badNodeRefs.length > 0) process.stderr.write(`図に無い、または特定できないノードの指定: ${out.badNodeRefs.join(', ')}
`);
}

/**
 * `import-shodan`：Shodan の書き出し（gzip 圧縮の JSON Lines、または JSON）から、インターネットに露出した
 * サービスの構成図を作り、プロジェクト JSON を出力する。バナー本文・HTTP の内容は読まない（`shodanToLayer` 参照）。
 */
function runImportShodan(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let text: string;
  try {
    const buf = readFileSync(file);
    text = (buf[0] === 0x1f && buf[1] === 0x8b ? gunzipSync(buf) : buf).toString('utf-8');
  } catch (e) {
    fail(`ファイルを読み込めません: ${file}（${e instanceof Error ? e.message : String(e)}）`);
  }
  const result = shodanToLayer(text);
  if (!result.ok) fail(result.error);

  if (values.into) {
    saveAsmAssets(values, result.exposed, { format: 'shodan', product: 'Shodan' });
    return;
  }
  writeOutput(JSON.stringify(layerToProject(result.layer), null, 2), values.out);
  const s = result.summary;
  process.stderr.write(
    `Shodan の書き出しを取り込みました（サービス ${s.services} / ホスト ${s.hosts} / CVE ${s.cves} / 読み飛ばし ${s.skipped} / 上限超過 ${s.truncated}）
`,
  );
}

/**
 * `convert-cyberstrikeai`：CyberStrikeAI の脆弱性（JSON ファイル、または `--api` の GET）を import-pentest の台帳 YAML に変換する。
 * 説明・証跡・再現手順は読まない。node と canonicalIds は人が埋める。
 */
async function runConvertCyberstrikeai(values: CliValues, positionals: string[]): Promise<void> {
  const file = positionals[1];
  if (!file && !values.api) fail(`入力ファイルまたは --api を指定してください。

${USAGE}`);
  if (file && values.api) fail('入力ファイルと --api は同時に指定できません。');
  if (!values.scope) fail('--scope <scope> を指定してください（import-pentest の置き換えの範囲）。');
  if (!values.api && (values['project-id'] || values['task-id'])) fail('--project-id / --task-id は --api と一緒に指定してください。');

  let raw: unknown;
  let capped = false;
  if (values.api) {
    let token: string;
    try {
      token = tokenFromEnv(process.env);
    } catch (e) {
      fail(e instanceof Error ? e.message : String(e));
    }
    try {
      const r = await fetchCyberStrikeVulns(values.api, token, { projectId: values['project-id'], taskId: values['task-id'] });
      raw = r.pages;
      capped = r.capped;
    } catch (e) {
      fail(`CyberStrikeAI から取得できません: ${(e instanceof Error ? e.message : String(e)).split(token).join('***')}`);
    }
  } else {
    try {
      if (statSync(file as string).size > MAX_FILE_BYTES) {
        fail(`ファイルが大きすぎます（上限 ${MAX_FILE_BYTES / 1024 / 1024} MB）: ${file}`);
      }
    } catch (e) {
      fail(`ファイルを読み込めません: ${file}（${e instanceof Error ? e.message : String(e)}）`);
    }
    raw = readJsonFile(file as string);
  }
  const parsed = parseCyberStrikeVulns(raw);
  if (!parsed.ok) fail(parsed.error);

  const result = cyberStrikeToRegistry(parsed.vulns, { scope: values.scope });
  result.summary.invalid = parsed.invalid;
  writeOutput(registryToYaml(result).trimEnd(), values.out);
  const s = result.summary;
  process.stderr.write(
    `CyberStrikeAI の脆弱性を台帳に変換しました（変換 ${s.converted} / 除外(ignored) ${s.ignored} / 不正 ${s.invalid ?? 0} / 状態不明 ${s.unknownStatus} / 実証 ${s.byOutcome.verified} / 試行のみ ${s.byOutcome.attempted}）。node と canonicalIds を確認してから import-pentest に渡してください。
${capped ? `取得件数が上限（${MAX_FINDINGS} 件）に達したため打ち切りました。--project-id / --task-id で絞り込んでください。
` : ''}`,
  );
}

/**
 * `convert-strix`：Strix の findings.sarif（ファイル、または strix_runs/<run> ディレクトリ）を import-pentest の台帳 YAML に変換する。
 * 説明・PoC・証跡は読まない。
 */
function runConvertStrix(values: CliValues, positionals: string[]): void {
  let file = positionals[1];
  if (!file) fail(`findings.sarif（または strix_runs/<run> ディレクトリ）を指定してください。

${USAGE}`);
  if (!values.scope) fail('--scope <scope> を指定してください（import-pentest の置き換えの範囲）。');
  try {
    if (statSync(file).isDirectory()) file = join(file, 'findings.sarif');
    if (statSync(file).size > MAX_FILE_BYTES) {
      fail(`ファイルが大きすぎます（上限 ${MAX_FILE_BYTES / 1024 / 1024} MB）: ${file}`);
    }
  } catch (e) {
    fail(`ファイルを読み込めません: ${file}（${e instanceof Error ? e.message : String(e)}）`);
  }
  const result = strixToRegistry(readJsonFile(file), { scope: values.scope, node: values.node });
  if (!result.ok) fail(result.error);
  writeOutput(strixToYaml(result).trimEnd(), values.out);
  const s = result.summary;
  process.stderr.write(
    `Strix の指摘を台帳に変換しました（変換 ${s.converted} / カバレッジ除外 ${s.coverage} / 実証 ${s.byOutcome.verified} / 試行のみ ${s.byOutcome.attempted} / 脅威に対応づけ ${s.mapped} / CWE が辞書に無い ${s.cweUnmapped} / 読めなかった結果 ${s.invalid}）。node と canonicalIds を確認してから import-pentest に渡してください。
`,
  );
}

/** Metasploit の XML を読む（--host-node の検証つき）。convert-metasploit / import-metasploit-assets が共有する。 */
function readMetasploit(file: string, values: CliValues) {
  try {
    if (statSync(file).size > MAX_FILE_BYTES) {
      fail(`ファイルが大きすぎます（上限 ${MAX_FILE_BYTES / 1024 / 1024} MB）: ${file}`);
    }
  } catch (e) {
    fail(`ファイルを読み込めません: ${file}（${e instanceof Error ? e.message : String(e)}）`);
  }
  const xml = readFileSync(file, 'utf-8');
  const parsed = parseMetasploit(xml);
  if (!parsed.ok) fail(`${parsed.error}（${file}）`);
  const nodes = parseHostNodeArgs(values['host-node'] ?? []);
  if (!nodes.ok) fail(nodes.error);
  return { hosts: parsed.hosts, skippedHosts: parsed.skippedHosts, hostNodes: nodes.map };
}

/**
 * `convert-metasploit`：Metasploit の db_export -f xml を import-pentest の台帳 YAML に変換する。
 * 資格情報・loot・notes・詳細・info は読まない（`parseMetasploit` 参照）。
 */
function runConvertMetasploit(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`db_export -f xml のファイルを指定してください。

${USAGE}`);
  if (!values.scope) fail('--scope <scope> を指定してください（import-pentest の置き換えの範囲）。');
  const { hosts, skippedHosts, hostNodes } = readMetasploit(file, values);
  const result = metasploitToRegistry(hosts, { scope: values.scope, hostNodes });
  writeOutput(metasploitToYaml(result).trimEnd(), values.out);
  const s = result.summary;
  process.stderr.write(
    `Metasploit の指摘を台帳に変換しました（ホスト ${s.hosts} / サービス ${s.services} / 脆弱性 ${s.vulns} / 実証 ${s.verified} / 試行のみ ${s.attempted} / CVE あり ${s.withCve} / ノード未指定のホスト ${s.unmappedHosts} / 読めなかったホスト ${skippedHosts}）。node と canonicalIds と重大度を確認してから import-pentest に渡してください。
`,
  );
}

/**
 * `import-metasploit-assets`：Metasploit の db_export -f xml のサービス（open）をプロジェクト JSON に Asset として保存する。
 */
function runImportMetasploitAssets(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイル（プロジェクト JSON）を指定してください。

${USAGE}`);
  if (!values.xml) fail('--xml <export.xml> を指定してください。');
  if (!values.scope) fail('--scope を指定してください。');
  const report = parseEnum(values.report, IMPORT_PROWLER_REPORTS, 'report') ?? 'md';
  const { hosts, hostNodes } = readMetasploit(values.xml, values);
  let out: ReturnType<typeof importMetasploitAssets>;
  try {
    out = importMetasploitAssets(readJsonFile(file), hosts, { scope: values.scope, hostNodes });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (values.out) writeFileSync(values.out, JSON.stringify(out.project, null, 2), 'utf-8');
  process.stdout.write(`${report === 'json' ? JSON.stringify(metasploitAssetsReportToJson(out), null, 2) : metasploitAssetsReportToMarkdown(out)}
`);
  process.stderr.write(`資産を取り込みました（ホスト ${out.hosts} / サービス ${out.services} / 未対応のホスト ${out.unlinkedHosts.length}）
`);
}

/**
 * `import-scopesentry`：ScopeSentry の書き出し JSON、または `--api` で MCP（読み取り専用の list_assets のみ）から取得した
 * レコードから、外部露出サービスの構成図を作り、プロジェクト JSON を出力する。本文・リクエスト等は読まない（`scopesentryToLayer` 参照）。
 */
async function runImportScopesentry(values: CliValues, positionals: string[]): Promise<void> {
  const file = positionals[1];
  if (!file && !values.api) {
    fail(`入力ファイルまたは --api を指定してください。

${USAGE}`);
  }
  if (file && values.api) fail('入力ファイルと --api は同時に指定できません。');
  if (!values.api && (values.project || values.search)) fail('--project / --search は --api と一緒に指定してください。');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let result: ScopesentryImportResult;
  if (values.api) {
    let key: string;
    try {
      key = apiKeyFromEnv(process.env);
    } catch (e) {
      fail(e instanceof Error ? e.message : String(e));
    }
    try {
      const { records, capped } = await fetchViaMcp(values.api, key, { project: values.project, search: values.search });
      if (capped) process.stderr.write(`取得件数が上限（${MAX_RECORDS} 件）に達したため打ち切りました。--project / --search で絞り込んでください。
`);
      result = scopesentryRecordsToLayer(records);
    } catch (e) {
      // キーをエラー文言に含めない（SDK のエラーはヘッダを含まないが、念のため置換する）。
      fail(`ScopeSentry から取得できません: ${(e instanceof Error ? e.message : String(e)).split(key).join('***')}`);
    }
  } else {
    let text: string;
    try {
      text = readFileSync(file as string, 'utf-8');
    } catch (e) {
      fail(`ファイルを読み込めません: ${file}（${e instanceof Error ? e.message : String(e)}）`);
    }
    result = scopesentryToLayer(text);
  }
  if (!result.ok) fail(result.error);

  if (values.into) {
    saveAsmAssets(values, result.exposed, { format: 'scopesentry', product: 'ScopeSentry' });
    return;
  }
  writeOutput(JSON.stringify(layerToProject(result.layer), null, 2), values.out);
  const s = result.summary;
  process.stderr.write(
    `ScopeSentry のデータを取り込みました（サービス ${s.services} / ホスト ${s.hosts} / 脆弱性 ${s.vulns}（紐付かず ${s.unmatchedVulns}） / 乗っ取り報告 ${s.takeovers} / 読み飛ばし ${s.skipped} / 上限超過 ${s.truncated}）
`,
  );
}

/**
 * `export-postman`：検出した脅威のうち HTTP で確かめられるものについて、確認リクエストの
 * Postman Collection（v2.1 JSON）を出力する。ホスト名・トークンは変数のまま出す。
 */
function runExportPostman(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const framework = parseEnum(values.framework, FRAMEWORKS, 'framework');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  const raw = readJsonFile(file);
  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(raw, { layer, framework, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  const generated = toPostmanCollection(target.input);
  const summary = generated.summary;
  let collection = generated.collection;
  if (values.vars) {
    const parsed = VarsFileSchema.safeParse(readJsonFile(values.vars));
    if (!parsed.success) {
      fail(`--vars は文字列だけを値に持つ JSON オブジェクトにしてください（例: {"C7_host": "api.example.com"}）: ${values.vars}`);
    }
    const applied = applyVariableValues(collection, parsed.data);
    collection = applied.collection;
    if (applied.unknownKeys.length > 0) {
      process.stderr.write(`コレクションに無い変数は無視しました: ${applied.unknownKeys.join(', ')}
`);
    }
    if (applied.filledTokenKeys.length > 0) {
      process.stderr.write(
        '注意: 出力ファイルに認証情報（token_ 変数）が含まれます。取り扱いに注意し、DAST ツール側で認証を設定することを推奨します。\n',
      );
    }
  }
  let kept = summary.requests;
  if (values['base-url']) {
    const filtered = filterByBaseUrl(collection, values['base-url']);
    collection = filtered.collection;
    kept = filtered.kept;
    if (kept === 0) {
      process.stderr.write(
        '警告: --base-url 配下のリクエストが 0 件です。--vars でホスト変数（*_host）を埋めたか、URL を確認してください。\n',
      );
    }
  }
  writeOutput(JSON.stringify(collection, null, 2), values.out);
  const keptNote = values['base-url'] ? `・base URL 配下のリクエスト ${kept} / ${summary.requests} 件` : '';
  process.stderr.write(
    `Postman Collection を出力しました（${target.layer}・リクエスト ${summary.requests} 件${keptNote}・対象の脅威 ${summary.coveredThreats} 件・対象外 ${summary.uncoveredThreats} 件）
`,
  );
}

/**
 * `export-sbom-ai`：脅威モデルから SBOM for AI を CycloneDX 1.7 JSON で出力する。
 * 既定は実装済みの対策だけ。`--include-threats` で未抑制の脅威も vulnerabilities に載せる。
 */
function runExportSbomAi(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(readJsonFile(file), { layer, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  const bom = buildSbomForAi(target.input, {
    includeThreats: values['include-threats'] ?? false,
    author: values.author,
    timestamp: new Date().toISOString(),
    serialNumber: `urn:uuid:${randomUUID()}`,
    locale,
    importedComponents: deserializeProject(readJsonFile(file))?.bomComponents,
  });
  writeOutput(JSON.stringify(bom, null, 2), values.out);
  const count = (k: string) => (Array.isArray(bom[k]) ? (bom[k] as unknown[]).length : 0);
  process.stderr.write(
    `SBOM for AI（CycloneDX 1.7）を出力しました（${target.layer}・components ${count('components')} 件・services ${count('services')} 件・vulnerabilities ${count('vulnerabilities')} 件）
`,
  );
}

/**
 * `export-detection-requirements`：脅威モデルから、攻撃経路上のノードごとの「監視すべき振る舞い」「必要なログ」と
 * ログが監視先に届かない区間を Markdown または JSON で出力する。検知できることは示さない。
 */
function runExportDetectionRequirements(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const format = parseEnum(values.format, TEST_PLAN_FORMATS, 'format') ?? 'md';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(readJsonFile(file), { layer, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  const d = buildDetectionRequirements(target.input, new Date(), locale);
  writeOutput(format === 'json' ? detectionRequirementsToJson(d) : detectionRequirementsToMarkdown(d), values.out);
  const reqs = d.nodes.reduce((n, x) => n + x.requirements.length, 0);
  process.stderr.write(
    `検知要件を出力しました（${target.layer}・対象ノード ${d.nodes.length} 件・監視要件 ${reqs} 件・経路 ${d.routes.length} 本${d.pathBased ? '' : '・攻撃経路なし＝全ノード'}）
`,
  );
}

/**
 * `export-investigation-plan`：脅威モデルから、侵害の疑いがあるときの調査計画（対象ノード・調査観点・
 * 調べられない恐れ）を Markdown または JSON で出力する。
 */
function runExportInvestigationPlan(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const format = parseEnum(values.format, TEST_PLAN_FORMATS, 'format') ?? 'md';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const tool = parseEnum(values.tool, INVESTIGATION_TOOLS, 'tool') ?? null;
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(readJsonFile(file), { layer, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  const plan = buildInvestigationPlan(
    { ...target.input, findings: resolveProject(readJsonFile(file)).findings },
    new Date(),
    locale,
    tool,
  );
  writeOutput(format === 'json' ? investigationPlanToJson(plan) : investigationPlanToMarkdown(plan), values.out);
  const viewpoints = plan.nodes.reduce((n, x) => n + x.viewpoints.length, 0);
  process.stderr.write(
    `調査計画を出力しました（${target.layer}・対象ノード ${plan.nodes.length} 件・調査観点 ${viewpoints} 件${plan.pathBased ? '' : '・攻撃経路なし＝全ノード'}）
`,
  );
}

/**
 * `export-contractor-paths`：委託先の接続経路を MFA 切り替えの優先順に Markdown / CSV / JSON で出力する。
 */
function runExportContractorPaths(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const format = parseEnum(values.format, REQUIREMENTS_FORMATS, 'format') ?? 'md';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(readJsonFile(file), { layer, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  const paths = buildContractorPaths(target.input, new Date(), locale);
  writeOutput(
    format === 'json'
      ? contractorPathsToJson(paths)
      : format === 'csv'
        ? contractorPathsToCsv(paths)
        : contractorPathsToMarkdown(paths),
    values.out,
  );
  process.stderr.write(`委託先の接続経路を出力しました（${target.layer}・${paths.rows.length} 件）
`);
}

/**
 * `export-requirements`：脅威モデルから、セキュリティ要件の一覧（たたき台）を Markdown / CSV / JSON で出力する。
 */
function runExportRequirements(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const format = parseEnum(values.format, REQUIREMENTS_FORMATS, 'format') ?? 'md';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(readJsonFile(file), { layer, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  const list = buildRequirements(target.input, new Date(), locale);
  writeOutput(
    format === 'json' ? requirementsToJson(list) : format === 'csv' ? requirementsToCsv(list) : requirementsToMarkdown(list),
    values.out,
  );
  process.stderr.write(
    `セキュリティ要件一覧を出力しました（${target.layer}・要件 ${list.requirements.length} 件・委託先への要件 ${list.contractorRequirements.length} 件）
`,
  );
}

/**
 * `investigation-report`：集めた証拠（トリアージの JSON・Velociraptor の収集結果）を脅威モデルのノードに重ね、
 * ノードごとの状態と図に無いホストを報告する。侵害の有無は判定しない。API は呼ばない。
 */
function runInvestigationReport(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);
  const evidencePaths = values.evidence ?? [];
  if (evidencePaths.length === 0) fail(translate('investigationReport.cli.missingEvidence', locale));
  if (!values.hosts) fail(translate('investigationReport.cli.missingHosts', locale));
  const format = parseEnum(values.format, TEST_PLAN_FORMATS, 'format') ?? 'md';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');

  const hostMap = parseHostMap(readJsonFile(values.hosts));
  if (!hostMap.ok) fail(translate('investigationReport.cli.badHosts', locale, { error: hostMap.error }));

  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(readJsonFile(file), { layer, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  const read = readEvidence(evidencePaths, locale);
  if (read.evidence.length === 0) {
    for (const r of read.rejected) process.stderr.write(`${r.path}: ${r.reason}
`);
    fail(translate('investigationReport.cli.noEvidenceFound', locale));
  }
  const report = buildInvestigationReport(target.input, read.evidence, hostMap.hosts, read.rejected, new Date(), locale);
  writeOutput(format === 'json' ? investigationReportToJson(report) : investigationReportToMarkdown(report), values.out);
  const s = report.summary;
  process.stderr.write(
    `${translate('investigationReport.cli.done', locale, {
      layer: report.layer,
      found: s['traces-found'],
      notNegatable: s['not-negatable'],
      notInvestigated: s['not-investigated'],
      noTraces: s['no-traces'],
      unknown: s.unknownHosts,
    })}
`,
  );
}

/**
 * `export-triage-patterns`：調査観点の `tools.triage` を、オフラインのログトリアージ
 * （`tools/triage/crs_triage.py --patterns`）に渡す JSON として書き出す。モデルは不要。
 */
function runExportTriagePatterns(values: CliValues): void {
  const patterns = buildTriagePatterns(getInvestigationViewpoints('ja'));
  writeOutput(JSON.stringify(patterns, null, 2), values.out);
  process.stderr.write(`トリアージのパターンを出力しました（検索パターン ${patterns.logPatterns.length} 件）
`);
}

/**
 * `export-test-plan`：脅威モデルから、ペネトレーションテスト計画書（入口・攻撃シナリオ・重点テスト項目）を
 * Markdown または JSON で出力する。
 */
function runExportTestPlan(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const format = parseEnum(values.format, TEST_PLAN_FORMATS, 'format') ?? 'md';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const framework = parseEnum(values.framework, FRAMEWORKS, 'framework');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(readJsonFile(file), { layer, framework, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  let retest: ReturnType<typeof computeRetestScope> | undefined;
  if (values['changed-from']) {
    try {
      const base = resolveProject(readJsonFile(values['changed-from']));
      const head = resolveProject(readJsonFile(file));
      const hits = detectTriggers(base.layers, head.layers, resolveTriggers(values, locale));
      retest = computeRetestScope(target.layer, base.layers[target.layer], head.layers[target.layer], hits);
    } catch (e) {
      fail(e instanceof Error ? e.message : String(e));
    }
  }

  const plan = buildTestPlan(target.input, new Date(), locale, retest);
  writeOutput(format === 'json' ? testPlanToJson(plan) : testPlanToMarkdown(plan), values.out);
  const focusThreats = plan.focusGroups.reduce((n, g) => n + g.threats.length, 0);
  process.stderr.write(
    `テスト計画書を出力しました（${target.layer}・入口 ${plan.entryPoints.length} 件・攻撃シナリオ ${plan.scenarios.length} 件・重点テスト項目 ${focusThreats} 件・対象外 ${plan.suppressed.length} 件）
`,
  );
}

/**
 * `export-roe`：脅威モデルから、交戦規定（RoE）／スコープ宣言（許可対象・スコープ外・承認方針）を
 * Markdown または JSON で出力する。エージェント型ペンテストツールの自社運用向け（ベンダー中立）。
 */
function runExportRoe(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const format = parseEnum(values.format, TEST_PLAN_FORMATS, 'format') ?? 'md';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const framework = parseEnum(values.framework, FRAMEWORKS, 'framework');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let results: LayerAnalysisResult[];
  let assets: Asset[] | undefined;
  try {
    const raw = readJsonFile(file);
    results = analyzeProject(raw, { layer, framework, locale });
    // ノードに結びついた資産（取り込み・手入力）をアドレスの手がかりに使う
    assets = resolveProject(raw).assets;
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  const doc = buildRoe({ ...target.input, assets }, new Date(), locale);
  writeOutput(format === 'json' ? roeToJson(doc) : roeToMarkdown(doc), values.out);
  process.stderr.write(
    `交戦規定（RoE）／スコープ宣言を出力しました（${target.layer}・許可対象 ${doc.inScope.length} 件・スコープ外 ${doc.outOfScope.length} 件）
`,
  );
}

/**
 * `export-attack-navigator`：検出脅威の references から ATT&CK Enterprise の technique を集め、
 * MITRE ATT&CK Navigator レイヤー（JSON）として出力する。CTEM / BAS / SOC での取り込み用（ベンダー中立）。
 */
function runExportNavigator(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const framework = parseEnum(values.framework, FRAMEWORKS, 'framework');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(readJsonFile(file), { layer, framework, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  let attackerNodeId: string | undefined;
  if (values.node) {
    const ref = values.node.toLowerCase();
    const attacker = target.input.nodes.find(
      (n) => (n.seq != null ? formatElementalId('node', n.seq) : n.id).toLowerCase() === ref,
    );
    if (!attacker) fail(`ノード ${values.node} が見つかりません（${target.layer}）。`);
    if (!ATTACK_OBJECTIVE_APPLICABLE.has(attacker.type) || !attacker.attackObjectiveId) {
      fail(`ノード ${values.node} は攻撃目標（OBJECTIVE）を持つ攻撃者ではありません。`);
    }
    attackerNodeId = attacker.id;
  }

  const layerDoc = buildNavigatorLayer(target.input, new Date(), locale, { attackerNodeId });
  writeOutput(navigatorLayerToJson(layerDoc), values.out);
  process.stderr.write(
    `ATT&CK Navigator レイヤーを出力しました（${target.layer}・technique ${layerDoc.techniques.length} 件・ATLAS ${layerDoc.atlasTechniques.length} 件・攻撃シナリオ ${layerDoc.scenarioCount} 件${attackerNodeId ? `のうち ${values.node} のみ` : ''}）
`,
  );
}

/**
 * `findings-report`：Veracode の結果ファイル（Pipeline Scan / Findings API v2）の指摘を、
 * CWE の対応表（`data/finding-maps/cwe.yaml`）を介して構成図の検出脅威と突き合わせる。
 * Cisco AI Defense の skill-scanner / mcp-scanner の結果は AITech の対応表（`aitech.yaml`）を介する。API は呼ばない。
 */
function runFindingsReport(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);
  const sources = (
    [
      ['veracode', values.veracode],
      ['skill-scanner', values['skill-scanner']],
      ['mcp-scanner', values['mcp-scanner']],
    ] as const
  ).filter((x): x is readonly [FindingsSource, string] => !!x[1]);
  if (sources.length === 0) fail(translate('findingsReport.cli.sourceRequired', locale));
  if (sources.length > 1) fail(translate('findingsReport.cli.sourceExclusive', locale));
  const [source, sourceFile] = sources[0];
  const format = parseEnum(values.format, FINDINGS_REPORT_FORMATS, 'format') ?? 'md';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const framework = parseEnum(values.framework, FRAMEWORKS, 'framework');
  const failOn = parseEnum(values['fail-on'], SEVERITIES, 'fail-on');

  const rawFindings = readJsonFile(sourceFile);
  const parsed =
    source === 'veracode'
      ? parseVeracodeFindings(rawFindings)
      : source === 'skill-scanner'
        ? parseSkillScannerFindings(rawFindings)
        : parseMcpScannerFindings(rawFindings);
  if (!parsed.ok) fail(`${parsed.error}（${sourceFile}）`);

  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(readJsonFile(file), { layer, framework, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (results.length === 0) fail('ノードのあるレイヤーがありません。');
  if (values.node && countNodeMatches(results, values.node) === 0) {
    fail(
      translate('sbomCrypto.cli.nodeNotFound', locale, {
        node: values.node,
        layer: results.map((r) => r.layer).join('/'),
        ids: [...new Set(results.flatMap((r) => r.input.nodes.map(nodeElementalId)))].join(', ') || '-',
      }),
    );
  }

  const reportInput = {
    findings: parsed.findings,
    threats: collectModelThreats(results, values.node),
    excluded: parsed.excluded,
    map: BUNDLED_FINDING_MAP,
    aitechMap: BUNDLED_AITECH_MAP,
    incompleteItems: 'incompleteItems' in parsed ? parsed.incompleteItems : undefined,
  };
  const reportOpts = { source, node: values.node };
  const report = buildFindingsReport(reportInput);
  const gate: FindingsGateResult | undefined = failOn
    ? { failOn, offenders: evaluateFindingsGate(reportInput, failOn) }
    : undefined;
  writeOutput(
    format === 'json'
      ? JSON.stringify(findingsReportToJson(report, gate, reportOpts), null, 2)
      : findingsReportToMarkdown(report, gate, reportOpts),
    values.out,
  );
  const s = report.summary;
  process.stderr.write(
    `${translate('findingsReport.cli.done', locale, {
      open: s.openFindings,
      confirmed: s.confirmedFindings,
      notInModel: s.notInModelFindings,
      unmapped: s.unmappedFindings,
      sca: s.excludedSca,
      closed: s.excludedClosed,
    })}
`,
  );
  if (gate && gate.offenders.length > 0) {
    process.stderr.write(
      `${
        source === 'veracode'
          ? translate('findingsReport.gate.stderr', locale, { failOn: gate.failOn, count: gate.offenders.length })
          : translate('findingsReport.gate.stderrSource', locale, {
              failOn: gate.failOn,
              count: gate.offenders.length,
              source,
            })
      }\n`,
    );
    process.exitCode = 1;
  }
}

/**
 * `pqc-sbom-report`：CycloneDX の SBOM／CBOM（JSON）から、指定したノードの暗号を確認するレポートを出す。
 * 図は変更しない。API は呼ばない。
 */
function runPqcSbomReport(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);
  if (!values.sbom) fail(translate('sbomCrypto.cli.missingSbom', locale));
  if (!values.node) fail(translate('sbomCrypto.cli.missingNode', locale));
  const format = parseEnum(values.format, SBOM_CRYPTO_FORMATS, 'format') ?? 'md';
  const layerOpt = parseEnum(values.layer, LAYER_KEYS, 'layer');

  let sbomText: string;
  try {
    sbomText = readFileSync(values.sbom, 'utf-8');
  } catch (e) {
    fail(
      translate('sbomCrypto.cli.readFailed', locale, {
        file: values.sbom,
        reason: e instanceof Error ? e.message : String(e),
      }),
    );
  }
  const libraries = getCryptoLibraries(locale);
  const parsed = parseSbomText(sbomText, libraries, locale);
  if (!parsed.ok) fail(`${parsed.error}（${values.sbom}）`);

  let layers: ResolvedProject['layers'];
  try {
    layers = resolveProject(readJsonFile(file)).layers;
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const layer =
    layerOpt ?? (layers.PQC.nodes.length > 0 ? 'PQC' : LAYER_KEYS.find((k) => layers[k].nodes.length > 0));
  if (!layer) fail('ノードのあるレイヤーがありません。');
  const { nodes, edges } = layers[layer];
  const node = nodes.find((n) => nodeElementalId(n).toLowerCase() === values.node?.toLowerCase());
  if (!node) {
    fail(
      translate('sbomCrypto.cli.nodeNotFound', locale, {
        node: values.node,
        layer,
        ids: nodes.map(nodeElementalId).join(', ') || '-',
      }),
    );
  }

  const report = buildSbomCryptoReport({
    parsed,
    node,
    edges: edgesTouchingNode(node, nodes, edges),
    algorithms: BUNDLED_ALGORITHM_TABLE,
    libraries,
    locale,
    now: new Date(),
    sourceName: basename(values.sbom),
  });
  writeOutput(format === 'json' ? sbomCryptoToJson(report) : sbomCryptoToMarkdown(report), values.out);
  process.stderr.write(
    `${translate('sbomCrypto.cli.done', locale, {
      layer,
      node: report.summary.node.id,
      assets: report.summary.cryptoAssetCount,
      libraries: report.summary.libraryCount,
    })}
`,
  );
}

/**
 * `mcp`：stdio の MCP サーバーとして起動する。stdout はプロトコル専用のため、
 * ここから先は stdout に何も書かない（ログ・エラーは stderr）。
 */
async function runMcp(values: CliValues): Promise<void> {
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  const root = values.root ?? process.cwd();
  let isDir: boolean;
  try {
    isDir = statSync(root).isDirectory();
  } catch {
    isDir = false;
  }
  if (!isDir) fail(`--root のディレクトリが存在しません: ${root}`);

  const triggers = resolveTriggers(values, locale);
  const server = createCrsMcpServer({ root, locale, triggers });
  await server.connect(new StdioServerTransport());
  process.stderr.write(`${BRANDING.name} MCP サーバーを起動しました（root: ${root}、locale: ${locale}）\n`);
}

function main(): void {
  let parsed: ReturnType<typeof parseCliArgs>;
  try {
    parsed = parseCliArgs();
  } catch (e) {
    fail(`引数の解析に失敗しました: ${e instanceof Error ? e.message : String(e)}\n\n${USAGE}`);
  }

  const { values, positionals } = parsed;

  if (values.help) {
    process.stdout.write(`${USAGE}\n`);
    process.exit(0);
  }

  const command = positionals[0];
  if (command === 'analyze') {
    runAnalyze(values, positionals);
  } else if (command === 'diff') {
    runDiff(values, positionals);
  } else if (command === 'triggers') {
    runTriggers(values);
  } else if (command === 'checklist') {
    runChecklist(values, positionals);
  } else if (command === 'export-postman') {
    runExportPostman(values, positionals);
  } else if (command === 'export-sbom-ai') {
    runExportSbomAi(values, positionals);
  } else if (command === 'export-test-plan') {
    runExportTestPlan(values, positionals);
  } else if (command === 'export-roe') {
    runExportRoe(values, positionals);
  } else if (command === 'export-attack-navigator') {
    runExportNavigator(values, positionals);
  } else if (command === 'export-investigation-plan') {
    runExportInvestigationPlan(values, positionals);
  } else if (command === 'export-detection-requirements') {
    runExportDetectionRequirements(values, positionals);
  } else if (command === 'export-contractor-paths') {
    runExportContractorPaths(values, positionals);
  } else if (command === 'export-requirements') {
    runExportRequirements(values, positionals);
  } else if (command === 'investigation-report') {
    runInvestigationReport(values, positionals);
  } else if (command === 'export-triage-patterns') {
    runExportTriagePatterns(values);
  } else if (command === 'findings-report') {
    runFindingsReport(values, positionals);
  } else if (command === 'pqc-sbom-report') {
    runPqcSbomReport(values, positionals);
  } else if (command === 'import-repo') {
    runImportRepo(values, positionals);
  } else if (command === 'import-prowler') {
    runImportProwler(values, positionals);
  } else if (command === 'import-findings') {
    runImportFindings(values, positionals);
  } else if (command === 'import-pentest') {
    runImportPentest(values, positionals);
  } else if (command === 'import-kev') {
    runImportKev(values, positionals);
  } else if (command === 'fill-patch-status') {
    runFillPatchStatusCommand(values, positionals);
  } else if (command === 'context') {
    runContext(values, positionals);
  } else if (command === 'import-epss') {
    runImportEpss(values, positionals);
  } else if (command === 'findings-priority') {
    runFindingsPriority(values, positionals);
  } else if (command === 'asm-reconcile') {
    runAsmReconcile(values, positionals);
  } else if (command === 'sbom-report') {
    runSbomReport(values, positionals);
  } else if (command === 'import-sarif') {
    runImportSarif(values, positionals);
  } else if (command === 'import-nuclei') {
    runImportNuclei(values, positionals);
  } else if (command === 'import-security-audit') {
    runImportSecurityAudit(values, positionals);
  } else if (command === 'import-sbom') {
    runImportSbom(values, positionals);
  } else if (command === 'export-spdx') {
    runExportSpdx(values, positionals);
  } else if (command === 'import-aipentest-assets') {
    runImportAipentestAssets(values, positionals);
  } else if (command === 'import-conjur') {
    runImportConjur(values, positionals);
  } else if (command === 'import-shodan') {
    runImportShodan(values, positionals);
  } else if (command === 'convert-cyberstrikeai') {
    runConvertCyberstrikeai(values, positionals).catch((e: unknown) => {
      fail(`CyberStrikeAI の変換に失敗しました: ${e instanceof Error ? e.message : String(e)}`);
    });
  } else if (command === 'convert-strix') {
    runConvertStrix(values, positionals);
  } else if (command === 'convert-metasploit') {
    runConvertMetasploit(values, positionals);
  } else if (command === 'import-metasploit-assets') {
    runImportMetasploitAssets(values, positionals);
  } else if (command === 'import-scopesentry') {
    runImportScopesentry(values, positionals).catch((e: unknown) => {
      fail(`ScopeSentry の取り込みに失敗しました: ${e instanceof Error ? e.message : String(e)}`);
    });
  } else if (command === 'import-kong') {
    runImportKong(values, positionals);
  } else if (command === 'import-kongctl') {
    runImportKongctl(values, positionals);
  } else if (command === 'mcp') {
    runMcp(values).catch((e: unknown) => {
      fail(`MCP サーバーの起動に失敗しました: ${e instanceof Error ? e.message : String(e)}`);
    });
  } else {
    fail(`不明なコマンドです: "${command ?? ''}"\n\n${USAGE}`);
  }
}

main();
