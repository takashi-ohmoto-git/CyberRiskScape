import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { basename } from 'node:path';
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
import { importProwler, prowlerReportToJson, prowlerReportToMarkdown } from './importProwler';
import { buildFindingsReport, evaluateFindingsGate } from '../features/findings-report/buildFindingsReport';
import { BUNDLED_AITECH_MAP, BUNDLED_FINDING_MAP } from '../features/findings-report/findingMap';
import { buildThreatReport, toDCRHThreatModelMarkdown, toJsonObject } from '../features/export/threatReport';
import { effectiveSeverity } from '../core/model/risk';
import { setLocale, translate, type Locale } from '../i18n';
import { ATTACK_OBJECTIVE_APPLICABLE, LAYER_KEYS, type FrameworkView, type Severity } from '../core/model/types';
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
import { conjurToLayer } from '../features/conjur-import/conjurToLayer';
import { shodanToLayer } from '../features/shodan-import/shodanToLayer';
import { scopesentryRecordsToLayer, scopesentryToLayer, type ScopesentryImportResult } from '../features/scopesentry-import/scopesentryToLayer';
import { apiKeyFromEnv, fetchViaMcp, MAX_RECORDS } from '../features/scopesentry-import/fetchViaMcp';
import { toPostmanCollection } from '../features/postman-export/toPostmanCollection';
import { buildSbomForAi } from '../features/sbom-ai/buildSbomForAi';
import { VarsFileSchema, applyVariableValues, filterByBaseUrl } from '../features/postman-export/dastOptions';
import { buildTestPlan } from '../features/test-plan/buildTestPlan';
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
const TEST_PLAN_FORMATS = ['md', 'json'] as const;
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
  import-conjur <policy.yml> [options]
  import-shodan <export.json[.gz]> [options]
  import-scopesentry <export.json> [options]
  import-scopesentry --api <base-url> [options]
  export-postman <project.json> [options]
  export-sbom-ai <project.json> [options]
  export-test-plan <project.json> [options]
  export-roe <project.json> [options]
  export-attack-navigator <project.json> [options]
  export-investigation-plan <project.json> [options]
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

import-prowler のオプション（Prowler の OCSF 出力（*.ocsf.json）の検査結果を、図のノードの運用状況・攻撃面属性の未入力の項目に載せる。入力済みの値は上書きせず、食い違いを報告に出す。ファイル入力のみ）:
  --ocsf <file>                                 Prowler の OCSF（必須。json-ocsf の出力）
  --map <file>                                  資源とノードの対応表（任意。JSON {"<資源の uid または名前>": "<ノード ID または C 番号>"}）。
                                                資源のタグ crs-node=<ノード ID> が優先され、タグの無い資源をこの表で補う
  --report <md|json>                            報告の形式（既定: md。標準出力）
  -o, --out <file>                              未入力の項目を埋めたプロジェクト JSON の出力先（指定しなければ書き出さない）

import-conjur のオプション（Conjur / Secrets Manager のポリシーから NHI と読み取り経路の図を L1 に作り、プロジェクト JSON を出力）:
  --locale <ja|en>                              ノード名の言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

import-shodan のオプション（Shodan の書き出し（.json.gz または JSON）から外部露出サービスの図を L1 に作り、プロジェクト JSON を出力）:
  --locale <ja|en>                              ノード名の言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

import-scopesentry のオプション（ScopeSentry の書き出し JSON、または MCP 経由の取得から外部露出サービスの図を L1 に作り、プロジェクト JSON を出力）:
  --api <base-url>                              ファイルの代わりに <base-url>/mcp から取得する（読み取り専用の list_assets のみ呼ぶ）。
                                                API キーは環境変数 SCOPESENTRY_API_KEY で渡す（保存・出力しない）。許可された範囲にだけ使うこと
  --project <ObjectID>                          --api のとき、このプロジェクトの資産だけ取得する
  --search <expr>                               --api のとき、ScopeSentry の検索式で絞り込む
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

終了コード: 0=成功 / 1=--fail-on / --fail-on-action によるゲート不合格 / 2=入力・引数エラー`;

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
      id: { type: 'string' },
      'as-of': { type: 'string' },
      triggers: { type: 'string' },
      locale: { type: 'string' },
      tool: { type: 'string' },
      out: { type: 'string', short: 'o' },
      ocsf: { type: 'string' },
      map: { type: 'string' },
      report: { type: 'string' },
      root: { type: 'string' },
      vars: { type: 'string' },
      veracode: { type: 'string' },
      'skill-scanner': { type: 'string' },
      'mcp-scanner': { type: 'string' },
      evidence: { type: 'string', multiple: true },
      hosts: { type: 'string' },
      sbom: { type: 'string' },
      node: { type: 'string' },
      'base-url': { type: 'string' },
      author: { type: 'string' },
      'include-threats': { type: 'boolean' },
      api: { type: 'string' },
      project: { type: 'string' },
      search: { type: 'string' },
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
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';

  const raw = readJsonFile(file);

  // 脅威本文のテンプレート展開（`renderTemplate`）とレポート生成はどちらも `getLocale()`
  // （モジュール内グローバル）を読むため、検出より前に揃える（App.tsx の JA/EN 切替と同じ経路）。
  setLocale(locale);

  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(raw, { layer, framework, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }

  const artifactUri = file.replace(/\\/g, '/');
  let output: string;
  if (format === 'sarif') {
    output = JSON.stringify(toSarif(results, { artifactUri }), null, 2);
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
    out = importProwler(readJsonFile(file), parsed, nodeMap);
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

  writeOutput(JSON.stringify(layerToProject(result.layer), null, 2), values.out);
  const s = result.summary;
  process.stderr.write(
    `Shodan の書き出しを取り込みました（サービス ${s.services} / ホスト ${s.hosts} / CVE ${s.cves} / 読み飛ばし ${s.skipped} / 上限超過 ${s.truncated}）
`,
  );
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
  });
  writeOutput(JSON.stringify(bom, null, 2), values.out);
  const count = (k: string) => (Array.isArray(bom[k]) ? (bom[k] as unknown[]).length : 0);
  process.stderr.write(
    `SBOM for AI（CycloneDX 1.7）を出力しました（${target.layer}・components ${count('components')} 件・services ${count('services')} 件・vulnerabilities ${count('vulnerabilities')} 件）
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

  const plan = buildInvestigationPlan(target.input, new Date(), locale, tool);
  writeOutput(format === 'json' ? investigationPlanToJson(plan) : investigationPlanToMarkdown(plan), values.out);
  const viewpoints = plan.nodes.reduce((n, x) => n + x.viewpoints.length, 0);
  process.stderr.write(
    `調査計画を出力しました（${target.layer}・対象ノード ${plan.nodes.length} 件・調査観点 ${viewpoints} 件${plan.pathBased ? '' : '・攻撃経路なし＝全ノード'}）
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

  const plan = buildTestPlan(target.input, new Date(), locale);
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
  try {
    results = analyzeProject(readJsonFile(file), { layer, framework, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  const doc = buildRoe(target.input, new Date(), locale);
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
  } else if (command === 'import-conjur') {
    runImportConjur(values, positionals);
  } else if (command === 'import-shodan') {
    runImportShodan(values, positionals);
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
