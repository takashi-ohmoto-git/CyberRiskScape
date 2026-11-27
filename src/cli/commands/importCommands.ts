/**
 * 取り込み・変換系のサブコマンド（import-* / convert-* / fill-patch-status）の実装。
 */
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { join } from 'node:path';
import { z } from 'zod';
import { bloodhoundReportToJson, bloodhoundReportToMarkdown, importBloodhound } from '../importBloodhound';
import {
  entraAppsReportToJson,
  entraAppsReportToMarkdown,
  importEntraApps,
  type EntraAppsRaw,
} from '../importEntraApps';
import { fetchGraphInventory, graphCredentialsFromEnv } from '../../features/entra-apps-import/fetchGraph';
import { BUNDLED_GRAPH_PERMISSIONS } from '../../features/entra-apps-import/graphPermissions';
import { BUNDLED_SARIF_CATEGORIES } from '../../features/sarif-import/sarifCategories';
import { extractSecretDetails } from '../../features/sarif-import/secretDetails';
import { importOpenapi, openapiReportToJson, openapiReportToMarkdown } from '../importOpenapi';
import { parseOpenApi } from '../../features/openapi-import/parseOpenApi';
import { importOcsf, ocsfReportToJson, ocsfReportToMarkdown } from '../importOcsf';
import { parseOcsf } from '../../features/ocsf-import/parseOcsf';
import { BUNDLED_BLOODHOUND_QUERIES } from '../../features/bloodhound-import/bloodhoundQueries';
import {
  credentialsFromEnv as bloodhoundCredentialsFromEnv,
  fetchBloodhoundQueries,
} from '../../features/bloodhound-import/fetchBloodhound';
import { parseProwlerOcsf } from '../../features/prowler-import/parseProwlerOcsf';
import { importSarif, sarifReportToJson, sarifReportToMarkdown } from '../importSarif';
import { importNuclei, nucleiReportToJson, nucleiReportToMarkdown } from '../importNuclei';
import { parseNuclei } from '../../features/nuclei-import/parseNuclei';
import { importKev, kevReportToJson, kevReportToMarkdown } from '../importKev';
import { fillPatchStatusToMarkdown, runFillPatchStatus } from '../fillPatchStatus';
import { parseKevCatalog } from '../../features/kev-import/applyKev';
import { importEpss, epssReportToJson, epssReportToMarkdown } from '../importEpss';
import { parseEpssCsv } from '../../features/epss-import/applyEpss';
import { parseSarif } from '../../features/sarif-import/parseSarif';
import { importProwler, prowlerReportToJson, prowlerReportToMarkdown } from '../importProwler';
import {
  findingsReportToJson as importFindingsReportToJson,
  findingsReportToMarkdown as importFindingsReportToMarkdown,
  importFindings,
} from '../importFindings';
import { parseScap } from '../../features/scap-import/parseScap';
import { importPentest, pentestReportToJson, pentestReportToMarkdown } from '../importPentest';
import { parseRegistry } from '../../features/pentest-import/parseRegistry';
import { importSecurityAudit, securityAuditReportToJson, securityAuditReportToMarkdown } from '../importSecurityAudit';
import {
  SECURITY_AUDIT_MAX_BYTES,
  parseCoverageLedger,
  parseSecurityAudit,
} from '../../features/security-audit-import/parseSecurityAudit';
import { parseArtexEndpoints, parseArtexServices } from '../../features/asset-import/artexAssets';
import { parseAiAsmEndpoints } from '../../features/asset-import/aiAsmAssets';
import { parseCyberStrikeAiAssets } from '../../features/asset-import/cyberstrikeaiAssets';
import type { PentestEndpointRecord, PentestServiceRecord } from '../../features/asset-import/pentestAssetRecord';
import { parseBom } from '../../features/bom-import/parseBom';
import { renderMigrationReportMarkdown } from '../../features/tm7-import/migrationReport';
import { bomReportToJson, bomReportToMarkdown, importBom } from '../importBom';
import { importAsmAssets } from '../importAsmAssets';
import {
  AIPENTEST_ASSET_TOOL_KEYS,
  aipentestAssetsReportToJson,
  aipentestAssetsReportToMarkdown,
  importAipentestAssets,
} from '../importAipentestAssets';
import { MAX_FILE_BYTES } from '../readEvidence';
import {
  businessContextReportToJson,
  businessContextReportToText,
  importBusinessContext,
} from '../importBusinessContext';
import { parseBusinessContextTable } from '../../features/business-context/parseBusinessContextTable';
import {
  celonisRowsToTable,
  credentialsFromEnv,
  fetchCelonisRecordRows,
  parseValueMaps,
} from '../../features/business-context/celonis';
import { setLocale, translate } from '../../i18n';
import { MAX_FINDINGS } from '../../core/model/types';
import { kongToLayer } from '../../features/kong-import/kongToLayer';
import { layerToProject } from '../../features/kong-import/toProject';
import { tm7ToProject } from '../../features/tm7-import/tm7ToProject';
import { kongctlToLayer } from '../../features/kongctl-import/kongctlToLayer';
import { collectRepo } from '../../features/repo-import/collectRepo';
import { repoToLayer } from '../../features/repo-import/repoToLayer';
import { buildRepoDashboard } from '../../features/repo-import/buildRepoDashboard';
import { renderRepoDashboardHtml } from '../../features/repo-import/renderRepoDashboardHtml';
import { conjurToLayer } from '../../features/conjur-import/conjurToLayer';
import { shodanToLayer } from '../../features/shodan-import/shodanToLayer';
import {
  scopesentryRecordsToLayer,
  scopesentryToLayer,
  type ScopesentryImportResult,
} from '../../features/scopesentry-import/scopesentryToLayer';
import { apiKeyFromEnv, fetchViaMcp, MAX_RECORDS } from '../../features/scopesentry-import/fetchViaMcp';
import {
  cyberStrikeToRegistry,
  parseCyberStrikeVulns,
  registryToYaml,
} from '../../features/pentest-import/cyberStrikeToRegistry';
import { fetchCyberStrikeVulns, tokenFromEnv } from '../../features/pentest-import/fetchCyberStrike';
import { strixToRegistry, strixToYaml } from '../../features/pentest-import/strixToRegistry';
import { metasploitToRegistry, metasploitToYaml } from '../../features/pentest-import/metasploitToRegistry';
import { parseHostNodeArgs, parseMetasploit } from '../../features/metasploit-import/parseMetasploit';
import {
  importMetasploitAssets,
  metasploitAssetsReportToJson,
  metasploitAssetsReportToMarkdown,
} from '../importMetasploitAssets';
import {
  IMPORT_PROWLER_REPORTS,
  LOCALES,
  fail,
  parseEnum,
  readJsonFile,
  writeOutput,
  buildMigrationReportFor,
} from '../cliShared';
import { USAGE } from '../usage';
import type { CliValues } from '../cliArgs';

const IMPORT_FINDINGS_FORMATS = ['xccdf', 'arf', 'oval'] as const;

/**
 * `import-kong`：Kong の宣言設定（decK の kong.yaml / JSON）から構成図の下書きを作り、
 * プロジェクト JSON を出力する。出力は `analyze` / `diff` の入力やアプリでの読み込みにそのまま使える。
 * 認証ヘッダ・資格情報の値は読まない（`kongToLayer` 参照）。
 */
export function runImportKong(values: CliValues, positionals: string[]): void {
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
 * `import-tm7`：Microsoft Threat Modeling Tool の .tm7 を、構成図・手動脅威・対策の状況を含む
 * プロジェクト JSON（移行用）に変換して出力する。脅威の判定はしない（`analyze` が改めて出す）。
 */
export function runImportTm7(values: CliValues, positionals: string[]): void {
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
  const result = tm7ToProject(text);
  if (!result.ok) fail(result.error);

  writeOutput(JSON.stringify(result.project, null, 2), values.out);
  const s = result.summary;
  process.stderr.write(
    `.tm7 を取り込みました（ノード ${s.nodes} / 線 ${s.edges} / 境界 ${s.boundaries} / 注釈 ${s.annotations} / 脅威 ${s.threats} / 対策の状況 ${s.controlStatuses}）
`,
  );
  if (s.review.length > 0) {
    const reasons = { unmappedType: '型を確認', lineBoundary: '線の形の境界を描き直す', danglingFlow: '線をつなぎ直す' } as const;
    process.stderr.write(`要確認 ${s.review.length} 件:
`);
    for (const r of s.review) process.stderr.write(`  [${r.layer}] ${r.label}: ${reasons[r.reason]}
`);
  }
  if (s.skippedSurfaces.length > 0) {
    process.stderr.write(`警告: 5 枚目以降の図は取り込んでいません: ${s.skippedSurfaces.join(', ')}
`);
  }
  if (values.report) {
    const { report, tmtCount } = buildMigrationReportFor(result.project, locale);
    writeFileSync(values.report, renderMigrationReportMarkdown(report, (k, p) => translate(k, locale, p)), 'utf-8');
    process.stderr.write(`移行レポートを出力しました: ${values.report}（TMT の脅威 ${tmtCount} 件）
`);
  }
}

/**
 * `import-kongctl`：Kong AI Gateway 2.x の kongctl 宣言ファイルから構成図の下書きを作り、
 * プロジェクト JSON を出力する。`!secret` の中身・認証情報は読まない（`kongctlToLayer` 参照）。
 */
export function runImportKongctl(values: CliValues, positionals: string[]): void {
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
export function runImportRepo(values: CliValues, positionals: string[]): void {
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
export function runImportProwler(values: CliValues, positionals: string[]): void {
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
export function runImportFindings(values: CliValues, positionals: string[]): void {
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
export function runImportPentest(values: CliValues, positionals: string[]): void {
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

/** `import-business-context`：業務の文脈の表をノードの businessContext に反映する。プロジェクトは標準出力か --out、報告は標準エラー。 */
export function runImportBusinessContext(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。

${USAGE}`);
  if (!values.in) fail('--in <table.csv|json> を指定してください。');
  const format = parseEnum(values.format, ['text', 'json'] as const, 'format') ?? 'text';

  let text: string;
  try {
    if (statSync(values.in).size > MAX_FILE_BYTES) {
      fail(`ファイルが大きすぎます（上限 ${MAX_FILE_BYTES / 1024 / 1024} MB）: ${values.in}`);
    }
    text = readFileSync(values.in, 'utf-8');
  } catch (e) {
    fail(`ファイルを読み込めません: ${values.in}（${e instanceof Error ? e.message : String(e)}）`);
  }
  const table = parseBusinessContextTable(text, values.in);
  if (!table.ok) fail(`${table.error}（${values.in}）`);

  let out: ReturnType<typeof importBusinessContext>;
  try {
    out = importBusinessContext(readJsonFile(file), table);
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  writeOutput(JSON.stringify(out.project, null, 2), values.out);
  process.stderr.write(`${format === 'json' ? JSON.stringify(businessContextReportToJson(out.summary), null, 2) : businessContextReportToText(out.summary)}
`);
}

/**
 * `convert-celonis`：Celonis の Knowledge Model の Record のデータ（GET のみ）を業務の文脈の表（JSON）に変換する。
 * 資格情報は環境変数だけから受け取る。
 */
export async function runConvertCelonis(values: CliValues): Promise<void> {
  if (!values.api) fail('--api <base-url> を指定してください。');
  if (!values.km) fail('--km <id> を指定してください。');
  if (!values.record) fail('--record <id> を指定してください。');
  if (!values['system-field']) fail('--system-field <id> を指定してください。');
  if (!values.process && !values['process-field']) fail('--process <name> か --process-field <id> のどちらかを指定してください。');
  if (values.process && values['process-field']) fail('--process と --process-field は同時に指定できません。');

  let map: Map<string, string>;
  let creds: ReturnType<typeof credentialsFromEnv>;
  try {
    map = parseValueMaps(values['map-value'] ?? []);
    creds = credentialsFromEnv(process.env);
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const fields = [...new Set([values['system-field'], values['process-field'], values['value-field'], values['cases-field']].filter((f): f is string => !!f))];
  const fetched = await fetchCelonisRecordRows(values.api, creds, { km: values.km, record: values.record, fields });
  const { table, summary } = celonisRowsToTable(fetched.rows, {
    km: values.km,
    record: values.record,
    systemField: values['system-field'],
    map,
    ...(values.process ? { process: values.process } : {}),
    ...(values['process-field'] ? { processField: values['process-field'] } : {}),
    ...(values['value-field'] ? { valueField: values['value-field'] } : {}),
    ...(values['cases-field'] ? { casesField: values['cases-field'] } : {}),
    ...(values.currency ? { currency: values.currency } : {}),
    ...(values.period ? { period: values.period } : {}),
  });
  writeOutput(JSON.stringify(table, null, 2), values.out);
  const unmapped = Object.entries(summary.unmapped);
  process.stderr.write(
    `Celonis から表を作りました（取得 ${summary.rows} 行 / 使用 ${summary.used} / プロセス名なし ${summary.missingProcess} / 数値でなく無視 ${summary.nonNumeric}）。
${unmapped.length > 0 ? `対応のない値で除外: ${unmapped.map(([k, n]) => `${k}（${n} 行）`).join('、')}
` : ''}${fetched.truncated ? `取得できる上限（1000 行）に達したため打ち切りました（総件数 ${fetched.total ?? '不明'}）。Knowledge Model 側で絞り込んでください。
` : ''}`,
  );
}

/** `import-kev`：KEV カタログを指摘の CVE と照合して kev の印を付け外しする（docs/attack-tree-analysis.md §12）。 */
export function runImportKev(values: CliValues, positionals: string[]): void {
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
export function runImportEpss(values: CliValues, positionals: string[]): void {
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
export function runFillPatchStatusCommand(values: CliValues, positionals: string[]): void {
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

/** `import-sarif`：汎用の SARIF 2.1.0 の結果を指摘としてプロジェクト JSON に保存する（docs/architecture.md §8.6）。 */
export function runImportSarif(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。

${USAGE}`);
  if (!values.sarif) fail('--sarif <file> を指定してください。');
  if (!values.scope) fail('--scope を指定してください。');
  const report = parseEnum(values.report, IMPORT_PROWLER_REPORTS, 'report') ?? 'md';

  const rawSarif = readJsonFile(values.sarif);
  const parsed = parseSarif(rawSarif);
  if (!parsed.ok) fail(`${parsed.error}（${values.sarif}）`);
  const category = values.category === undefined ? undefined : BUNDLED_SARIF_CATEGORIES.find((c) => c.id === values.category);
  if (values.category !== undefined && !category) {
    fail(`不正な --category の値です: "${values.category}"（指定可能: ${BUNDLED_SARIF_CATEGORIES.map((c) => c.id).join(' | ')}）`);
  }
  if (values['show-secrets'] && !category?.allowRawReport) {
    fail('--show-secrets は、生の情報を出せる分類（--category secrets）と一緒に指定してください。');
  }

  let out: ReturnType<typeof importSarif>;
  try {
    out = importSarif(readJsonFile(file), parsed, {
      scope: values.scope,
      ...(values.node ? { node: values.node } : {}),
      ...(category ? { category } : {}),
      // 生の情報は報告にだけ出す（プロジェクト JSON には入らない）
      ...(values['show-secrets'] ? { rawDetails: extractSecretDetails(rawSarif) } : {}),
    });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (values.out) writeFileSync(values.out, JSON.stringify(out.project, null, 2), 'utf-8');
  process.stdout.write(`${report === 'json' ? JSON.stringify(sarifReportToJson(out), null, 2) : sarifReportToMarkdown(out)}
`);
  process.stderr.write(`SARIF の結果を取り込みました（run ${out.runs.length} / 保存した指摘 ${out.stored} / 上限で除外 ${out.truncated}）
`);
  if (out.rawDetails) {
    process.stderr.write(`注意：報告に秘密の値を含む生の情報 ${out.rawDetails.length} 件を出しました。共有・保存せず、調べ終えたら消してください（プロジェクト JSON には保存していません）。
`);
  }
}

/** `import-nuclei`：Nuclei の結果（JSONL / JSON）を指摘としてプロジェクト JSON に保存する（docs/architecture.md §8.6）。 */
export function runImportNuclei(values: CliValues, positionals: string[]): void {
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
export function runImportSecurityAudit(values: CliValues, positionals: string[]): void {
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

/** 問い合わせの応答 1 ファイルの上限。 */
const BLOODHOUND_RESPONSE_MAX_BYTES = 50 * 1024 * 1024;

/** `import-bloodhound`：BloodHound CE の問い合わせの結果を指摘として保存する（plan §2.141）。 */
export async function runImportBloodhound(values: CliValues, positionals: string[]): Promise<void> {
  if (values['print-queries']) {
    const qs = BUNDLED_BLOODHOUND_QUERIES.map((q) => ({ id: q.id, title: q.title, cypher: q.cypher }));
    writeOutput(JSON.stringify(qs, null, 2), values.out);
    return;
  }
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。

${USAGE}`);
  if (!values.in === !values.api) fail('--in <dir> か --api <base-url> のどちらか一方を指定してください。');
  const report = parseEnum(values.report, IMPORT_PROWLER_REPORTS, 'report') ?? 'md';

  const responses = new Map<string, unknown>();
  if (values.in) {
    let names: string[];
    try {
      names = readdirSync(values.in);
    } catch (e) {
      fail(`フォルダを読み込めません: ${values.in}（${e instanceof Error ? e.message : String(e)}）`);
    }
    for (const q of BUNDLED_BLOODHOUND_QUERIES) {
      const name = `${q.id}.json`;
      if (!names.includes(name)) continue;
      const path = `${values.in.replace(/[\\/]+$/, '')}/${name}`;
      if (statSync(path).size > BLOODHOUND_RESPONSE_MAX_BYTES) {
        fail(`ファイルが大きすぎます（上限 ${BLOODHOUND_RESPONSE_MAX_BYTES / 1024 / 1024} MB）: ${path}`);
      }
      responses.set(q.id, readJsonFile(path));
    }
    if (responses.size === 0) fail(`${values.in} に問い合わせの応答（<問い合わせ id>.json）がありません。--print-queries で id を確認してください。`);
  } else {
    let creds: ReturnType<typeof bloodhoundCredentialsFromEnv>;
    try {
      creds = bloodhoundCredentialsFromEnv(process.env);
    } catch (e) {
      fail(e instanceof Error ? e.message : String(e));
    }
    let fetched: Awaited<ReturnType<typeof fetchBloodhoundQueries>>;
    try {
      fetched = await fetchBloodhoundQueries(values.api!, creds, BUNDLED_BLOODHOUND_QUERIES);
    } catch (e) {
      fail(`BloodHound CE に問い合わせできません: ${e instanceof Error ? e.message : String(e)}`);
    }
    for (const [id, body] of fetched.responses) responses.set(id, body);
    for (const f of fetched.failed) process.stderr.write(`問い合わせ ${f.queryId} に失敗しました（${f.reason}）。この問い合わせは未評価になります。
`);
    if (responses.size === 0) fail('BloodHound CE から 1 件も応答を得られませんでした。');
  }

  let out: ReturnType<typeof importBloodhound>;
  try {
    out = importBloodhound(readJsonFile(file), responses, {
      ...(values.node ? { node: values.node } : {}),
      ...(values['ca-node'] ? { caNode: values['ca-node'] } : {}),
      ...(values['idp-node'] ? { idpNode: values['idp-node'] } : {}),
      ...(values['cloud-node'] ? { cloudNode: values['cloud-node'] } : {}),
      ...(values['vault-node'] ? { vaultNode: values['vault-node'] } : {}),
      ...(values.scope ? { scope: values.scope } : {}),
    });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (values.out) writeFileSync(values.out, JSON.stringify(out.project, null, 2), 'utf-8');
  process.stdout.write(`${report === 'json' ? JSON.stringify(bloodhoundReportToJson(out), null, 2) : bloodhoundReportToMarkdown(out)}
`);
  process.stderr.write(`BloodHound CE の結果を取り込みました（保存 ${out.stored} 件）
`);
}

/** `import-entra-apps`：Microsoft Graph の外部アプリ・同意の在庫を取り込む（plan §2.144）。 */
export async function runImportEntraApps(values: CliValues, positionals: string[]): Promise<void> {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。

${USAGE}`);
  if (!values.in === !values.graph) fail('--in <dir> か --graph のどちらか一方を指定してください。');
  const report = parseEnum(values.report, IMPORT_PROWLER_REPORTS, 'report') ?? 'md';

  let raw: EntraAppsRaw;
  let tenantId: string;
  if (values.in) {
    if (!values['tenant-id']) fail('--in のときは --tenant-id <自組織のテナント ID> を指定してください。');
    tenantId = values['tenant-id'];
    const dir = values.in.replace(/[\\/]+$/, '');
    const read = (name: string, required: boolean): unknown => {
      const path = `${dir}/${name}`;
      let size: number;
      try {
        size = statSync(path).size;
      } catch {
        if (required) fail(`${path} がありません。`);
        return undefined;
      }
      if (size > BLOODHOUND_RESPONSE_MAX_BYTES) fail(`ファイルが大きすぎます（上限 ${BLOODHOUND_RESPONSE_MAX_BYTES / 1024 / 1024} MB）: ${path}`);
      return readJsonFile(path);
    };
    raw = {
      servicePrincipals: read('servicePrincipals.json', true),
      graphServicePrincipal: read('graphServicePrincipal.json', false),
      graphAppRoleAssignedTo: read('graphAppRoleAssignedTo.json', false),
      oauth2PermissionGrants: read('oauth2PermissionGrants.json', false),
    };
  } else {
    let creds: ReturnType<typeof graphCredentialsFromEnv>;
    try {
      creds = graphCredentialsFromEnv(process.env);
    } catch (e) {
      fail(e instanceof Error ? e.message : String(e));
    }
    tenantId = creds.tenantId;
    try {
      const r = await fetchGraphInventory(creds, BUNDLED_GRAPH_PERMISSIONS.graphAppId);
      raw = r;
      for (const t of r.truncated) process.stderr.write(`${t} はページの上限で打ち切りました（数え漏れがありえます）。
`);
    } catch (e) {
      fail(`Microsoft Graph から読めません: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  let out: ReturnType<typeof importEntraApps>;
  try {
    out = importEntraApps(readJsonFile(file), raw, {
      tenantId,
      ...(values['idp-node'] ? { idpNode: values['idp-node'] } : {}),
      ...(values.scope ? { scope: values.scope } : {}),
    });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (values.out) writeFileSync(values.out, JSON.stringify(out.project, null, 2), 'utf-8');
  process.stdout.write(`${report === 'json' ? JSON.stringify(entraAppsReportToJson(out), null, 2) : entraAppsReportToMarkdown(out)}
`);
  process.stderr.write(`Microsoft Graph の在庫を取り込みました（外部アプリ ${out.externalCount} 件・保存 ${out.stored} 件）
`);
}

const OPENAPI_MAX_BYTES = 16 * 1024 * 1024;

/** `import-openapi`：OpenAPI の定義を API の定義の資産として保存する（plan §2.148）。 */
export function runImportOpenapi(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。

${USAGE}`);
  if (!values.in) fail('--in <openapi.yaml|json> を指定してください。');
  if (!values.scope) fail('--scope を指定してください。');
  const report = parseEnum(values.report, IMPORT_PROWLER_REPORTS, 'report') ?? 'md';
  let text: string;
  try {
    if (statSync(values.in).size > OPENAPI_MAX_BYTES) fail(`ファイルが大きすぎます（上限 16 MB）: ${values.in}`);
    text = readFileSync(values.in, 'utf8');
  } catch (e) {
    fail(`ファイルを読み込めません: ${values.in}（${e instanceof Error ? e.message : String(e)}）`);
  }
  const parsed = parseOpenApi(text);
  if (!parsed.ok) fail(`${parsed.error}（${values.in}）`);
  let out: ReturnType<typeof importOpenapi>;
  try {
    out = importOpenapi(readJsonFile(file), parsed.doc, {
      scope: values.scope,
      ...(values['base-url'] ? { baseUrl: values['base-url'] } : {}),
      ...(values.node ? { node: values.node } : {}),
    });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (values.out) writeFileSync(values.out, JSON.stringify(out.project, null, 2), 'utf-8');
  process.stdout.write(`${report === 'json' ? JSON.stringify(openapiReportToJson(out), null, 2) : openapiReportToMarkdown(out)}
`);
  process.stderr.write(`OpenAPI の定義を取り込みました（エンドポイント ${out.endpoints} 件・認証の指定が無い操作 ${out.withoutAuth.length} 件）
`);
}

/** `import-ocsf`：OCSF の検査結果を指摘とクラウドのリソースの資産として保存する（plan §2.149）。 */
export function runImportOcsf(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。

${USAGE}`);
  if (!values.in) fail('--in <findings.ocsf.json> を指定してください。');
  if (!values.scope) fail('--scope を指定してください。');
  const report = parseEnum(values.report, IMPORT_PROWLER_REPORTS, 'report') ?? 'md';
  const parsed = parseOcsf(readJsonFile(values.in));
  if (!parsed.ok) fail(`${parsed.error}（${values.in}）`);
  let nodeMap: Record<string, string> | undefined;
  if (values.map) {
    const m = z.record(z.string(), z.string()).safeParse(readJsonFile(values.map));
    if (!m.success) fail(`--map は {"<リソースの ID または名前>": "<ノード ID>"} の JSON にしてください（${values.map}）`);
    nodeMap = m.data;
  }
  let out: ReturnType<typeof importOcsf>;
  try {
    out = importOcsf(readJsonFile(file), parsed, { scope: values.scope, ...(nodeMap ? { nodeMap } : {}) });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (values.out) writeFileSync(values.out, JSON.stringify(out.project, null, 2), 'utf-8');
  process.stdout.write(`${report === 'json' ? JSON.stringify(ocsfReportToJson(out), null, 2) : ocsfReportToMarkdown(out)}
`);
  process.stderr.write(
    `OCSF の検査結果を取り込みました（指摘 ${out.products.reduce((n, p) => n + p.findings, 0)} 件・クラウドのリソース ${out.resources.total} 件）
`,
  );
}

/** `import-sbom`：CycloneDX・SPDX の部品をプロジェクト JSON に保存する（docs/architecture.md §8.8）。 */
export function runImportSbom(values: CliValues, positionals: string[]): void {
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

/**
 * `import-aipentest-assets`：AI ペンテストのツール（ARTEX・CyberStrikeAI・AI-ASM）が観測した資産の JSON をプロジェクト JSON に保存する
 * （docs/architecture.md §8.7）。
 */
export function runImportAipentestAssets(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。\n\n${USAGE}`);
  const tool = parseEnum(values.format, AIPENTEST_ASSET_TOOL_KEYS, 'format');
  if (!tool) fail('--format を指定してください（artex・cyberstrikeai・ai-asm のどれか）。');
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
  } else if (tool === 'ai-asm') {
    if (!values.endpoints) fail('--endpoints を指定してください（AI-ASM の endpoints.json）。');
    const parsed = parseAiAsmEndpoints(readJsonFile(values.endpoints));
    if (!parsed.ok) fail(`${parsed.error}（${values.endpoints}）`);
    endpoints.push(...parsed.records);
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
export function runImportConjur(values: CliValues, positionals: string[]): void {
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

/** import-shodan / import-scopesentry 共通の `--name` / `--report` の検証。 */
function parseAsmCommonOptions(values: CliValues): { name?: string; json: boolean } {
  const json = parseEnum(values.report, ['json'] as const, 'report') === 'json';
  if (json && !values.out) fail('--report json のときは --out を指定してください（標準出力にはプロジェクト JSON が出るため）。');
  if (values.name === undefined) return { json };
  if (values.into) fail('--name は --into と一緒に使えません（既存のプロジェクト名は変えません）。');
  const name = values.name.trim();
  // eslint-disable-next-line no-control-regex
  if (!name || name.length > 200 || /[\u0000-\u001f\u007f]/.test(name)) fail('--name は 1〜200 文字で、制御文字を含めないでください。');
  return { name, json };
}

/**
 * `import-shodan` / `import-scopesentry` の `--into`：観測サービスを資産として既存プロジェクトに保存する。
 * ノードとの結合は `--map` / `--node` の明示だけ（推測しない）。
 */
function saveAsmAssets(
  values: CliValues,
  exposed: Parameters<typeof importAsmAssets>[1],
  product: { format: 'shodan' | 'scopesentry'; product: string },
  json = false,
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
  if (json) {
    const { services, cves, unlinkedHosts, badNodeRefs } = out;
    process.stdout.write(`${JSON.stringify({ schemaVersion: 1, kind: 'cyberriskscape-asm-import-report', product: product.product, mode: 'into', services, cves, unlinkedHosts, badNodeRefs }, null, 2)}
`);
  }
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
export function runImportShodan(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const { name, json } = parseAsmCommonOptions(values);
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
    saveAsmAssets(values, result.exposed, { format: 'shodan', product: 'Shodan' }, json);
    return;
  }
  writeOutput(JSON.stringify(layerToProject(result.layer, name), null, 2), values.out);
  const s = result.summary;
  if (json) process.stdout.write(`${JSON.stringify({ schemaVersion: 1, kind: 'cyberriskscape-asm-import-report', product: 'Shodan', mode: 'diagram', ...s }, null, 2)}
`);
  process.stderr.write(
    `Shodan の書き出しを取り込みました（サービス ${s.services} / ホスト ${s.hosts} / CVE ${s.cves} / 読み飛ばし ${s.skipped} / 上限超過 ${s.truncated}）
`,
  );
}

/**
 * `convert-cyberstrikeai`：CyberStrikeAI の脆弱性（JSON ファイル、または `--api` の GET）を import-pentest の台帳 YAML に変換する。
 * 説明・証跡・再現手順は読まない。node と canonicalIds は人が埋める。
 */
export async function runConvertCyberstrikeai(values: CliValues, positionals: string[]): Promise<void> {
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
export function runConvertStrix(values: CliValues, positionals: string[]): void {
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
export function runConvertMetasploit(values: CliValues, positionals: string[]): void {
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
export function runImportMetasploitAssets(values: CliValues, positionals: string[]): void {
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
export async function runImportScopesentry(values: CliValues, positionals: string[]): Promise<void> {
  const file = positionals[1];
  if (!file && !values.api) {
    fail(`入力ファイルまたは --api を指定してください。

${USAGE}`);
  }
  if (file && values.api) fail('入力ファイルと --api は同時に指定できません。');
  if (!values.api && (values.project || values.search)) fail('--project / --search は --api と一緒に指定してください。');
  if (values.product !== undefined && !values.into) fail('--product は --into と一緒に指定してください。');
  // 画面の「製品」欄と資産の ID に入る。保存形式の上限（100 文字）に合わせ、制御文字は受け付けない
  const product = values.product?.trim() ?? 'ScopeSentry';
  // eslint-disable-next-line no-control-regex
  if (!product || product.length > 100 || /[\u0000-\u001f\u007f]/.test(product)) fail('--product は 1〜100 文字で、制御文字を含めないでください。');
  const { name, json } = parseAsmCommonOptions(values);
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
    saveAsmAssets(values, result.exposed, { format: 'scopesentry', product }, json);
    return;
  }
  writeOutput(JSON.stringify(layerToProject(result.layer, name), null, 2), values.out);
  const s = result.summary;
  if (json) process.stdout.write(`${JSON.stringify({ schemaVersion: 1, kind: 'cyberriskscape-asm-import-report', product: 'ScopeSentry', mode: 'diagram', ...s }, null, 2)}
`);
  process.stderr.write(
    `ScopeSentry のデータを取り込みました（サービス ${s.services} / ホスト ${s.hosts} / 脆弱性 ${s.vulns}（紐付かず ${s.unmatchedVulns}） / 乗っ取り報告 ${s.takeovers} / 読み飛ばし ${s.skipped} / 上限超過 ${s.truncated}）
`,
  );
}
