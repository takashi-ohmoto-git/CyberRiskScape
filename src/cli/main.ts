import { USAGE } from './usage';
import { fail } from './cliShared';
import { parseCliArgs } from './cliArgs';
import type { CliValues } from './cliArgs';
import {
  runAnalyze,
  runDiff,
  runIndicators,
  runTriggers,
  runChecklist,
  runFindingsPriority,
  runContext,
  runAsmReconcile,
  runMcp,
} from './commands/analyzeCommands';
import {
  runExportScope,
  runExportSpdx,
  runExportPostman,
  runExportSbomAi,
  runExportDetectionRequirements,
  runExportInvestigationPlan,
  runExportContractorPaths,
  runExportEventLog,
  runExportRequirements,
  runExportTriagePatterns,
  runExportTestPlan,
  runExportRoe,
  runExportNavigator,
} from './commands/exportCommands';
import {
  runImportKong,
  runImportTm7,
  runImportKongctl,
  runImportRepo,
  runImportProwler,
  runImportFindings,
  runImportPentest,
  runImportBusinessContext,
  runConvertCelonis,
  runImportKev,
  runImportEpss,
  runFillPatchStatusCommand,
  runImportSarif,
  runImportNuclei,
  runImportSecurityAudit,
  runImportBloodhound,
  runImportEntraApps,
  runImportOpenapi,
  runImportOcsf,
  runImportSbom,
  runImportAipentestAssets,
  runImportConjur,
  runImportShodan,
  runConvertCyberstrikeai,
  runConvertStrix,
  runConvertMetasploit,
  runImportMetasploitAssets,
  runImportScopesentry,
} from './commands/importCommands';
import {
  runMigrationReport,
  runSbomReport,
  runInvestigationReport,
  runFindingsReport,
  runPqcSbomReport,
} from './commands/reportCommands';

/**
 * CyberRiskScape ヘッドレス CLI。
 * 保存済みプロジェクト JSON を入力に、ブラウザなしで脅威を検出してレポートを出す
 * （`analyze`）か、2 版を比較して実行トリガー・脅威差分・ゲート判定を出す（`diff`）。
 * カスタムルール（IndexedDB 別保存）は含まれないため、同梱ルールのみで評価する。
 */

/** サブコマンドの表（名前 → 実行）。main() はここから引く。 */
const COMMANDS = new Map<string, (values: CliValues, positionals: string[]) => void>([
  ['analyze', (values, positionals) => {
    runAnalyze(values, positionals);
  }],
  ['diff', (values, positionals) => {
    runDiff(values, positionals);
  }],
  ['triggers', (values) => {
    runTriggers(values);
  }],
  ['indicators', (values, positionals) => {
    runIndicators(values, positionals);
  }],
  ['export-scope', (values, positionals) => {
    runExportScope(values, positionals);
  }],
  ['checklist', (values, positionals) => {
    runChecklist(values, positionals);
  }],
  ['export-postman', (values, positionals) => {
    runExportPostman(values, positionals);
  }],
  ['export-sbom-ai', (values, positionals) => {
    runExportSbomAi(values, positionals);
  }],
  ['export-test-plan', (values, positionals) => {
    runExportTestPlan(values, positionals);
  }],
  ['export-roe', (values, positionals) => {
    runExportRoe(values, positionals);
  }],
  ['export-attack-navigator', (values, positionals) => {
    runExportNavigator(values, positionals);
  }],
  ['export-investigation-plan', (values, positionals) => {
    runExportInvestigationPlan(values, positionals);
  }],
  ['export-detection-requirements', (values, positionals) => {
    runExportDetectionRequirements(values, positionals);
  }],
  ['export-contractor-paths', (values, positionals) => {
    runExportContractorPaths(values, positionals);
  }],
  ['export-event-log', (values) => {
    runExportEventLog(values);
  }],
  ['export-requirements', (values, positionals) => {
    runExportRequirements(values, positionals);
  }],
  ['investigation-report', (values, positionals) => {
    runInvestigationReport(values, positionals);
  }],
  ['export-triage-patterns', (values) => {
    runExportTriagePatterns(values);
  }],
  ['findings-report', (values, positionals) => {
    runFindingsReport(values, positionals);
  }],
  ['pqc-sbom-report', (values, positionals) => {
    runPqcSbomReport(values, positionals);
  }],
  ['import-repo', (values, positionals) => {
    runImportRepo(values, positionals);
  }],
  ['import-prowler', (values, positionals) => {
    runImportProwler(values, positionals);
  }],
  ['import-findings', (values, positionals) => {
    runImportFindings(values, positionals);
  }],
  ['import-pentest', (values, positionals) => {
    runImportPentest(values, positionals);
  }],
  ['import-business-context', (values, positionals) => {
    runImportBusinessContext(values, positionals);
  }],
  ['convert-celonis', (values) => {
    runConvertCelonis(values).catch((e: unknown) => {
      fail(`Celonis の変換に失敗しました: ${e instanceof Error ? e.message : String(e)}`);
    });
  }],
  ['import-kev', (values, positionals) => {
    runImportKev(values, positionals);
  }],
  ['fill-patch-status', (values, positionals) => {
    runFillPatchStatusCommand(values, positionals);
  }],
  ['context', (values, positionals) => {
    runContext(values, positionals);
  }],
  ['import-epss', (values, positionals) => {
    runImportEpss(values, positionals);
  }],
  ['findings-priority', (values, positionals) => {
    runFindingsPriority(values, positionals);
  }],
  ['asm-reconcile', (values, positionals) => {
    runAsmReconcile(values, positionals);
  }],
  ['sbom-report', (values, positionals) => {
    runSbomReport(values, positionals);
  }],
  ['import-sarif', (values, positionals) => {
    runImportSarif(values, positionals);
  }],
  ['import-nuclei', (values, positionals) => {
    runImportNuclei(values, positionals);
  }],
  ['import-security-audit', (values, positionals) => {
    runImportSecurityAudit(values, positionals);
  }],
  ['import-sbom', (values, positionals) => {
    runImportSbom(values, positionals);
  }],
  ['export-spdx', (values, positionals) => {
    runExportSpdx(values, positionals);
  }],
  ['import-aipentest-assets', (values, positionals) => {
    runImportAipentestAssets(values, positionals);
  }],
  ['import-conjur', (values, positionals) => {
    runImportConjur(values, positionals);
  }],
  ['import-shodan', (values, positionals) => {
    runImportShodan(values, positionals);
  }],
  ['import-openapi', (values, positionals) => {
    runImportOpenapi(values, positionals);
  }],
  ['import-ocsf', (values, positionals) => {
    runImportOcsf(values, positionals);
  }],
  ['import-entra-apps', (values, positionals) => {
    runImportEntraApps(values, positionals).catch((e: unknown) => {
      fail(`Microsoft Graph の在庫の取り込みに失敗しました: ${e instanceof Error ? e.message : String(e)}`);
    });
  }],
  ['import-bloodhound', (values, positionals) => {
    runImportBloodhound(values, positionals).catch((e: unknown) => {
      fail(`BloodHound CE の取り込みに失敗しました: ${e instanceof Error ? e.message : String(e)}`);
    });
  }],
  ['convert-cyberstrikeai', (values, positionals) => {
    runConvertCyberstrikeai(values, positionals).catch((e: unknown) => {
      fail(`CyberStrikeAI の変換に失敗しました: ${e instanceof Error ? e.message : String(e)}`);
    });
  }],
  ['convert-strix', (values, positionals) => {
    runConvertStrix(values, positionals);
  }],
  ['convert-metasploit', (values, positionals) => {
    runConvertMetasploit(values, positionals);
  }],
  ['import-metasploit-assets', (values, positionals) => {
    runImportMetasploitAssets(values, positionals);
  }],
  ['import-scopesentry', (values, positionals) => {
    runImportScopesentry(values, positionals).catch((e: unknown) => {
      fail(`ScopeSentry の取り込みに失敗しました: ${e instanceof Error ? e.message : String(e)}`);
    });
  }],
  ['import-kong', (values, positionals) => {
    runImportKong(values, positionals);
  }],
  ['import-tm7', (values, positionals) => {
    runImportTm7(values, positionals);
  }],
  ['migration-report', (values, positionals) => {
    runMigrationReport(values, positionals);
  }],
  ['import-kongctl', (values, positionals) => {
    runImportKongctl(values, positionals);
  }],
  ['mcp', (values) => {
    runMcp(values).catch((e: unknown) => {
      fail(`MCP サーバーの起動に失敗しました: ${e instanceof Error ? e.message : String(e)}`);
    });
  }],
]);

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
  const run = command === undefined ? undefined : COMMANDS.get(command);
  if (run === undefined) {
    fail(`不明なコマンドです: "${command ?? ''}"\n\n${USAGE}`);
  }
  run(values, positionals);
}

main();
