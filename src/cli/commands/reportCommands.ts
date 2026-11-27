/**
 * レポート系のサブコマンド（findings-report / sbom-report / pqc-sbom-report /
 * migration-report / investigation-report）の実装。
 */
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { analyzeProject, resolveProject, type LayerAnalysisResult, type ResolvedProject } from '../analyze';
import {
  collectModelThreats,
  countNodeMatches,
  findingsReportToJson,
  findingsReportToMarkdown,
  type FindingsGateResult,
  type FindingsSource,
} from '../findingsReport';
import { parseVeracodeFindings } from '../../features/findings-report/parseVeracode';
import { parseSkillScannerFindings } from '../../features/findings-report/parseSkillScanner';
import { parseMcpScannerFindings } from '../../features/findings-report/parseMcpScanner';
import { sbomReport, sbomReportToJson, sbomReportToMarkdown } from '../sbomReport';
import { renderMigrationReportMarkdown } from '../../features/tm7-import/migrationReport';
import { buildFindingsReport, evaluateFindingsGate } from '../../features/findings-report/buildFindingsReport';
import { BUNDLED_AITECH_MAP, BUNDLED_FINDING_MAP } from '../../features/findings-report/findingMap';
import { setLocale, translate } from '../../i18n';
import { LAYER_KEYS } from '../../core/model/types';
import { parseSbomText } from '../../features/sbom-crypto/parseCycloneDx';
import {
  buildSbomCryptoReport,
  edgesTouchingNode,
  nodeElementalId,
} from '../../features/sbom-crypto/buildSbomCryptoReport';
import { sbomCryptoToJson, sbomCryptoToMarkdown } from '../../features/sbom-crypto/sbomCryptoOutput';
import { BUNDLED_ALGORITHM_TABLE, getCryptoLibraries } from '../../crypto-behavior/bundled';
import { buildInvestigationReport, parseHostMap } from '../../features/investigation-report/buildInvestigationReport';
import {
  investigationReportToJson,
  investigationReportToMarkdown,
} from '../../features/investigation-report/investigationReportOutput';
import { readEvidence } from '../readEvidence';
import {
  IMPORT_PROWLER_REPORTS,
  TEST_PLAN_FORMATS,
  FRAMEWORKS,
  SEVERITIES,
  LOCALES,
  fail,
  parseEnum,
  readJsonFile,
  writeOutput,
  buildMigrationReportFor,
} from '../cliShared';
import { USAGE } from '../usage';
import type { CliValues } from '../cliArgs';

const FINDINGS_REPORT_FORMATS = ['md', 'json'] as const;

const SBOM_CRYPTO_FORMATS = ['md', 'json'] as const;

/**
 * `migration-report`：TMT（.tm7）から取り込んだ脅威と、CyberRiskScape が検出した脅威の重なりと差を出す。
 * 判定は `analyze` と同じエンジン（framework ALL）。図は変更しない。
 */
export function runMigrationReport(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);
  const format = parseEnum(values.format, FINDINGS_REPORT_FORMATS, 'format') ?? 'md';
  const { report, tmtCount } = buildMigrationReportFor(readJsonFile(file), locale);
  if (tmtCount === 0) {
    process.stderr.write('警告: TMT から取り込んだ脅威がありません（import-tm7 の出力を指定してください）\n');
  }
  writeOutput(
    format === 'json'
      ? JSON.stringify(report, null, 2)
      : renderMigrationReportMarkdown(report, (k, p) => translate(k, locale, p)),
    values.out,
  );
}

/** `sbom-report`：保存済みの SBOM の検収レポート（読み取り専用）。 */
export function runSbomReport(values: CliValues, positionals: string[]): void {
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

/**
 * `investigation-report`：集めた証拠（トリアージの JSON・Velociraptor の収集結果）を脅威モデルのノードに重ね、
 * ノードごとの状態と図に無いホストを報告する。侵害の有無は判定しない。API は呼ばない。
 */
export function runInvestigationReport(values: CliValues, positionals: string[]): void {
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
 * `findings-report`：Veracode の結果ファイル（Pipeline Scan / Findings API v2）の指摘を、
 * CWE の対応表（`data/finding-maps/cwe.yaml`）を介して構成図の検出脅威と突き合わせる。
 * Cisco AI Defense の skill-scanner / mcp-scanner の結果は AITech の対応表（`aitech.yaml`）を介する。API は呼ばない。
 */
export function runFindingsReport(values: CliValues, positionals: string[]): void {
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
export function runPqcSbomReport(values: CliValues, positionals: string[]): void {
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
