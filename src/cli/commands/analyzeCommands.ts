/**
 * 解析・判定系のサブコマンド（analyze / diff / triggers / indicators / checklist / context /
 * findings-priority / asm-reconcile / mcp）の実装。
 */
import { readFileSync, statSync } from 'node:fs';
import {
  analyzeResolvedProject,
  evaluateGate,
  findOrphanedJudgementsInProject,
  resolveProject,
  type LayerAnalysisResult,
  type ResolvedProject,
} from '../analyze';
import type { OrphanedJudgement } from '../../core/threat-engine/orphanedJudgements';
import { toSarif } from '../sarif';
import { evaluateSavedFindingsGate, formatGateFinding } from '../findingsGate';
import {
  diffProjects,
  diffToJson,
  diffToMarkdown,
  evaluateDiffGate,
  type DiffGateResult,
  type ProjectDiff,
} from '../diff';
import { triggersToJson, triggersToMarkdown } from '../triggers';
import { projectIndicators, type ProjectIndicatorsReport } from '../indicators';
import { loadIndicatorWeights, type IndicatorWeights } from '../../features/indicators/computeIndicators';
import { findingsPriority, priorityToJson, priorityToMarkdown } from '../findingsPriority';
import { asmReconcile, reconcileToJson, reconcileToMarkdown } from '../asmReconcile';
import { contextLookup, contextToMarkdown } from '../context';
import { buildThreatReport, toDCRHThreatModelMarkdown, toJsonObject } from '../../features/export/threatReport';
import { effectiveSeverity } from '../../core/model/risk';
import { setLocale, translate } from '../../i18n';
import { LAYER_KEYS, type Finding } from '../../core/model/types';
import type { ChangeTrigger } from '../../change-triggers/schema/trigger';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createCrsMcpServer } from '../../mcp/server';
import { BRANDING } from '../../core/branding';
import { getChecklists } from '../../checklist/bundled';
import { evaluateChecklist } from '../../checklist/evaluate';
import { toChecklistCsv, toChecklistJson, toChecklistMarkdown } from '../../checklist/report';
import { formatLocalDate } from '../../core/model/localDate';
import {
  IMPORT_PROWLER_REPORTS,
  FRAMEWORKS,
  SEVERITIES,
  LOCALES,
  fail,
  parseEnum,
  readJsonFile,
  resolveTriggers,
  writeOutput,
} from '../cliShared';
import { USAGE } from '../usage';
import type { CliValues } from '../cliArgs';

const ANALYZE_FORMATS = ['json', 'sarif', 'md'] as const;

const DIFF_FORMATS = ['md', 'json'] as const;

const TRIGGERS_FORMATS = ['md', 'json'] as const;

const CHECKLIST_FORMATS = ['md', 'json', 'csv'] as const;

const ORPHAN_REASON_TEXT: Record<OrphanedJudgement['reason'], string> = {
  'element-removed': '部品が図に無い',
  'source-removed': '元のルール・手動脅威が見つからない',
  'not-detected': '今の図では脅威として出ていない',
};

export function runAnalyze(values: CliValues, positionals: string[]): void {
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
  let orphaned: OrphanedJudgement[];
  try {
    const resolved = resolveProject(raw);
    results = analyzeResolvedProject(resolved, { layer, framework, locale });
    orphaned = findOrphanedJudgementsInProject(resolved);
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

  if (orphaned.length > 0) {
    process.stderr.write(
      `注意: どの脅威にも結びついていない判断（リスク対応方針・リスク評価・対策実装状況）が ${orphaned.length} 件あります。保存データには残っています（カスタムルールは CLI では評価しないため、その脅威への判断もここに挙がります）。
`,
    );
    for (const o of orphaned) {
      process.stderr.write(`  - ${o.key}: ${ORPHAN_REASON_TEXT[o.reason]}
`);
    }
  }

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

export function runDiff(values: CliValues, positionals: string[]): void {
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
/**
 * `indicators`：脅威モデル単位の指標（設定率・検討率・実装済みの割合）を JSON で出す。
 * 全レイヤー・全フレームワーク・同梱ルールのみ（カスタムルールの脅威は入らない）。
 */
export function runIndicators(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  setLocale('ja');
  let weights: IndicatorWeights | undefined;
  if (values.weights) {
    try {
      weights = loadIndicatorWeights(readFileSync(values.weights, 'utf8'));
    } catch {
      fail(`--weights の形式が不正です（同梱の data/indicators/weights.yaml と同じ形で、重みはすべて正の数にしてください）: ${values.weights}`);
    }
  }
  let report: ProjectIndicatorsReport;
  try {
    report = projectIndicators(readJsonFile(file), weights);
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  writeOutput(JSON.stringify(report, null, 2), values.out);
}

export function runTriggers(values: CliValues): void {
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
export function runChecklist(values: CliValues, positionals: string[]): void {
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

/** `findings-priority`：保存済みの指摘を攻撃経路に載せて推奨の優先度を出す（docs/attack-tree-analysis.md §12）。 */
export function runFindingsPriority(values: CliValues, positionals: string[]): void {
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
export function runContext(values: CliValues, positionals: string[]): void {
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
export function runAsmReconcile(values: CliValues, positionals: string[]): void {
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

/**
 * `mcp`：stdio の MCP サーバーとして起動する。stdout はプロトコル専用のため、
 * ここから先は stdout に何も書かない（ログ・エラーは stderr）。
 */
export async function runMcp(values: CliValues): Promise<void> {
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
