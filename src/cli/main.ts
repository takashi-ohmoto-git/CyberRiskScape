import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { analyzeProject, evaluateGate, type LayerAnalysisResult } from './analyze';
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
import { buildThreatReport, toDCRHThreatModelMarkdown, toJsonObject } from '../features/export/threatReport';
import { effectiveSeverity } from '../core/model/risk';
import { setLocale, type Locale } from '../i18n';
import { LAYER_KEYS, type FrameworkView, type Severity } from '../core/model/types';
import { getChangeTriggers } from '../change-triggers/loader/bundledChangeTriggers';
import { loadChangeTriggers } from '../change-triggers/loader/loadChangeTriggers';
import type { ChangeTrigger } from '../change-triggers/schema/trigger';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createCrsMcpServer } from '../mcp/server';
import { BRANDING } from '../core/branding';
import { kongToLayer } from '../features/kong-import/kongToLayer';
import { layerToProject } from '../features/kong-import/toProject';
import { conjurToLayer } from '../features/conjur-import/conjurToLayer';
import { toPostmanCollection } from '../features/postman-export/toPostmanCollection';

/**
 * CyberRiskScape ヘッドレス CLI。
 * 保存済みプロジェクト JSON を入力に、ブラウザなしで脅威を検出してレポートを出す
 * （`analyze`）か、2 版を比較して実行トリガー・脅威差分・ゲート判定を出す（`diff`）。
 * カスタムルール（IndexedDB 別保存）は含まれないため、同梱ルールのみで評価する。
 */

const ANALYZE_FORMATS = ['json', 'sarif', 'md'] as const;
const DIFF_FORMATS = ['md', 'json'] as const;
const TRIGGERS_FORMATS = ['md', 'json'] as const;

const FRAMEWORKS: readonly FrameworkView[] = ['STRIDE', 'AI', 'AgenticAI', 'ALL'];
const SEVERITIES: readonly Severity[] = ['Low', 'Medium', 'High', 'Critical'];
const LOCALES: readonly Locale[] = ['ja', 'en'];

const USAGE = `使い方:
  analyze <project.json> [options]
  diff <base.json> <head.json> [options]
  triggers [options]
  import-kong <kong.yaml> [options]
  import-conjur <policy.yml> [options]
  export-postman <project.json> [options]
  mcp [options]

analyze のオプション:
  --format <json|sarif|md>                     出力形式（既定: json）
  --layer <L0|L1|L2|L3>                         対象レイヤー（既定: ノードがある全レイヤー）
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

import-kong のオプション（Kong の宣言設定から構成図の下書きを L1 に作り、プロジェクト JSON を出力）:
  --locale <ja|en>                              ノード名の言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

import-conjur のオプション（Conjur / Secrets Manager のポリシーから NHI と読み取り経路の図を L1 に作り、プロジェクト JSON を出力）:
  --locale <ja|en>                              ノード名の言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

export-postman のオプション（検出脅威を確かめる確認リクエストを Postman Collection v2.1 で出力）:
  --layer <L0|L1|L2|L3>                         対象レイヤー（既定: ノードがある最初のレイヤー）
  --framework <STRIDE|AI|AgenticAI|ALL>         対象フレームワーク（既定: ALL）
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）

mcp のオプション（stdio の MCP サーバーとして起動。stdout は MCP プロトコル専用）:
  --root <dir>                                  読み書きを許可するディレクトリ（既定: カレントディレクトリ）
  --triggers <file>                             実行トリガー定義 YAML（既定: 同梱の T1〜T8。指定時は翻訳オーバーレイ非適用）
  --locale <ja|en>                              表示言語（既定: ja。起動中は固定）

共通:
  --help                                        このヘルプを表示

終了コード: 0=成功 / 1=--fail-on によるゲート不合格 / 2=入力・引数エラー`;

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
      triggers: { type: 'string' },
      locale: { type: 'string' },
      out: { type: 'string' },
      root: { type: 'string' },
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
    const exportDate = new Date().toISOString().slice(0, 10);
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
      `--fail-on ${failOn}: 新規かつ未抑制の脅威が ${gate.offenders.length} 件しきい値以上です。\n`,
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

  const { collection, summary } = toPostmanCollection(target.input);
  writeOutput(JSON.stringify(collection, null, 2), values.out);
  process.stderr.write(
    `Postman Collection を出力しました（${target.layer}・リクエスト ${summary.requests} 件・対象の脅威 ${summary.coveredThreats} 件・対象外 ${summary.uncoveredThreats} 件）
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
  } else if (command === 'export-postman') {
    runExportPostman(values, positionals);
  } else if (command === 'import-conjur') {
    runImportConjur(values, positionals);
  } else if (command === 'import-kong') {
    runImportKong(values, positionals);
  } else if (command === 'mcp') {
    runMcp(values).catch((e: unknown) => {
      fail(`MCP サーバーの起動に失敗しました: ${e instanceof Error ? e.message : String(e)}`);
    });
  } else {
    fail(`不明なコマンドです: "${command ?? ''}"\n\n${USAGE}`);
  }
}

main();
