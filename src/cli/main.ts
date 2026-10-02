import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { analyzeProject, evaluateGate, type LayerAnalysisResult } from './analyze';
import { toSarif } from './sarif';
import { buildThreatReport, toDCRHThreatModelMarkdown, toJsonObject } from '../features/export/threatReport';
import { effectiveSeverity } from '../core/model/risk';
import { setLocale, type Locale } from '../i18n';
import { LAYER_KEYS, type FrameworkView, type Severity } from '../core/model/types';

/**
 * CyberRiskScape ヘッドレス CLI（[[plan]] §2.49）。
 * 保存済みプロジェクト JSON を入力に、ブラウザなしで脅威を検出してレポートを出す。
 * カスタムルール（IndexedDB 別保存）は含まれないため、同梱ルールのみで評価する。
 */

const FORMATS = ['json', 'sarif', 'md'] as const;

const FRAMEWORKS: readonly FrameworkView[] = ['STRIDE', 'AI', 'AgenticAI', 'ALL'];
const SEVERITIES: readonly Severity[] = ['Low', 'Medium', 'High', 'Critical'];
const LOCALES: readonly Locale[] = ['ja', 'en'];

const USAGE = `使い方:
  analyze <project.json> [options]

オプション:
  --format <json|sarif|md>                     出力形式（既定: json）
  --layer <L0|L1|L2|L3>                         対象レイヤー（既定: ノードがある全レイヤー）
  --framework <STRIDE|AI|AgenticAI|ALL>         対象フレームワーク（既定: ALL）
  --fail-on <Critical|High|Medium|Low>          指定した重大度以上の未抑制脅威があれば exit 1
  --locale <ja|en>                              表示言語（既定: ja）
  --out <file>                                  出力先ファイル（既定: 標準出力）
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
      locale: { type: 'string' },
      out: { type: 'string' },
      help: { type: 'boolean' },
    },
  });
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
  if (command !== 'analyze') {
    fail(`不明なコマンドです: "${command ?? ''}"\n\n${USAGE}`);
  }

  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。\n\n${USAGE}`);
  }

  const format = parseEnum(values.format, FORMATS, 'format') ?? 'json';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const framework = parseEnum(values.framework, FRAMEWORKS, 'framework');
  const failOn = parseEnum(values['fail-on'], SEVERITIES, 'fail-on');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';

  let text: string;
  try {
    text = readFileSync(file, 'utf-8');
  } catch (e) {
    fail(`ファイルを読み込めません: ${file}（${e instanceof Error ? e.message : String(e)}）`);
  }

  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    fail(`JSON の解析に失敗しました: ${e instanceof Error ? e.message : String(e)}`);
  }

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
    output = results
      .map((r) => toDCRHThreatModelMarkdown(r.input, exportDate))
      .join('\n\n');
  } else {
    output = JSON.stringify(
      results.map((r) => toJsonObject(buildThreatReport(r.input))),
      null,
      2,
    );
  }

  if (values.out) {
    writeFileSync(values.out, output, 'utf-8');
  } else {
    process.stdout.write(`${output}\n`);
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
}

main();
