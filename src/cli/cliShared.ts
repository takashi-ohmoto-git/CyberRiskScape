/**
 * 複数のサブコマンド群で共有する CLI の補助関数・定数（エラー終了・enum 検証・JSON 読み込み・出力など）。
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { analyzeProject, type LayerAnalysisResult } from './analyze';
import { deserializeProject, resolveManualThreats } from '../features/persistence/serialize';
import { buildMigrationReport } from '../features/tm7-import/migrationReport';
import { type Locale } from '../i18n';
import { type FrameworkView, type Severity } from '../core/model/types';
import { getChangeTriggers } from '../change-triggers/loader/bundledChangeTriggers';
import { loadChangeTriggers } from '../change-triggers/loader/loadChangeTriggers';
import type { ChangeTrigger } from '../change-triggers/schema/trigger';
import type { CliValues } from './cliArgs';

export const IMPORT_PROWLER_REPORTS = ['md', 'json'] as const;

export const TEST_PLAN_FORMATS = ['md', 'json'] as const;

export const FRAMEWORKS: readonly FrameworkView[] = ['STRIDE', 'AI', 'AgenticAI', 'ALL'];

export const SEVERITIES: readonly Severity[] = ['Low', 'Medium', 'High', 'Critical'];

export const LOCALES: readonly Locale[] = ['ja', 'en'];

export function fail(message: string): never {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}

export function parseEnum<T extends string>(
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

export function readJsonFile(file: string): unknown {
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
export function resolveTriggers(values: CliValues, locale: Locale): ChangeTrigger[] {
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

export function writeOutput(output: string, outFile: string | undefined): void {
  if (outFile) {
    writeFileSync(outFile, output, 'utf-8');
  } else {
    process.stdout.write(`${output}\n`);
  }
}

/** 移行レポートの入力（framework ALL の全レイヤーの脅威＋手動脅威）を組み立てて報告を作る。 */
export function buildMigrationReportFor(raw: unknown, locale: Locale) {
  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(raw, { framework: 'ALL', locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const project = deserializeProject(raw);
  if (!project) fail('プロジェクト JSON を読み込めません。');
  const manualThreats = resolveManualThreats(project);
  const report = buildMigrationReport({
    layers: results.map((l) => ({ layer: l.layer, threats: l.threats, nodes: l.input.nodes, edges: l.input.edges })),
    manualThreats,
  });
  return { report, tmtCount: report.tmt.total };
}
