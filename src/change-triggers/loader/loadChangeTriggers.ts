import { parse as parseYaml } from 'yaml';
import { ChangeTriggerLibraryFileSchema, type ChangeTrigger } from '../schema/trigger';

/**
 * 実行トリガー YAML のロード失敗時に投げる例外。
 * ソースファイル名と元エラーを保持し、起動時の診断を容易にする。
 */
export class ChangeTriggerLoadError extends Error {
  readonly source: string;
  override readonly cause?: unknown;

  constructor(message: string, source: string, cause?: unknown) {
    super(message);
    this.name = 'ChangeTriggerLoadError';
    this.source = source;
    this.cause = cause;
  }
}

export interface RawYamlFile {
  /** ファイル名・識別子。エラーメッセージや diagnostics に使う。 */
  source: string;
  /** YAML のテキスト本文。 */
  text: string;
}

export interface LoadResult {
  triggers: ChangeTrigger[];
  sources: string[];
}

/**
 * YAML 文字列 1 本をパース＋スキーマ検証して `ChangeTrigger[]` を返す。
 * 単一ファイル単位の純粋関数で、テスト・Vite ローダー双方から利用できる。
 */
export function parseChangeTriggerFile(yamlText: string, source: string): ChangeTrigger[] {
  let parsed: unknown;
  try {
    parsed = parseYaml(yamlText);
  } catch (e) {
    throw new ChangeTriggerLoadError(
      `YAML parse error in "${source}": ${(e as Error).message}`,
      source,
      e,
    );
  }

  const result = ChangeTriggerLibraryFileSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new ChangeTriggerLoadError(
      `Schema validation failed for "${source}":\n${issues}`,
      source,
      result.error,
    );
  }

  return result.data.triggers;
}

/**
 * 複数の YAML ファイルをまとめてロードする。
 * - ファイル単位のスキーマ違反は最初に検出した時点で throw。
 * - ライブラリ全体での id 重複も throw（`--triggers <file>` で差し替えた場合の参照キーとしての
 *   一貫性を担保するため）。
 */
export function loadChangeTriggers(files: readonly RawYamlFile[]): LoadResult {
  const seen = new Map<string, string>();
  const triggers: ChangeTrigger[] = [];

  for (const file of files) {
    const parsed = parseChangeTriggerFile(file.text, file.source);
    for (const trigger of parsed) {
      const prev = seen.get(trigger.id);
      if (prev !== undefined) {
        throw new ChangeTriggerLoadError(
          `Duplicate trigger id "${trigger.id}" found in "${file.source}" (already defined in "${prev}")`,
          file.source,
        );
      }
      seen.set(trigger.id, file.source);
      triggers.push(trigger);
    }
  }

  return { triggers, sources: files.map((f) => f.source) };
}
