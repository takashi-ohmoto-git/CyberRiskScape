import { parse as parseYaml } from 'yaml';
import { ThreatLibraryFileSchema, type ThreatRule } from '../schema/threatRule';
import { parseMitigationTiers } from './parseMitigationTiers';

/**
 * 脅威ライブラリ YAML のロード失敗時に投げる例外。
 * ソースファイル名と元エラーを保持し、起動時の診断を容易にする。
 */
export class ThreatLibraryLoadError extends Error {
  readonly source: string;
  override readonly cause?: unknown;

  constructor(message: string, source: string, cause?: unknown) {
    super(message);
    this.name = 'ThreatLibraryLoadError';
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
  rules: ThreatRule[];
  sources: string[];
  /** ルール id → 定義元ファイル名の逆引き（検出根拠表示用）。 */
  ruleSources: Record<string, string>;
}

/**
 * YAML 文字列 1 本をパース＋スキーマ検証して `ThreatRule[]` を返す。
 * 単一ファイル単位の純粋関数で、テスト・Vite ローダー双方から利用できる。
 */
export function parseThreatLibraryFile(yamlText: string, source: string): ThreatRule[] {
  let parsed: unknown;
  try {
    parsed = parseYaml(yamlText);
  } catch (e) {
    throw new ThreatLibraryLoadError(
      `YAML parse error in "${source}": ${(e as Error).message}`,
      source,
      e,
    );
  }

  const result = ThreatLibraryFileSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new ThreatLibraryLoadError(
      `Schema validation failed for "${source}":\n${issues}`,
      source,
      result.error,
    );
  }

  // ローダー後処理：`mitigation` 内の [Foundation]/[Enterprise]/[Advanced] markup を
  // `mitigationTiers` に自動 populate（YAML 上で既に指定があれば尊重し上書きしない）。
  return result.data.rules.map((rule) => {
    if (rule.mitigationTiers !== undefined) return rule;
    const tiers = parseMitigationTiers(rule.mitigation, rule.id);
    return tiers ? { ...rule, mitigationTiers: tiers } : rule;
  });
}

/**
 * 複数の YAML ファイルをまとめてロードする。
 * - ファイル単位のスキーマ違反は最初に検出した時点で throw。
 * - ライブラリ全体での id 重複も throw。これは外部化された脅威ルールの参照キー
 *   としての一貫性を担保するための制約（detectThreats の出力 id にも使う）。
 */
export function loadThreatLibrary(files: readonly RawYamlFile[]): LoadResult {
  const seen = new Map<string, string>();
  const rules: ThreatRule[] = [];

  for (const file of files) {
    const parsed = parseThreatLibraryFile(file.text, file.source);
    for (const rule of parsed) {
      const prev = seen.get(rule.id);
      if (prev !== undefined) {
        throw new ThreatLibraryLoadError(
          `Duplicate rule id "${rule.id}" found in "${file.source}" (already defined in "${prev}")`,
          file.source,
        );
      }
      seen.set(rule.id, file.source);
      rules.push(rule);
    }
  }

  return { rules, sources: files.map((f) => f.source), ruleSources: Object.fromEntries(seen) };
}
