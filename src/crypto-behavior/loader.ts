import { parse as parseYaml } from 'yaml';
import type { ZodType } from 'zod';
import {
  AlgorithmTableSchema,
  CryptoLibraryFileSchema,
  CryptoLibraryOverlayFileSchema,
  TerminationFileSchema,
  TerminationOverlayFileSchema,
  type AlgorithmClass,
  type AlgorithmTable,
  type CryptoLibrary,
  type CryptoLibraryOverlay,
  type TerminationBehavior,
  type TerminationOverlay,
} from './schema';

/** 暗号判定データ YAML のロード失敗時に投げる例外。 */
export class CryptoBehaviorLoadError extends Error {
  readonly source: string;

  constructor(message: string, source: string) {
    super(message);
    this.name = 'CryptoBehaviorLoadError';
    this.source = source;
  }
}

function parseWith<T>(schema: ZodType<T>, yamlText: string, source: string): T {
  let parsed: unknown;
  try {
    parsed = parseYaml(yamlText);
  } catch (e) {
    throw new CryptoBehaviorLoadError(
      `YAML parse error in "${source}": ${(e as Error).message}`,
      source,
    );
  }
  const result = schema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new CryptoBehaviorLoadError(
      `Schema validation failed for "${source}":\n${issues}`,
      source,
    );
  }
  return result.data;
}

/** 終端判定の既定値 YAML をパース＋検証する。componentType の重複は throw。 */
export function parseTerminationFile(yamlText: string, source: string): TerminationBehavior[] {
  const { behaviors } = parseWith(TerminationFileSchema, yamlText, source);
  const seen = new Set<string>();
  for (const b of behaviors) {
    if (seen.has(b.componentType)) {
      throw new CryptoBehaviorLoadError(
        `Duplicate componentType "${b.componentType}" in "${source}"`,
        source,
      );
    }
    seen.add(b.componentType);
  }
  return behaviors;
}

/** 翻訳オーバーレイ YAML をパース＋検証する（componentType → 訳）。 */
export function parseTerminationOverlayFile(yamlText: string, source: string): TerminationOverlay {
  return parseWith(TerminationOverlayFileSchema, yamlText, source).behaviors;
}

/** 原本へオーバーレイを被せる。訳が無い項目は原文のまま。 */
export function localizeTermination(
  behaviors: readonly TerminationBehavior[],
  overlay: TerminationOverlay,
): TerminationBehavior[] {
  return behaviors.map((b) => {
    const note = overlay[b.componentType]?.note;
    return note ? { ...b, note } : b;
  });
}

/** PQC 判定の基準表 YAML をパース＋検証する。 */
export function parseAlgorithmTable(yamlText: string, source: string): AlgorithmTable {
  return parseWith(AlgorithmTableSchema, yamlText, source);
}

/**
 * アルゴリズム名を分類する。大文字小文字を区別しない部分一致で、複数の分類に当たる場合は
 * `table.priority` の先頭を採用する（ハイブリッドは pqc になる）。空文字・未知は null。
 */
export function classifyAlgorithm(name: string, table: AlgorithmTable): AlgorithmClass | null {
  const lower = name.trim().toLowerCase();
  if (lower === '') return null;
  for (const cls of table.priority) {
    if (table.classes[cls].tokens.some((t) => lower.includes(t.toLowerCase()))) return cls;
  }
  return null;
}

/** 暗号ライブラリ一覧 YAML をパース＋検証する。id の重複は throw。 */
export function parseCryptoLibraries(yamlText: string, source: string): CryptoLibrary[] {
  const { libraries } = parseWith(CryptoLibraryFileSchema, yamlText, source);
  const seen = new Set<string>();
  for (const l of libraries) {
    if (seen.has(l.id)) {
      throw new CryptoBehaviorLoadError(`Duplicate library id "${l.id}" in "${source}"`, source);
    }
    seen.add(l.id);
  }
  return libraries;
}

/** 暗号ライブラリの翻訳オーバーレイ YAML をパース＋検証する（id → 訳）。 */
export function parseCryptoLibraryOverlay(yamlText: string, source: string): CryptoLibraryOverlay {
  return parseWith(CryptoLibraryOverlayFileSchema, yamlText, source).libraries;
}

/** 原本へオーバーレイを被せる。訳が無い項目は原文のまま。 */
export function localizeCryptoLibraries(
  libraries: readonly CryptoLibrary[],
  overlay: CryptoLibraryOverlay,
): CryptoLibrary[] {
  return libraries.map((l) => {
    const o = overlay[l.id];
    return o ? { ...l, label: o.label ?? l.label, note: o.note ?? l.note } : l;
  });
}

/** purl の版（@）・修飾子（?）・サブパス（#）を除き、小文字にする。 */
export function normalizePurl(purl: string): string {
  return purl.trim().toLowerCase().replace(/[#?].*$/, '').replace(/@.*$/, '');
}

function globToRegExp(pattern: string): RegExp {
  const escaped = pattern.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&'));
  return new RegExp(`^${escaped.join('.*')}$`);
}

/**
 * SBOM の部品に当たる暗号ライブラリを返す（先に書いた項目が優先）。
 * purl があればそれで、無ければ名前（小文字・完全一致）で照合する。
 */
export function matchCryptoLibrary(
  component: { name: string; purl?: string },
  libraries: readonly CryptoLibrary[],
): CryptoLibrary | undefined {
  if (component.purl) {
    const purl = normalizePurl(component.purl);
    return libraries.find((l) => (l.purls ?? []).some((p) => globToRegExp(p.toLowerCase()).test(purl)));
  }
  const name = component.name.trim().toLowerCase();
  return libraries.find((l) => (l.names ?? []).includes(name));
}
