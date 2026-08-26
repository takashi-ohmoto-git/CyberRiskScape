import { parse as parseYaml } from 'yaml';
import {
  ComplianceMapFileSchema,
  type ComplianceItem,
  type ComplianceMapFile,
  type StandardId,
} from '../schema/complianceItem';

/**
 * コンプライアンスマップ YAML のロード失敗時に投げる例外。
 * 脅威ライブラリ側の `ThreatLibraryLoadError` と同じ思想で、ソース名と原因を保持する。
 */
export class ComplianceMapLoadError extends Error {
  readonly source: string;
  override readonly cause?: unknown;

  constructor(message: string, source: string, cause?: unknown) {
    super(message);
    this.name = 'ComplianceMapLoadError';
    this.source = source;
    this.cause = cause;
  }
}

export interface RawYamlFile {
  source: string;
  text: string;
}

/**
 * `(standard.id, ref)` で逆引きするためのキー型。
 */
export type ComplianceKey = `${StandardId}:${string}`;

export interface LoadedComplianceMap {
  /** 規格 ID → メタ情報。 */
  standards: ReadonlyMap<StandardId, ComplianceMapFile['standard']>;
  /** 規格 ID → 当該規格の全 item（YAML 上の順序を保持）。 */
  itemsByStandard: ReadonlyMap<StandardId, readonly ComplianceItem[]>;
  /** `(standard.id, ref)` → item の逆引き辞書。 */
  index: ReadonlyMap<ComplianceKey, ComplianceItem>;
  /** ロードしたソース一覧（診断用）。 */
  sources: readonly string[];
}

/** 1 件の item を一意に表すキーを生成する。 */
export function makeComplianceKey(standard: StandardId, ref: string): ComplianceKey {
  return `${standard}:${ref}` as ComplianceKey;
}

/**
 * YAML 1 本をパース＋スキーマ検証する純粋関数。
 */
export function parseComplianceMapFile(yamlText: string, source: string): ComplianceMapFile {
  let parsed: unknown;
  try {
    parsed = parseYaml(yamlText);
  } catch (e) {
    throw new ComplianceMapLoadError(
      `YAML parse error in "${source}": ${(e as Error).message}`,
      source,
      e,
    );
  }

  const result = ComplianceMapFileSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new ComplianceMapLoadError(
      `Schema validation failed for "${source}":\n${issues}`,
      source,
      result.error,
    );
  }

  return result.data;
}

/**
 * 複数 YAML をまとめてロードする。
 *
 * - 同一 `standard.id` の重複定義は throw（1 規格 = 1 ファイル方針）。
 * - 規格内 `ref` の重複も throw。
 * - `relatedTo` の参照先がライブラリ内に存在しない場合も throw（リンク切れは設計ミス）。
 */
export function loadComplianceMap(files: readonly RawYamlFile[]): LoadedComplianceMap {
  const standards = new Map<StandardId, ComplianceMapFile['standard']>();
  const itemsByStandard = new Map<StandardId, ComplianceItem[]>();
  const index = new Map<ComplianceKey, ComplianceItem>();
  const sourceByStandard = new Map<StandardId, string>();

  for (const file of files) {
    const parsed = parseComplianceMapFile(file.text, file.source);
    const standardId = parsed.standard.id;

    const prevSource = sourceByStandard.get(standardId);
    if (prevSource !== undefined) {
      throw new ComplianceMapLoadError(
        `Duplicate standard "${standardId}" in "${file.source}" (already defined in "${prevSource}")`,
        file.source,
      );
    }
    sourceByStandard.set(standardId, file.source);
    standards.set(standardId, parsed.standard);

    const items: ComplianceItem[] = [];
    for (const item of parsed.items) {
      const key = makeComplianceKey(standardId, item.ref);
      if (index.has(key)) {
        throw new ComplianceMapLoadError(
          `Duplicate item "${item.ref}" for standard "${standardId}" in "${file.source}"`,
          file.source,
        );
      }
      index.set(key, item);
      items.push(item);
    }
    itemsByStandard.set(standardId, items);
  }

  // relatedTo のリンク切れチェック（全ファイル読み込み後に実施）。
  for (const [key, item] of index) {
    if (!item.relatedTo) continue;
    const ownerStandard = key.split(':')[0] as StandardId;
    for (const rel of item.relatedTo) {
      const targetKey = makeComplianceKey(rel.standard, rel.ref);
      if (!index.has(targetKey)) {
        throw new ComplianceMapLoadError(
          `Dangling relatedTo: item "${key}" references missing "${targetKey}"`,
          sourceByStandard.get(ownerStandard) ?? '(unknown)',
        );
      }
    }
  }

  return {
    standards,
    itemsByStandard,
    index,
    sources: files.map((f) => f.source),
  };
}

/**
 * 脅威ルール側 `complianceRefs` がマップ内に解決できるかを検査し、
 * 未解決の参照を返す（warn ログ用途、throw しない）。
 *
 * UI 表示時のフォールバック（マップに無いキーはそのまま `standard / ref` を表示）と
 * 整合する設計のため、起動時に fail させずに開発者にだけ知らせる。
 */
export interface UnresolvedComplianceRef {
  ruleId: string;
  standard: string;
  ref: string;
}

export function findUnresolvedComplianceRefs(
  map: LoadedComplianceMap,
  rules: readonly {
    id: string;
    complianceRefs?: readonly { standard: string; ref: string }[];
  }[],
): UnresolvedComplianceRef[] {
  const unresolved: UnresolvedComplianceRef[] = [];
  const knownStandards = new Set<string>(map.standards.keys());

  for (const rule of rules) {
    if (!rule.complianceRefs) continue;
    for (const c of rule.complianceRefs) {
      // 未知の standard ID（外部参照扱い、map の対象外）はスキップしない：警告対象。
      if (!knownStandards.has(c.standard)) {
        unresolved.push({ ruleId: rule.id, standard: c.standard, ref: c.ref });
        continue;
      }
      const key = makeComplianceKey(c.standard as StandardId, c.ref);
      if (!map.index.has(key)) {
        unresolved.push({ ruleId: rule.id, standard: c.standard, ref: c.ref });
      }
    }
  }

  return unresolved;
}
