import { parse as parseYaml } from 'yaml';
import {
  ComponentLibraryFileSchema,
  type CategoryDefinition,
  type ComponentDefinition,
  type ComponentLibraryFile,
  type LibraryMeta,
} from '../schema/component';

/**
 * コンポーネントライブラリ YAML のロード失敗時に投げる例外。
 */
export class ComponentLibraryLoadError extends Error {
  readonly source: string;
  override readonly cause?: unknown;
  constructor(message: string, source: string, cause?: unknown) {
    super(message);
    this.name = 'ComponentLibraryLoadError';
    this.source = source;
    this.cause = cause;
  }
}

export interface RawYamlFile {
  source: string;
  text: string;
}

export interface LoadedLibrary {
  meta: LibraryMeta;
  source: string;
}

export interface LoadResult {
  libraries: LoadedLibrary[];
  categories: CategoryDefinition[];
  components: ComponentDefinition[];
  /** component.id → 所属ライブラリ id。整合性検証で利用。 */
  componentToLibrary: Map<string, string>;
  /** ロード時に検出した非致命の警告（重複カテゴリ宣言など）。 */
  warnings: string[];
}

/**
 * YAML 文字列 1 本をパース＋スキーマ検証する。
 */
export function parseComponentLibraryFile(
  yamlText: string,
  source: string,
): ComponentLibraryFile {
  let parsed: unknown;
  try {
    parsed = parseYaml(yamlText);
  } catch (e) {
    throw new ComponentLibraryLoadError(
      `YAML parse error in "${source}": ${(e as Error).message}`,
      source,
      e,
    );
  }
  const result = ComponentLibraryFileSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new ComponentLibraryLoadError(
      `Schema validation failed for "${source}":\n${issues}`,
      source,
      result.error,
    );
  }
  return result.data;
}

/**
 * 複数 YAML をまとめてロード。
 *
 * 制約：
 * - ライブラリ id 重複は throw。
 * - コンポーネント id 重複（ライブラリをまたいでも）は throw。
 * - カテゴリ id 重複は idempotent：label / order が一致すれば silently 許可、
 *   不一致なら warnings に積み、先勝ち（最初に宣言されたものを採用）。
 * - 各 component.category が **集約後のカテゴリ集合に存在すること** を fail-fast 検証。
 */
export function loadComponentLibraries(files: readonly RawYamlFile[]): LoadResult {
  const libraries: LoadedLibrary[] = [];
  const seenLibraryIds = new Map<string, string>();
  const categoriesById = new Map<string, CategoryDefinition>();
  const componentToLibrary = new Map<string, string>();
  const componentSourceById = new Map<string, string>();
  const components: ComponentDefinition[] = [];
  const warnings: string[] = [];

  for (const file of files) {
    const parsed = parseComponentLibraryFile(file.text, file.source);
    const { library, categories, components: comps } = parsed;

    const prevLib = seenLibraryIds.get(library.id);
    if (prevLib !== undefined) {
      throw new ComponentLibraryLoadError(
        `Duplicate library id "${library.id}" in "${file.source}" (already defined in "${prevLib}")`,
        file.source,
      );
    }
    seenLibraryIds.set(library.id, file.source);
    libraries.push({ meta: library, source: file.source });

    for (const cat of categories) {
      const prev = categoriesById.get(cat.id);
      if (prev === undefined) {
        categoriesById.set(cat.id, cat);
      } else if (prev.label !== cat.label || prev.order !== cat.order) {
        warnings.push(
          `Category "${cat.id}" re-declared in "${file.source}" with different label/order (kept first declaration)`,
        );
      }
      // 完全一致の再宣言は静かに無視（idempotent）
    }

    for (const comp of comps) {
      const prev = componentSourceById.get(comp.id);
      if (prev !== undefined) {
        throw new ComponentLibraryLoadError(
          `Duplicate component id "${comp.id}" in "${file.source}" (already defined in "${prev}")`,
          file.source,
        );
      }
      componentSourceById.set(comp.id, file.source);
      componentToLibrary.set(comp.id, library.id);
      components.push(comp);
    }
  }

  // カテゴリ参照整合性（fail-fast）
  for (const comp of components) {
    if (!categoriesById.has(comp.category)) {
      const source = componentSourceById.get(comp.id) ?? '(unknown)';
      throw new ComponentLibraryLoadError(
        `Component "${comp.id}" in "${source}" references undeclared category "${comp.category}"`,
        source,
      );
    }
  }

  // canContain 参照整合性（fail-fast）：未宣言の子型を指していないか
  const knownComponentIds = new Set(components.map((c) => c.id));
  for (const comp of components) {
    if (!comp.canContain) continue;
    for (const childId of comp.canContain) {
      if (!knownComponentIds.has(childId)) {
        const source = componentSourceById.get(comp.id) ?? '(unknown)';
        throw new ComponentLibraryLoadError(
          `Component "${comp.id}" in "${source}" canContain references unknown component "${childId}"`,
          source,
        );
      }
    }
  }

  // カテゴリを order 昇順 → id 辞書順でソート
  const categories = [...categoriesById.values()].sort(
    (a, b) => a.order - b.order || a.id.localeCompare(b.id),
  );

  return { libraries, categories, components, componentToLibrary, warnings };
}
