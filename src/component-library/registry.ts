import type {
  CategoryDefinition,
  ComponentDefinition,
  ComponentTypeId,
  LibraryMeta,
} from './schema/component';
import type { LoadResult } from './loader/loadComponentLibrary';

/**
 * ロード済みコンポーネントライブラリへの照会窓口。
 *
 * このクラス自体は **無効化状態を持たない**（ピュアな読み取りインタフェース）。
 * 「どのライブラリを無効化中か」は呼び出し側（Zustand store）が保持し、
 * `listByCategory(disabledIds)` 等にパラメータで渡す。
 */
export class ComponentRegistry {
  private readonly componentsById: ReadonlyMap<ComponentTypeId, ComponentDefinition>;
  private readonly categories: readonly CategoryDefinition[];
  private readonly libraries: readonly LibraryMeta[];
  private readonly componentToLibrary: ReadonlyMap<string, string>;

  constructor(load: LoadResult) {
    this.componentsById = new Map(load.components.map((c) => [c.id, c] as const));
    this.categories = load.categories;
    this.libraries = load.libraries.map((l) => l.meta);
    this.componentToLibrary = load.componentToLibrary;
  }

  /** 全コンポーネント（無効化状態に関係なく）から ID 引き。配置済みノードの描画で使用。 */
  get(id: ComponentTypeId): ComponentDefinition | undefined {
    return this.componentsById.get(id);
  }

  /** ID で存在チェック（脅威ルール側の整合性検証用）。 */
  has(id: ComponentTypeId): boolean {
    return this.componentsById.has(id);
  }

  /** 全コンポーネント（無効化に関係なく）。整合性チェック等のため。 */
  getAll(): readonly ComponentDefinition[] {
    return [...this.componentsById.values()];
  }

  /** 全カテゴリ（order 昇順）。 */
  getCategories(): readonly CategoryDefinition[] {
    return this.categories;
  }

  /** 全ライブラリのメタ（UI のライブラリ管理画面用）。 */
  getLibraries(): readonly LibraryMeta[] {
    return this.libraries;
  }

  /** コンポーネントが属するライブラリ ID を返す（無ければ undefined）。 */
  getLibraryIdOf(componentId: ComponentTypeId): string | undefined {
    return this.componentToLibrary.get(componentId);
  }

  /**
   * 親型が子型を内包できるかをホワイトリスト（canContain）で判定する。
   * 親 or 子が未登録、あるいは parent.canContain 未宣言なら false。
   * ドロップ判定・データ整合性検証の双方で利用する単一の真実ソース。
   */
  canContain(parentTypeId: ComponentTypeId, childTypeId: ComponentTypeId): boolean {
    const parent = this.componentsById.get(parentTypeId);
    if (!parent || !parent.canContain) return false;
    if (!this.componentsById.has(childTypeId)) return false;
    return parent.canContain.includes(childTypeId);
  }

  /**
   * パレット用：カテゴリ別に **有効化中の** コンポーネントを返す。
   * 空カテゴリはスキップ。`disabledLibraryIds` 省略時は全有効化扱い。
   */
  listByCategory(
    disabledLibraryIds: ReadonlySet<string> = new Set(),
  ): Array<{ category: CategoryDefinition; components: ComponentDefinition[] }> {
    const buckets = new Map<string, ComponentDefinition[]>();
    for (const comp of this.componentsById.values()) {
      const libId = this.componentToLibrary.get(comp.id);
      if (libId !== undefined && disabledLibraryIds.has(libId)) continue;
      const arr = buckets.get(comp.category) ?? [];
      arr.push(comp);
      buckets.set(comp.category, arr);
    }
    return this.categories
      .filter((c) => buckets.has(c.id))
      .map((category) => ({
        category,
        components: (buckets.get(category.id) ?? []).sort((a, b) =>
          a.label.localeCompare(b.label, 'ja'),
        ),
      }));
  }
}
