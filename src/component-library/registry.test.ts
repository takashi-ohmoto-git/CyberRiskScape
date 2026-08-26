import { describe, expect, it } from 'vitest';
import { ComponentRegistry } from './registry';
import type { LoadResult } from './loader/loadComponentLibrary';
import type {
  CategoryDefinition,
  ComponentDefinition,
  LibraryMeta,
} from './schema/component';

function comp(
  id: string,
  category: string,
  label?: string,
  opts?: { canContain?: string[] },
): ComponentDefinition {
  return {
    id,
    label: label ?? id,
    category,
    icon: { kind: 'builtin', name: 'box' },
    shape: 'rounded',
    color: 'bg-slate-500',
    ...(opts?.canContain ? { canContain: opts.canContain } : {}),
  };
}

function makeRegistry(args: {
  components: ComponentDefinition[];
  categories: CategoryDefinition[];
  libraries: { meta: LibraryMeta; ownsIds: string[] }[];
}): ComponentRegistry {
  const componentToLibrary = new Map<string, string>();
  const libraries = args.libraries.map(({ meta, ownsIds }) => {
    for (const id of ownsIds) componentToLibrary.set(id, meta.id);
    return { meta, source: '(test)' };
  });
  const result: LoadResult = {
    components: args.components,
    categories: args.categories,
    libraries,
    componentToLibrary,
    warnings: [],
  };
  return new ComponentRegistry(result);
}

describe('ComponentRegistry', () => {
  const registry = makeRegistry({
    components: [
      comp('LLM', 'AI', 'LLM'),
      comp('AGENT', 'AI', 'Agent'),
      comp('USER', 'INFRA', 'User'),
      comp('MCP_SERVER', 'MCP', 'MCP Server'),
    ],
    // ローダーが order 昇順で並べてからレジストリに渡す契約。テストでも事前ソート済みで渡す。
    categories: [
      { id: 'AI', label: 'AI', order: 20 },
      { id: 'MCP', label: 'MCP', order: 25 },
      { id: 'INFRA', label: 'Infrastructure', order: 30 },
    ],
    libraries: [
      {
        meta: { id: 'builtin', title: 'Built-in', version: '1.0', license: 'Apache-2.0', builtin: true },
        ownsIds: ['LLM', 'AGENT', 'USER'],
      },
      {
        meta: { id: 'my-mcp', title: 'MCP Stencil', version: '0.1', license: 'MIT' },
        ownsIds: ['MCP_SERVER'],
      },
    ],
  });

  it('get() で登録済みコンポーネントを引ける', () => {
    expect(registry.get('LLM')?.label).toBe('LLM');
    expect(registry.get('MCP_SERVER')?.label).toBe('MCP Server');
  });

  it('未登録 ID は undefined を返す', () => {
    expect(registry.get('NONEXISTENT')).toBeUndefined();
    expect(registry.has('NONEXISTENT')).toBe(false);
  });

  it('listByCategory: 無効化なしなら全コンポーネントを返す', () => {
    const sections = registry.listByCategory();
    expect(sections).toHaveLength(3); // AI, MCP, INFRA
    const ai = sections.find((s) => s.category.id === 'AI');
    expect(ai?.components.map((c) => c.id).sort()).toEqual(['AGENT', 'LLM']);
  });

  it('listByCategory: order 昇順でカテゴリが並ぶ', () => {
    const sections = registry.listByCategory();
    expect(sections.map((s) => s.category.id)).toEqual(['AI', 'MCP', 'INFRA']);
  });

  it('listByCategory: 無効化したライブラリのコンポーネントは除外される', () => {
    const sections = registry.listByCategory(new Set(['my-mcp']));
    const ids = sections.flatMap((s) => s.components.map((c) => c.id));
    expect(ids).not.toContain('MCP_SERVER');
    expect(ids).toContain('LLM');
    // 全コンポーネントが消えたカテゴリ (MCP) はセクションから消える
    expect(sections.some((s) => s.category.id === 'MCP')).toBe(false);
  });

  it('getLibraryIdOf: コンポーネントの所属ライブラリを引ける', () => {
    expect(registry.getLibraryIdOf('LLM')).toBe('builtin');
    expect(registry.getLibraryIdOf('MCP_SERVER')).toBe('my-mcp');
    expect(registry.getLibraryIdOf('NONEXISTENT')).toBeUndefined();
  });

  describe('canContain', () => {
    const r = makeRegistry({
      components: [
        comp('VECTOR_DB', 'AI', 'VectorDB', { canContain: ['PII', 'LOG'] }),
        comp('PII', 'DOCS', 'PII'),
        comp('LOG', 'DOCS', 'Log'),
        comp('LEAF', 'AI', 'Leaf'),
      ],
      categories: [
        { id: 'AI', label: 'AI', order: 10 },
        { id: 'DOCS', label: 'Docs', order: 20 },
      ],
      libraries: [
        {
          meta: { id: 'builtin', title: 'Built-in', version: '1.0', license: 'Apache-2.0', builtin: true },
          ownsIds: ['VECTOR_DB', 'PII', 'LOG', 'LEAF'],
        },
      ],
    });

    it('ホワイトリストに含まれる子は true', () => {
      expect(r.canContain('VECTOR_DB', 'PII')).toBe(true);
      expect(r.canContain('VECTOR_DB', 'LOG')).toBe(true);
    });

    it('ホワイトリスト外の子は false', () => {
      expect(r.canContain('VECTOR_DB', 'LEAF')).toBe(false);
    });

    it('canContain 未宣言の親は false', () => {
      expect(r.canContain('LEAF', 'PII')).toBe(false);
    });

    it('未登録の親 or 子は false', () => {
      expect(r.canContain('NONEXISTENT', 'PII')).toBe(false);
      expect(r.canContain('VECTOR_DB', 'NONEXISTENT')).toBe(false);
    });
  });
});
