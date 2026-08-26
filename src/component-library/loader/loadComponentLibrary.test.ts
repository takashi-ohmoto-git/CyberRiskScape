import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  loadComponentLibraries,
  parseComponentLibraryFile,
  ComponentLibraryLoadError,
  type RawYamlFile,
} from './loadComponentLibrary';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const DATA_DIR = resolve(__dirname, '../../../data/component-library');

function loadAllYamlFiles(): RawYamlFile[] {
  const files = readdirSync(DATA_DIR).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
  return files.map((name) => ({
    source: name,
    text: readFileSync(join(DATA_DIR, name), 'utf-8'),
  }));
}

describe('loadComponentLibraries - 同梱データ', () => {
  it('data/component-library 配下の YAML をすべてロードできる', () => {
    const result = loadComponentLibraries(loadAllYamlFiles());
    expect(result.components.length).toBeGreaterThan(0);
    expect(result.libraries.some((l) => l.meta.id === 'builtin')).toBe(true);
  });

  it('ビルトインに 13 種類のコンポーネントが含まれる', () => {
    const result = loadComponentLibraries(loadAllYamlFiles());
    const ids = new Set(result.components.map((c) => c.id));
    for (const required of [
      'EXTERNAL_ENTITY',
      'PROCESS',
      'DATA_STORE',
      'LLM',
      'DB',
      'TOOL',
      'AGENT',
      'USER',
      'PC',
      'SMARTPHONE',
      'IOT',
      'GATEWAY',
      'CONNECTOR',
    ]) {
      expect(ids.has(required)).toBe(true);
    }
  });

  it('全カテゴリ ID が宣言済み（dangling reference なし）', () => {
    const result = loadComponentLibraries(loadAllYamlFiles());
    const catIds = new Set(result.categories.map((c) => c.id));
    for (const comp of result.components) {
      expect(catIds.has(comp.category)).toBe(true);
    }
  });

  it('警告ゼロでロードできる', () => {
    const result = loadComponentLibraries(loadAllYamlFiles());
    expect(result.warnings).toEqual([]);
  });
});

describe('parseComponentLibraryFile - バリデーション', () => {
  it('最小構成のライブラリを受理する', () => {
    const yaml = `
schemaVersion: 1
library:
  id: test-lib
  title: "Test Library"
  version: "0.1"
  license: "MIT"
categories:
  - id: TEST
    label: "Test"
    order: 100
components:
  - id: TEST_COMP
    label: "Test Component"
    category: TEST
    icon: { kind: builtin, name: "box" }
    shape: rounded
    color: "bg-slate-500"
`;
    const parsed = parseComponentLibraryFile(yaml, 'inline');
    expect(parsed.components).toHaveLength(1);
    expect(parsed.components[0].id).toBe('TEST_COMP');
  });

  it('小文字始まりの component id を拒否する', () => {
    const yaml = `
schemaVersion: 1
library:
  id: test-lib
  title: t
  version: "0.1"
  license: MIT
categories:
  - id: X
    label: X
    order: 1
components:
  - id: bad_id
    label: x
    category: X
    icon: { kind: builtin, name: box }
    shape: rounded
    color: "bg-slate-500"
`;
    expect(() => parseComponentLibraryFile(yaml, 'inline')).toThrow(ComponentLibraryLoadError);
  });

  it('未知の shape を拒否する', () => {
    const yaml = `
schemaVersion: 1
library:
  id: test-lib
  title: t
  version: "0.1"
  license: MIT
categories:
  - id: X
    label: X
    order: 1
components:
  - id: X_COMP
    label: x
    category: X
    icon: { kind: builtin, name: box }
    shape: hexagon
    color: "bg-slate-500"
`;
    expect(() => parseComponentLibraryFile(yaml, 'inline')).toThrow(ComponentLibraryLoadError);
  });

  it('icon の kind が不正な場合は拒否する', () => {
    const yaml = `
schemaVersion: 1
library:
  id: test-lib
  title: t
  version: "0.1"
  license: MIT
categories:
  - id: X
    label: X
    order: 1
components:
  - id: X_COMP
    label: x
    category: X
    icon: { kind: emoji, value: "🤖" }
    shape: rounded
    color: "bg-slate-500"
`;
    expect(() => parseComponentLibraryFile(yaml, 'inline')).toThrow(ComponentLibraryLoadError);
  });

  it('inline SVG アイコンを受理する', () => {
    const yaml = `
schemaVersion: 1
library:
  id: test-lib
  title: t
  version: "0.1"
  license: MIT
categories:
  - id: X
    label: X
    order: 1
components:
  - id: X_COMP
    label: x
    category: X
    icon: { kind: svg, svg: "<svg></svg>" }
    shape: rounded
    color: "bg-slate-500"
`;
    const parsed = parseComponentLibraryFile(yaml, 'inline');
    expect(parsed.components[0].icon.kind).toBe('svg');
  });

  it('schemaVersion 不一致を拒否する', () => {
    const yaml = `
schemaVersion: 2
library:
  id: test-lib
  title: t
  version: "0.1"
  license: MIT
categories: []
components: []
`;
    expect(() => parseComponentLibraryFile(yaml, 'inline')).toThrow(ComponentLibraryLoadError);
  });
});

describe('loadComponentLibraries - 重複検知 / カテゴリ整合性', () => {
  const validBase = (libId: string, compId: string) => `
schemaVersion: 1
library:
  id: ${libId}
  title: ${libId}
  version: "0.1"
  license: MIT
categories:
  - id: AI
    label: AI
    order: 20
components:
  - id: ${compId}
    label: x
    category: AI
    icon: { kind: builtin, name: box }
    shape: rounded
    color: "bg-slate-500"
`;

  it('ライブラリ ID 重複を拒否する', () => {
    expect(() =>
      loadComponentLibraries([
        { source: 'a.yaml', text: validBase('dup-lib', 'A_COMP') },
        { source: 'b.yaml', text: validBase('dup-lib', 'B_COMP') },
      ]),
    ).toThrow(/Duplicate library id/);
  });

  it('コンポーネント ID 重複（ライブラリ越え）を拒否する', () => {
    expect(() =>
      loadComponentLibraries([
        { source: 'a.yaml', text: validBase('lib-a', 'DUP_COMP') },
        { source: 'b.yaml', text: validBase('lib-b', 'DUP_COMP') },
      ]),
    ).toThrow(/Duplicate component id/);
  });

  it('未宣言カテゴリを参照する component を拒否する', () => {
    const yaml = `
schemaVersion: 1
library:
  id: bad-lib
  title: bad
  version: "0.1"
  license: MIT
categories:
  - id: REAL
    label: real
    order: 1
components:
  - id: X_COMP
    label: x
    category: NONEXISTENT
    icon: { kind: builtin, name: box }
    shape: rounded
    color: "bg-slate-500"
`;
    expect(() => loadComponentLibraries([{ source: 'bad.yaml', text: yaml }])).toThrow(
      /references undeclared category/,
    );
  });

  it('別ライブラリで同じカテゴリを再宣言（idempotent）してもエラーにならない', () => {
    const a = `
schemaVersion: 1
library: { id: lib-a, title: a, version: "0.1", license: MIT }
categories:
  - id: AI
    label: AI
    order: 20
components:
  - id: A_COMP
    label: a
    category: AI
    icon: { kind: builtin, name: box }
    shape: rounded
    color: "bg-slate-500"
`;
    const b = `
schemaVersion: 1
library: { id: lib-b, title: b, version: "0.1", license: MIT }
categories:
  - id: AI
    label: AI
    order: 20
components:
  - id: B_COMP
    label: b
    category: AI
    icon: { kind: builtin, name: box }
    shape: rounded
    color: "bg-slate-500"
`;
    const result = loadComponentLibraries([
      { source: 'a.yaml', text: a },
      { source: 'b.yaml', text: b },
    ]);
    expect(result.warnings).toEqual([]);
    expect(result.categories).toHaveLength(1);
  });

  it('同 ID で label/order が異なる再宣言は warn する（先勝ち）', () => {
    const a = `
schemaVersion: 1
library: { id: lib-a, title: a, version: "0.1", license: MIT }
categories:
  - id: AI
    label: "AI"
    order: 20
components:
  - id: A_COMP
    label: a
    category: AI
    icon: { kind: builtin, name: box }
    shape: rounded
    color: "bg-slate-500"
`;
    const b = `
schemaVersion: 1
library: { id: lib-b, title: b, version: "0.1", license: MIT }
categories:
  - id: AI
    label: "Artificial Intelligence"
    order: 50
components:
  - id: B_COMP
    label: b
    category: AI
    icon: { kind: builtin, name: box }
    shape: rounded
    color: "bg-slate-500"
`;
    const result = loadComponentLibraries([
      { source: 'a.yaml', text: a },
      { source: 'b.yaml', text: b },
    ]);
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.warnings[0]).toMatch(/re-declared/);
    // 先勝ちで a の値が残る
    expect(result.categories.find((c) => c.id === 'AI')?.label).toBe('AI');
  });
});
