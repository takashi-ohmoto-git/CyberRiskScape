import { describe, expect, it } from 'vitest';
import {
  findOrphanOverlayIds,
  findUntranslatedComponentIds,
  loadComponentOverlay,
  localizeComponents,
  parseComponentOverlayFile,
} from './localizeComponentLibrary';
import { ComponentLibraryLoadError, type LoadResult } from './loadComponentLibrary';
import type { ComponentDefinition } from '../schema/component';

const agent: ComponentDefinition = {
  id: 'AGENT',
  label: 'AIエージェント',
  category: 'AI',
  icon: { kind: 'builtin', name: 'bot' },
  shape: 'rounded',
  color: 'bg-purple-600',
  description: '計画・ツール選択・推論を自律的に行う AI エージェント。',
};

const iot: ComponentDefinition = {
  id: 'IOT',
  label: 'IoT',
  category: 'ENDPOINT',
  icon: { kind: 'builtin', name: 'cpu' },
  shape: 'rectangle',
  color: 'bg-teal-600',
  description: 'IoT 機器・組込デバイス。',
};

const load: LoadResult = {
  libraries: [],
  categories: [],
  components: [agent, iot],
  componentToLibrary: new Map([
    ['AGENT', 'builtin'],
    ['IOT', 'builtin'],
  ]),
  warnings: [],
};

const overlayYaml = `
schemaVersion: 1
locale: en
components:
  AGENT:
    label: AI agent
    description: An AI agent that plans, selects tools, and reasons autonomously.
  IOT:
    description: An IoT or embedded device.
`;

describe('parseComponentOverlayFile', () => {
  it('コンポーネント型 ID をキーに訳文を返す', () => {
    const overlay = parseComponentOverlayFile(overlayYaml, 'en/builtin.yaml');
    expect(Object.keys(overlay)).toEqual(['AGENT', 'IOT']);
    expect(overlay.AGENT?.label).toBe('AI agent');
  });

  it('未知フィールドを拒否する（strict）', () => {
    expect(() =>
      parseComponentOverlayFile(
        `
schemaVersion: 1
locale: en
components:
  AGENT:
    color: bg-red-600
`,
        'en/bad.yaml',
      ),
    ).toThrow(ComponentLibraryLoadError);
  });

  it('YAML として壊れていれば source 付きで落ちる', () => {
    expect(() => parseComponentOverlayFile('rules: [unclosed', 'en/broken.yaml')).toThrow(
      ComponentLibraryLoadError,
    );
  });
});

describe('loadComponentOverlay', () => {
  it('複数ファイルを 1 つのマップへ統合する', () => {
    const overlay = loadComponentOverlay([
      { source: 'en/a.yaml', text: overlayYaml },
      {
        source: 'en/b.yaml',
        text: `
schemaVersion: 1
locale: en
components:
  MCP_SERVER:
    label: MCP server
`,
      },
    ]);
    expect(Object.keys(overlay).sort()).toEqual(['AGENT', 'IOT', 'MCP_SERVER']);
  });

  it('同じ型 ID が複数ファイルにあれば落とす', () => {
    expect(() =>
      loadComponentOverlay([
        { source: 'en/a.yaml', text: overlayYaml },
        { source: 'en/b.yaml', text: overlayYaml },
      ]),
    ).toThrow(ComponentLibraryLoadError);
  });
});

describe('localizeComponents', () => {
  const overlay = parseComponentOverlayFile(overlayYaml, 'en/builtin.yaml');

  it('label と description を差し替える', () => {
    const localized = localizeComponents(load, overlay);
    const a = localized.components.find((c) => c.id === 'AGENT');
    expect(a?.label).toBe('AI agent');
    expect(a?.description).toBe('An AI agent that plans, selects tools, and reasons autonomously.');
  });

  it('指定の無いフィールドは原文のまま残す', () => {
    const localized = localizeComponents(load, overlay);
    // IOT は description だけ訳されている
    expect(localized.components.find((c) => c.id === 'IOT')?.label).toBe('IoT');
  });

  it('言語非依存のフィールドは変えない', () => {
    const localized = localizeComponents(load, overlay);
    const a = localized.components.find((c) => c.id === 'AGENT');
    expect(a?.shape).toBe('rounded');
    expect(a?.color).toBe('bg-purple-600');
    expect(a?.category).toBe('AI');
    expect(localized.componentToLibrary).toBe(load.componentToLibrary);
  });

  it('訳の無い型は同一オブジェクトのまま返す（無駄なコピーをしない）', () => {
    const localized = localizeComponents(load, {});
    expect(localized.components[0]).toBe(agent);
    expect(localized.components[1]).toBe(iot);
  });

  it('原本を書き換えない', () => {
    localizeComponents(load, overlay);
    expect(agent.label).toBe('AIエージェント');
  });
});

describe('診断', () => {
  it('原本に無い型 ID を検出する', () => {
    const overlay = parseComponentOverlayFile(
      `
schemaVersion: 1
locale: en
components:
  REMOVED_TYPE:
    label: Gone
`,
      'en/orphan.yaml',
    );
    expect(findOrphanOverlayIds(load.components, overlay)).toEqual(['REMOVED_TYPE']);
  });

  it('未翻訳の型 ID を検出する', () => {
    const overlay = parseComponentOverlayFile(
      `
schemaVersion: 1
locale: en
components:
  AGENT:
    label: AI agent
`,
      'en/partial.yaml',
    );
    expect(findUntranslatedComponentIds(load.components, overlay)).toEqual(['IOT']);
  });
});
