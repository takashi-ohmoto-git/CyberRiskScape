import { describe, expect, it } from 'vitest';
import {
  listProjectFiles,
  projectFilename,
  readProjectFile,
  writeProjectFile,
} from './fileSystem';
import { deserializeProject, serializeProject, type SerializableState } from './serialize';
import { EMPTY_LAYER, type LayerData } from '../../core/model/types';

// ─── projectFilename（slug 化） ──────────────────────────
describe('projectFilename', () => {
  it('英数はそのまま、拡張子 .json を付ける', () => {
    expect(projectFilename('CreditScoringAPI')).toBe('CreditScoringAPI.json');
  });

  it('空白・記号は _ に潰し、前後の _ を除去する', () => {
    expect(projectFilename('  与信 API / v2  ')).toBe('与信_API_v2.json');
  });

  it('空文字・空白のみは project にフォールバックする', () => {
    expect(projectFilename('')).toBe('project.json');
    expect(projectFilename('   ')).toBe('project.json');
  });

  it('. と - は保持する', () => {
    expect(projectFilename('proj-1.2')).toBe('proj-1.2.json');
  });
});

// ─── 保存/読込/一覧（in-memory フェイクハンドル） ──────────
const L1_DATA: LayerData = {
  nodes: [{ id: 'n1', type: 'USER', x: 10, y: 20 }],
  edges: [],
  boundaries: [],
};

const STATE: SerializableState = {
  layers: { L0: EMPTY_LAYER, L1: L1_DATA, L2: EMPTY_LAYER, L3: EMPTY_LAYER },
  activeLayer: 'L1',
  activeFramework: 'AgenticAI',
  projectMeta: {
    name: 'Demo',
    systemName: 'Sys',
    purpose: '',
    businessImpact: '',
    securityObjectives: '',
  },
};

/** FileSystemDirectoryHandle の最小フェイク（node 環境・window/DOM 非依存）。 */
function fakeDir() {
  const files = new Map<string, string>();
  return {
    kind: 'directory',
    name: 'save',
    async getFileHandle(name: string, opts?: { create?: boolean }) {
      if (!files.has(name) && !opts?.create) throw new Error(`not found: ${name}`);
      return {
        kind: 'file',
        name,
        async createWritable() {
          let buf = '';
          return {
            async write(data: string) {
              buf += data;
            },
            async close() {
              files.set(name, buf);
            },
          };
        },
        async getFile() {
          return { text: async () => files.get(name) ?? '' };
        },
      };
    },
    async *values() {
      for (const name of files.keys()) yield { kind: 'file', name };
    },
  } as unknown as FileSystemDirectoryHandle;
}

describe('writeProjectFile / readProjectFile', () => {
  it('書き出したプロジェクトが読み戻せる（round-trip）', async () => {
    const dir = fakeDir();
    const project = serializeProject(STATE);
    await writeProjectFile(dir, 'demo.json', project);
    const restored = await readProjectFile(dir, 'demo.json');
    expect(restored).toEqual(deserializeProject(project));
    expect(restored?.layers?.L1).toEqual(L1_DATA);
    expect(restored?.projectMeta?.name).toBe('Demo');
  });

  it('整形 JSON（2 スペースインデント）で書き出す', async () => {
    const dir = fakeDir();
    await writeProjectFile(dir, 'demo.json', serializeProject(STATE));
    const fh = await dir.getFileHandle('demo.json');
    const text = await (await fh.getFile()).text();
    expect(text).toContain('\n  "schemaVersion"');
  });

  it('JSON 構文エラーのファイルは null を返す', async () => {
    const dir = fakeDir();
    const fh = await dir.getFileHandle('broken.json', { create: true });
    const w = await fh.createWritable();
    await w.write('{ not json');
    await w.close();
    expect(await readProjectFile(dir, 'broken.json')).toBeNull();
  });

  it('スキーマ違反の JSON は null を返す（他種ファイルの誤読を弾く）', async () => {
    const dir = fakeDir();
    const fh = await dir.getFileHandle('other.json', { create: true });
    const w = await fh.createWritable();
    await w.write('{"hello":"world"}');
    await w.close();
    expect(await readProjectFile(dir, 'other.json')).toBeNull();
  });
});

describe('listProjectFiles', () => {
  it('.json のみを昇順で列挙する', async () => {
    const dir = fakeDir();
    await writeProjectFile(dir, 'b.json', serializeProject(STATE));
    await writeProjectFile(dir, 'a.json', serializeProject(STATE));
    // 非 .json は対象外
    const note = await dir.getFileHandle('readme.txt', { create: true });
    const w = await note.createWritable();
    await w.write('memo');
    await w.close();
    expect(await listProjectFiles(dir)).toEqual(['a.json', 'b.json']);
  });
});
