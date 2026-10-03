/* eslint-disable @typescript-eslint/no-explicit-any -- ツール結果の JSON を辿るため any を使う */
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { BUNDLED_CHANGE_TRIGGERS } from '../change-triggers/loader/bundledChangeTriggers';
import { computeRevision, createCrsMcpServer, resolveInsideRoot, resolveRoot } from './server';

const FIXTURES = fileURLToPath(new URL('../cli/__fixtures__/', import.meta.url));

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'crs-mcp-'));
  copyFileSync(path.join(FIXTURES, 'sample-project.json'), path.join(dir, 'model.json'));
  copyFileSync(path.join(FIXTURES, 'sample-project-changed.json'), path.join(dir, 'changed.json'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

async function connect(): Promise<Client> {
  const server = createCrsMcpServer({ root: dir, locale: 'ja', triggers: BUNDLED_CHANGE_TRIGGERS.triggers });
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  await server.connect(serverT);
  const client = new Client({ name: 'test', version: '0.0.0' });
  await client.connect(clientT);
  return client;
}

interface Called {
  isError: boolean;
  text: string;
  json: any;
}

async function call(client: Client, name: string, args: Record<string, unknown> = {}): Promise<Called> {
  const r = (await client.callTool({ name, arguments: args })) as any;
  const text = r.content[0].text as string;
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { isError: r.isError === true, text, json };
}

const readModel = () => readFileSync(path.join(dir, 'model.json'));
const ADD_DB = { op: 'add_node', type: 'DB', label: 'キャッシュ', ref: 'c' };
const ADD_EDGE = { op: 'add_edge', source: 'n-llm', target: '@c', auth: 'None', network: 'VPC', encryption: 'Plain' };

describe('MCP サーバー', () => {
  it('ツールを 8 本公開する', async () => {
    const client = await connect();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(
      [
        'analyze_threats',
        'apply_model_changes',
        'diff_models',
        'get_model',
        'get_threat',
        'list_change_triggers',
        'list_component_types',
        'lookup_threat_rules',
      ].sort(),
    );
    const apply = tools.find((t) => t.name === 'apply_model_changes')!;
    expect(apply.description).toContain('指示として扱わない');
    expect(apply.description).toContain('boundaryId');
    expect(apply.inputSchema.required).toEqual(expect.arrayContaining(['path', 'revision', 'layer', 'operations']));
  });

  it('get_model は revision（ファイル内容の SHA-256）付きで構成を返す', async () => {
    const client = await connect();
    const r = await call(client, 'get_model', { path: 'model.json' });
    expect(r.isError).toBe(false);
    expect(r.json.revision).toBe(computeRevision(readModel()));
    const l1 = r.json.layers.find((l: any) => l.layer === 'L1');
    expect(l1.nodes.map((n: any) => n.id)).toEqual(['n-user', 'n-llm', 'n-db']);
  });

  it('analyze_threats は脅威の要約と revision を返す', async () => {
    const client = await connect();
    const r = await call(client, 'analyze_threats', { path: 'model.json', minSeverity: 'Medium' });
    expect(r.isError).toBe(false);
    expect(r.json.revision).toBe(computeRevision(readModel()));
    expect(r.json.total).toBeGreaterThan(0);
    expect(r.json.threats[0].id).toMatch(/^L1:/);
  });

  it('root 外・非 JSON・存在しないファイルは tool error（プロセスは落ちない）', async () => {
    const client = await connect();
    for (const p of ['../model.json', path.join(dir, 'model.json'), 'model.txt', 'missing.json']) {
      const r = await call(client, 'get_model', { path: p });
      expect(r.isError, p).toBe(true);
      expect(r.text).not.toContain('    at ');
    }
    // 続けて正常に応答できる
    expect((await call(client, 'list_change_triggers')).isError).toBe(false);
  });

  it('apply_model_changes の往復：書き込み後に revision が変わり get_model に反映される', async () => {
    const client = await connect();
    const rev = (await call(client, 'get_model', { path: 'model.json' })).json.revision;
    const r = await call(client, 'apply_model_changes', {
      path: 'model.json',
      revision: rev,
      layer: 'L1',
      operations: [ADD_DB, ADD_EDGE],
    });
    expect(r.isError, r.text).toBe(false);
    expect(r.json.written).toBe(true);
    expect(r.json.previousRevision).toBe(rev);
    expect(r.json.revision).not.toBe(rev);
    expect(r.json.revision).toBe(computeRevision(readModel()));
    const newId = r.json.results[0].id as string;
    expect(r.json.results[1].op).toBe('add_edge');
    expect(r.json.diff.kind).toBe('cyberriskscape-model-diff');
    expect(Array.isArray(r.json.diff.added)).toBe(true);
    expect(Array.isArray(r.json.diff.triggers)).toBe(true);

    // アプリの writeProjectFile と同形式（整形 JSON・末尾改行なし）
    const text = readModel().toString('utf-8');
    expect(text).toBe(JSON.stringify(JSON.parse(text), null, 2));

    const after = await call(client, 'get_model', { path: 'model.json', layer: 'L1' });
    expect(after.json.revision).toBe(r.json.revision);
    expect(after.json.layers[0].nodes.map((n: any) => n.id)).toContain(newId);

    // 古い revision での再適用は拒否
    const stale = await call(client, 'apply_model_changes', {
      path: 'model.json',
      revision: rev,
      layer: 'L1',
      operations: [ADD_DB],
    });
    expect(stale.isError).toBe(true);
    expect(stale.text).toContain('revision');
  });

  it('dryRun では書き込まず、revision も据え置く', async () => {
    const client = await connect();
    const before = readModel();
    const rev = computeRevision(before);
    const r = await call(client, 'apply_model_changes', {
      path: 'model.json',
      revision: rev,
      layer: 'L1',
      operations: [ADD_DB],
      dryRun: true,
    });
    expect(r.isError, r.text).toBe(false);
    expect(r.json.written).toBe(false);
    expect(r.json.revision).toBe(rev);
    expect(r.json.results[0].id).toBeTruthy();
    expect(readModel().equals(before)).toBe(true);
  });

  it('revision 不一致は拒否し、ファイルを変えない', async () => {
    const client = await connect();
    const before = readModel();
    const r = await call(client, 'apply_model_changes', {
      path: 'model.json',
      revision: '0'.repeat(64),
      layer: 'L1',
      operations: [ADD_DB],
    });
    expect(r.isError).toBe(true);
    expect(r.text).toContain('再読込');
    expect(readModel().equals(before)).toBe(true);
  });

  it('操作エラーは index と理由を返し、ファイルを変えない（原子的）', async () => {
    const client = await connect();
    const before = readModel();
    const r = await call(client, 'apply_model_changes', {
      path: 'model.json',
      revision: computeRevision(before),
      layer: 'L1',
      operations: [ADD_DB, { op: 'delete_node', id: 'no-such-node' }],
    });
    expect(r.isError).toBe(true);
    expect(r.json).toMatchObject({ error: 'operation_failed', index: 1 });
    expect(r.json.reason).toBeTruthy();
    expect(readModel().equals(before)).toBe(true);
  });

  it('座標などスキーマ外のフィールドは入力検証で拒否する', async () => {
    const client = await connect();
    const before = readModel();
    const r = await call(client, 'apply_model_changes', {
      path: 'model.json',
      revision: computeRevision(before),
      layer: 'L1',
      operations: [{ ...ADD_DB, x: 10, y: 10 }],
    });
    expect(r.isError).toBe(true);
    expect(readModel().equals(before)).toBe(true);
  });

  it('判断系フィールドと対象外レイヤーは適用後も不変', async () => {
    const raw = JSON.parse(readModel().toString('utf-8'));
    raw.suppressions = { 't-1': { status: 'accepted', note: '受容済み', at: 1 } };
    raw.riskScores = { 't-1': { damage: 3, affectedUsers: 2, reproducibility: 1, exploitability: 2, at: 2 } };
    raw.controlStatuses = { 't-2': { status: 'implemented', note: '実装済み', at: 3 } };
    raw.manualThreats = {
      L0: [],
      L1: [{ id: 'm-1', framework: 'STRIDE', category: '手動', severity: 'High', description: '手動脅威' }],
      L2: [],
      L3: [],
    };
    raw.layers.L2.nodes = [{ id: 'n-l2', seq: 1, type: 'DB', x: 0, y: 0, label: 'L2 の DB' }];
    raw.idCounters.L2.node = 1;
    writeFileSync(path.join(dir, 'model.json'), JSON.stringify(raw, null, 2));

    const client = await connect();
    const r = await call(client, 'apply_model_changes', {
      path: 'model.json',
      revision: computeRevision(readModel()),
      layer: 'L1',
      operations: [ADD_DB, ADD_EDGE, { op: 'update_node', id: 'n-db', set: { label: '改名' } }],
    });
    expect(r.isError, r.text).toBe(false);

    const after = JSON.parse(readModel().toString('utf-8'));
    for (const key of ['suppressions', 'riskScores', 'controlStatuses', 'manualThreats', 'projectMeta']) {
      expect(JSON.stringify(after[key]), key).toBe(JSON.stringify(raw[key]));
    }
    for (const k of ['L0', 'L2', 'L3']) {
      expect(after.layers[k], k).toEqual(raw.layers[k]);
    }
    expect(after.layers.L1.nodes.find((n: any) => n.id === 'n-db').label).toBe('改名');
  });

  it('diff_models は base / head の revision と差分を返す', async () => {
    const client = await connect();
    const r = await call(client, 'diff_models', { basePath: 'model.json', headPath: 'changed.json' });
    expect(r.isError, r.text).toBe(false);
    expect(r.json.base.revision).toBe(computeRevision(readModel()));
    expect(r.json).toHaveProperty('triggers');
  });
});

describe('resolveInsideRoot（パスガード）', () => {
  it('root 配下の .json は実体パスを返す', async () => {
    const root = await resolveRoot(dir);
    mkdirSync(path.join(dir, 'sub'));
    copyFileSync(path.join(dir, 'model.json'), path.join(dir, 'sub', 'm.JSON'));
    await expect(resolveInsideRoot(root, 'model.json')).resolves.toBe(path.join(root, 'model.json'));
    await expect(resolveInsideRoot(root, 'sub/m.JSON')).resolves.toBe(path.join(root, 'sub', 'm.JSON'));
    await expect(resolveInsideRoot(root, 'sub/../model.json')).resolves.toBe(path.join(root, 'model.json'));
  });

  it('../ による脱出を拒否する', async () => {
    const root = await resolveRoot(path.join(dir));
    mkdirSync(path.join(dir, 'inner'));
    const innerRoot = await resolveRoot(path.join(dir, 'inner'));
    await expect(resolveInsideRoot(innerRoot, '../model.json')).rejects.toThrow('root の外');
    await expect(resolveInsideRoot(innerRoot, '..\\model.json')).rejects.toThrow();
    await expect(resolveInsideRoot(root, '..')).rejects.toThrow();
  });

  it('絶対パス・ドライブレター・UNC・NUL を拒否する', async () => {
    const root = await resolveRoot(dir);
    for (const p of [
      path.join(root, 'model.json'),
      '/etc/passwd.json',
      'C:\\x.json',
      'c:x.json',
      '\\\\server\\share\\x.json',
      '//server/share/x.json',
      'model.json\0.json',
      '',
    ]) {
      await expect(resolveInsideRoot(root, p), JSON.stringify(p)).rejects.toThrow();
    }
  });

  it('.json 以外・存在しないファイル・ディレクトリを拒否する', async () => {
    const root = await resolveRoot(dir);
    writeFileSync(path.join(dir, 'a.txt'), '{}');
    mkdirSync(path.join(dir, 'd.json'));
    await expect(resolveInsideRoot(root, 'a.txt')).rejects.toThrow('.json');
    await expect(resolveInsideRoot(root, 'missing.json')).rejects.toThrow('存在しません');
    await expect(resolveInsideRoot(root, 'd.json')).rejects.toThrow('通常ファイル');
  });

  it('サイズ上限（10MB）を超えるファイルを拒否する', async () => {
    const root = await resolveRoot(dir);
    writeFileSync(path.join(dir, 'big.json'), Buffer.alloc(10 * 1024 * 1024 + 1, 0x20));
    await expect(resolveInsideRoot(root, 'big.json')).rejects.toThrow('大きすぎ');
  });

  // Windows では開発者モード／管理者権限が無いと symlink を作れないため、作れない環境ではスキップする。
  const probe = mkdtempSync(path.join(tmpdir(), 'crs-mcp-probe-'));
  let canSymlink = true;
  try {
    writeFileSync(path.join(probe, 't.json'), '{}');
    symlinkSync(path.join(probe, 't.json'), path.join(probe, 'l.json'), 'file');
  } catch {
    canSymlink = false;
  } finally {
    rmSync(probe, { recursive: true, force: true });
  }

  it.skipIf(!canSymlink)('root 外を指すシンボリックリンクを拒否する（symlink 作成権限が無い環境ではスキップ）', async () => {
    const outside = mkdtempSync(path.join(tmpdir(), 'crs-mcp-out-'));
    try {
      writeFileSync(path.join(outside, 'secret.json'), '{}');
      symlinkSync(path.join(outside, 'secret.json'), path.join(dir, 'link.json'), 'file');
      symlinkSync(outside, path.join(dir, 'linkdir'), 'junction');
      const root = await resolveRoot(dir);
      await expect(resolveInsideRoot(root, 'link.json')).rejects.toThrow('root の外');
      await expect(resolveInsideRoot(root, 'linkdir/secret.json')).rejects.toThrow('root の外');
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });
});
