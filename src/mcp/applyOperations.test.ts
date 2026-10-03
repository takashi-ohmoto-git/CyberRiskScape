import { describe, expect, it } from 'vitest';
import { McpOperationError, applyOperations } from './applyOperations';
import { deserializeProject } from '../features/persistence/serialize';
import { resolveNodeBoundaries } from '../core/canvas/boundaryCrossing';
import type { LayerKey } from '../core/model/types';

type Raw = Record<string, unknown>;

/** L1 に境界 b1（0,0,400x200）と、その内側の LLM / DB、外側の USER / IdP / 攻撃者を置いた最小プロジェクト。 */
function fixture(): Raw {
  const empty = { nodes: [], edges: [], boundaries: [], annotations: [] };
  return {
    schemaVersion: 1,
    layers: {
      L0: {
        nodes: [{ id: 'l0-n', seq: 1, type: 'USER', x: 5, y: 6, label: 'L0 の利用者' }],
        edges: [],
        boundaries: [],
        annotations: [],
      },
      L1: {
        nodes: [
          { id: 'n-user', seq: 1, type: 'USER', x: -400, y: 0, label: '利用者' },
          { id: 'n-idp', seq: 2, type: 'IDENTITY_PROVIDER', x: -400, y: 200, label: 'IdP' },
          { id: 'n-llm', seq: 3, type: 'LLM', x: 32, y: 32, label: 'LLM', authProviderId: 'n-idp' },
          { id: 'n-db', seq: 4, type: 'DB', x: 192, y: 32, label: 'DB' },
          { id: 'n-att', seq: 5, type: 'THREAT_ACTOR', x: -400, y: 400, attackObjectiveId: 'n-llm' },
          { id: 'n-pc', seq: 6, type: 'PC', x: 0, y: 0, parentId: 'n-user' },
        ],
        edges: [
          {
            id: 'e-1',
            seq: 1,
            source: 'n-user',
            target: 'n-llm',
            auth: 'Password',
            network: 'Internet',
            encryption: 'TLS',
            authProviderId: 'n-idp',
          },
          { id: 'e-2', seq: 2, source: 'n-llm', target: 'n-db', auth: 'None', network: 'VPC', encryption: 'Plain' },
        ],
        boundaries: [{ id: 'b-1', seq: 1, type: 'RECT', x: 0, y: 0, width: 400, height: 200, trustLevel: 'Internal' }],
        annotations: [{ id: 'a-1', kind: 'callout', x: 10, y: 10, text: 'メモ', targetNodeId: 'n-llm' }],
      },
      L2: empty,
      L3: empty,
    },
    activeLayer: 'L1',
    idCounters: {
      L0: { node: 1, edge: 0, boundary: 0 },
      L1: { node: 6, edge: 2, boundary: 1 },
      L2: { node: 0, edge: 0, boundary: 0 },
      L3: { node: 0, edge: 0, boundary: 0 },
    },
    activeFramework: 'ALL',
    projectMeta: {
      name: 'テスト',
      systemName: 'sys',
      purpose: 'p',
      businessImpact: 'b',
      securityObjectives: 's',
    },
    manualThreats: {
      L0: [],
      L1: [{ id: 'm1', framework: 'STRIDE', category: 'x', severity: 'High', description: 'd' }],
      L2: [],
      L3: [],
    },
    suppressions: { t1: { status: 'accepted', note: 'ok', at: 1 } },
    riskScores: { t1: { damage: 3, affectedUsers: 2, reproducibility: 1, exploitability: 2, at: 1 } },
    controlStatuses: { t1: { status: 'implemented', at: 1 } },
    updatedAt: 1,
  };
}

function apply(ops: unknown[], layer: LayerKey = 'L1', raw: Raw = fixture()) {
  return applyOperations(raw, layer, ops);
}

function l1(project: ReturnType<typeof apply>['project']) {
  return project.layers!.L1;
}

function owningIds(project: ReturnType<typeof apply>['project'], nodeId: string): string[] {
  const layer = l1(project);
  const nodes = layer.nodes as never;
  return resolveNodeBoundaries(nodes, layer.boundaries as never)
    .get(nodeId)!
    .map((b) => b.id);
}

function reasonOf(fn: () => unknown): McpOperationError {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(McpOperationError);
    return e as McpOperationError;
  }
  throw new Error('throw されませんでした');
}

describe('正常系：ノード', () => {
  it('add_node（境界内）：境界の内側に置かれ、採番とカウンタが更新される', () => {
    const { project, results } = apply([{ op: 'add_node', type: 'LLM', label: '新 LLM', boundaryId: 'b-1' }]);
    const added = l1(project).nodes.find((n) => n.id === results[0].id)!;
    expect(added.label).toBe('新 LLM');
    expect(added.seq).toBe(7);
    expect(added.id).toMatch(/^n[0-9a-z]+$/);
    expect(owningIds(project, added.id)).toEqual(['b-1']);
    expect(project.idCounters!.L1.node).toBe(7);
    expect(project.idCounters!.L0).toEqual({ node: 1, edge: 0, boundary: 0 });
    expect(deserializeProject(project)).not.toBeNull();
  });

  it('add_node（境界指定なし）：どの境界にも入らない', () => {
    const { project, results } = apply([{ op: 'add_node', type: 'DB', label: 'X' }]);
    expect(owningIds(project, results[0].id!)).toEqual([]);
  });

  it('add_node（境界が満杯）：境界を下へ広げ、それでも境界内に入る', () => {
    const { project, results } = apply([
      { op: 'add_node', type: 'LLM', label: 'A', boundaryId: 'b-1' },
      { op: 'add_node', type: 'LLM', label: 'B', boundaryId: 'b-1' },
      { op: 'add_node', type: 'LLM', label: 'C', boundaryId: 'b-1' },
    ]);
    for (const r of results) expect(owningIds(project, r.id!)).toEqual(['b-1']);
    const b = l1(project).boundaries.find((x) => x.id === 'b-1')!;
    expect(b.height).toBeGreaterThan(200);
    expect(b.x).toBe(0);
    expect(b.width).toBe(400);
  });

  it('add_node（parentId）：canContain を満たすときだけ内包できる', () => {
    const ok = apply([{ op: 'add_node', type: 'PC', label: 'PC', parentId: 'n-user' }]);
    expect(l1(ok.project).nodes.find((n) => n.id === ok.results[0].id)!.parentId).toBe('n-user');
    expect(
      reasonOf(() => apply([{ op: 'add_node', type: 'DB', label: 'DB', parentId: 'n-user' }])).reason,
    ).toMatch(/内包できません/);
  });

  it('add_node：属性が型に合わない場合は拒否、USER の信頼区分から managedState を派生', () => {
    expect(
      reasonOf(() => apply([{ op: 'add_node', type: 'DB', label: 'DB', cloudSanction: 'Sanctioned' }])).reason,
    ).toMatch(/cloudSanction/);
    const { project, results } = apply([
      { op: 'add_node', type: 'USER', label: 'ゲスト', userTrustAttribute: 'Guest' },
    ]);
    const n = l1(project).nodes.find((x) => x.id === results[0].id)!;
    expect(n.managedState).toBe('Unmanaged');
  });

  it('update_node：許可リストの属性を更新し、null で消せる', () => {
    const { project } = apply([
      { op: 'update_node', id: 'n-db', set: { label: '更新後', description: '説明' } },
      { op: 'update_node', id: 'n-llm', set: { authProviderId: null } },
    ]);
    const db = l1(project).nodes.find((n) => n.id === 'n-db')!;
    expect(db.label).toBe('更新後');
    expect(db.description).toBe('説明');
    expect(db.x).toBe(192);
    expect(l1(project).nodes.find((n) => n.id === 'n-llm')!.authProviderId).toBeUndefined();
  });

  it('update_node（boundaryId）：再配置で境界の内外を移動する', () => {
    const into = apply([{ op: 'update_node', id: 'n-user', boundaryId: 'b-1' }]);
    expect(owningIds(into.project, 'n-user')).toEqual(['b-1']);
    const out = apply([{ op: 'update_node', id: 'n-db', boundaryId: null }]);
    expect(owningIds(out.project, 'n-db')).toEqual([]);
  });

  it('update_node：内包された子の再配置は拒否', () => {
    expect(reasonOf(() => apply([{ op: 'update_node', id: 'n-pc', boundaryId: 'b-1' }])).reason).toMatch(/内包/);
  });

  it('delete_node：連鎖解除と接続エッジの削除（ストアの deleteNode と同じ解除＋エッジ）', () => {
    const { project } = apply([
      { op: 'delete_node', id: 'n-llm' },
      { op: 'delete_node', id: 'n-user' },
      { op: 'delete_node', id: 'n-idp' },
    ]);
    const layer = l1(project);
    expect(layer.nodes.map((n) => n.id).sort()).toEqual(['n-att', 'n-db', 'n-pc']);
    expect(layer.nodes.find((n) => n.id === 'n-att')!.attackObjectiveId).toBeUndefined();
    expect(layer.nodes.find((n) => n.id === 'n-pc')!.parentId).toBeUndefined();
    expect(layer.edges).toEqual([]);
    expect(layer.annotations![0].targetNodeId).toBeUndefined();
    expect(layer.annotations!).toHaveLength(1);
  });

  it('delete_node：エッジの authProviderId（発行元）だけを消した場合は解除される', () => {
    const { project } = apply([{ op: 'delete_node', id: 'n-idp' }]);
    expect(l1(project).edges.find((e) => e.id === 'e-1')!.authProviderId).toBeUndefined();
    expect(l1(project).nodes.find((n) => n.id === 'n-llm')!.authProviderId).toBeUndefined();
  });
});

describe('正常系：エッジ', () => {
  it('add_edge / update_edge / delete_edge', () => {
    const { project, results } = apply([
      { op: 'add_edge', source: 'n-db', target: 'n-llm', auth: 'MFA', network: 'VPN', encryption: 'E2EE', semantic: 'rag_retrieval', dataFlowName: 'query' },
      { op: 'update_edge', id: 'e-2', set: { auth: 'MFA', encryption: 'TLS', dataFlowName: null } },
      { op: 'delete_edge', id: 'e-1' },
    ]);
    const layer = l1(project);
    const added = layer.edges.find((e) => e.id === results[0].id)!;
    expect(added).toMatchObject({ seq: 3, dataFlow: 'outbound', semantic: 'rag_retrieval', dataFlowName: 'query' });
    expect(layer.edges.find((e) => e.id === 'e-2')).toMatchObject({ auth: 'MFA', encryption: 'TLS' });
    expect(layer.edges.some((e) => e.id === 'e-1')).toBe(false);
    expect(project.idCounters!.L1.edge).toBe(3);
  });

  it('add_edge：自己ループ・発行元に不適切な型は拒否', () => {
    const base = { op: 'add_edge', auth: 'None', network: 'VPC', encryption: 'TLS' };
    expect(reasonOf(() => apply([{ ...base, source: 'n-db', target: 'n-db' }])).reason).toMatch(/同じノード/);
    expect(
      reasonOf(() => apply([{ ...base, source: 'n-db', target: 'n-llm', authProviderId: 'n-db' }])).reason,
    ).toMatch(/発行元/);
  });
});

describe('正常系：境界・注釈', () => {
  it('add_boundary（around）：対象ノードを囲む', () => {
    const { project, results } = apply([{ op: 'add_boundary', type: 'RECT', trustLevel: 'Partner', around: ['n-user', 'n-idp'] }]);
    const id = results[0].id!;
    expect(owningIds(project, 'n-user')).toEqual([id]);
    expect(owningIds(project, 'n-idp')).toEqual([id]);
    expect(owningIds(project, 'n-att')).toEqual([]);
    expect(l1(project).boundaries.find((b) => b.id === id)).toMatchObject({ trustLevel: 'Partner', seq: 2 });
    expect(project.idCounters!.L1.boundary).toBe(2);
  });

  it('add_boundary（around）：対象外のノードを巻き込む場合は拒否', () => {
    // n-user(-400,0) と n-att(-400,400) を囲むと n-idp(-400,200) が巻き込まれる
    expect(
      reasonOf(() => apply([{ op: 'add_boundary', type: 'RECT', around: ['n-user', 'n-att'] }])).reason,
    ).toMatch(/n-idp/);
  });

  it('add_boundary：型ごとの既定値・固定の trustLevel・型に合わない属性', () => {
    const { project, results } = apply([
      { op: 'add_boundary', type: 'ROUNDED', macroTrust: 'Public Area' },
      { op: 'add_boundary', type: 'RECT_DASHED' },
      { op: 'add_boundary', type: 'ROUNDED_DASHED' },
    ]);
    const get = (i: number) => l1(project).boundaries.find((b) => b.id === results[i].id)!;
    expect(get(0)).toMatchObject({ trustLevel: 'Internet', macroTrust: 'Public Area' });
    expect(get(1).trustLevel).toBe('Internet');
    expect(get(2)).toMatchObject({ trustLevel: 'Internal', microTrust: 'Production', microSegmentationStatus: '未適用' });
    expect(reasonOf(() => apply([{ op: 'add_boundary', type: 'RECT_DASHED', trustLevel: 'Internal' }])).reason).toMatch(/固定/);
    expect(reasonOf(() => apply([{ op: 'add_boundary', type: 'RECT', vlanId: 10 }])).reason).toMatch(/vlanId/);
  });

  it('update_boundary / delete_boundary', () => {
    const { project } = apply([
      { op: 'update_boundary', id: 'b-1', set: { trustLevel: 'Partner' } },
      { op: 'add_boundary', type: 'BLAST_RADIUS', blastRadiusLabel: 'x' },
    ]);
    expect(l1(project).boundaries.find((b) => b.id === 'b-1')!.trustLevel).toBe('Partner');
    const removed = apply([{ op: 'delete_boundary', id: 'b-1' }]);
    expect(l1(removed.project).boundaries).toEqual([]);
    expect(owningIds(removed.project, 'n-llm')).toEqual([]);
  });

  it('add_annotation：callout は対象ノードにリンクでき、label は対象不可', () => {
    const { project, results } = apply([
      { op: 'add_annotation', kind: 'callout', text: '注意', targetNodeId: 'n-db' },
      { op: 'add_annotation', kind: 'label', text: 'ラベル' },
    ]);
    const a = l1(project).annotations!.find((x) => x.id === results[0].id)!;
    expect(a.targetNodeId).toBe('n-db');
    expect(results[0].id).toMatch(/^ann/);
    expect(l1(project).annotations!).toHaveLength(3);
    expect(
      reasonOf(() => apply([{ op: 'add_annotation', kind: 'label', text: 't', targetNodeId: 'n-db' }])).reason,
    ).toMatch(/callout/);
  });

  it('ref：同一呼び出し内で新規要素を @name で参照できる', () => {
    const { project, results } = apply([
      { op: 'add_node', ref: 'a', type: 'LLM', label: 'A', boundaryId: 'b-1' },
      { op: 'add_node', ref: 'b', type: 'DB', label: 'B' },
      { op: 'add_edge', source: '@a', target: '@b', auth: 'None', network: 'VPC', encryption: 'TLS' },
    ]);
    const edge = l1(project).edges.find((e) => e.id === results[2].id)!;
    expect(edge.source).toBe(results[0].id);
    expect(edge.target).toBe(results[1].id);
    expect(reasonOf(() => apply([{ op: 'delete_node', id: '@nope' }])).reason).toMatch(/ref/);
  });
});

describe('拒否', () => {
  it.each([
    ['x', { op: 'add_node', type: 'LLM', label: 'a', x: 1 }],
    ['y', { op: 'add_node', type: 'LLM', label: 'a', y: 1 }],
    ['id', { op: 'add_node', type: 'LLM', label: 'a', id: 'n1' }],
    ['seq', { op: 'add_node', type: 'LLM', label: 'a', seq: 99 }],
    ['width', { op: 'add_boundary', type: 'RECT', width: 10 }],
    ['height', { op: 'add_boundary', type: 'RECT', height: 10 }],
    ['set.x', { op: 'update_node', id: 'n-db', set: { x: 0 } }],
    ['set.parentId', { op: 'update_node', id: 'n-db', set: { parentId: 'n-user' } }],
    ['set.seq', { op: 'update_node', id: 'n-db', set: { seq: 9 } }],
    ['boundary set.width', { op: 'update_boundary', id: 'b-1', set: { width: 10 } }],
    ['boundary set.x', { op: 'update_boundary', id: 'b-1', set: { x: 10 } }],
    ['edge set.source', { op: 'update_edge', id: 'e-1', set: { source: 'n-db' } }],
    ['annotation x', { op: 'add_annotation', kind: 'label', text: 't', x: 1 }],
  ])('座標・id・seq 等のフィールドは受け付けない: %s', (_name, op) => {
    expect(reasonOf(() => apply([op])).index).toBe(0);
  });

  it('未知のコンポーネント型・存在しない id・不正な列挙値・長すぎる文字列', () => {
    expect(reasonOf(() => apply([{ op: 'add_node', type: 'NO_SUCH_TYPE', label: 'a' }])).reason).toMatch(/未知/);
    expect(reasonOf(() => apply([{ op: 'delete_node', id: 'ghost' }])).reason).toMatch(/存在しません/);
    expect(reasonOf(() => apply([{ op: 'update_edge', id: 'ghost', set: { auth: 'MFA' } }])).reason).toMatch(/存在しません/);
    expect(reasonOf(() => apply([{ op: 'add_node', type: 'LLM', label: 'a', boundaryId: 'ghost' }])).reason).toMatch(/ghost/);
    expect(reasonOf(() => apply([{ op: 'add_edge', source: 'n-db', target: 'ghost', auth: 'None', network: 'VPC', encryption: 'TLS' }])).reason).toMatch(/ghost/);
    expect(reasonOf(() => apply([{ op: 'add_edge', source: 'n-db', target: 'n-llm', auth: 'Bogus', network: 'VPC', encryption: 'TLS' }])).index).toBe(0);
    expect(reasonOf(() => apply([{ op: 'add_node', type: 'LLM', label: 'a'.repeat(201) }])).index).toBe(0);
    expect(reasonOf(() => apply([{ op: 'add_annotation', kind: 'label', text: 'a'.repeat(2001) }])).index).toBe(0);
    expect(reasonOf(() => apply([{ op: 'unknown_op' }])).index).toBe(0);
    expect(reasonOf(() => apply([{ op: 'update_node', id: 'n-db' }])).reason).toMatch(/set か boundaryId/);
  });

  it('原子性：2 件目が失敗したら例外で、何も返らず入力も変わらない', () => {
    const raw = fixture();
    const before = JSON.stringify(raw);
    const err = reasonOf(() =>
      applyOperations(raw, 'L1', [
        { op: 'add_node', type: 'LLM', label: 'ok' },
        { op: 'delete_node', id: 'ghost' },
      ]),
    );
    expect(err.index).toBe(1);
    expect(JSON.stringify(raw)).toBe(before);
  });

  it('巻き込み：境界を広げると境界外のノードを取り込む場合は全体を失敗にする', () => {
    const raw = fixture();
    const nodes = (raw.layers as Raw & { L1: { nodes: unknown[] } }).L1.nodes;
    nodes.push({ id: 'n-below', seq: 7, type: 'LLM', x: 32, y: 220 });
    const err = reasonOf(() =>
      applyOperations(raw, 'L1', [
        { op: 'add_node', type: 'LLM', label: 'A', boundaryId: 'b-1' },
        { op: 'add_node', type: 'LLM', label: 'B', boundaryId: 'b-1' },
        { op: 'add_node', type: 'LLM', label: 'C', boundaryId: 'b-1' },
      ]),
    );
    expect(err.reason).toMatch(/n-below/);
  });

  it('入力が不正なプロジェクト・不正なレイヤー・空/過大な操作列は拒否', () => {
    expect(reasonOf(() => applyOperations({ foo: 1 }, 'L1', [{ op: 'delete_node', id: 'a' }])).index).toBe(-1);
    expect(reasonOf(() => apply([{ op: 'delete_node', id: 'a' }], 'L9' as LayerKey)).index).toBe(-1);
    expect(reasonOf(() => apply([])).index).toBe(-1);
    expect(reasonOf(() => apply(Array.from({ length: 101 }, () => ({ op: 'delete_node', id: 'a' })))).index).toBe(-1);
  });
});

describe('不変条件', () => {
  it('判断系フィールドと対象外レイヤーは JSON.stringify が操作前後で同一', () => {
    const raw = fixture();
    const before = deserializeProject(raw)!;
    const { project } = applyOperations(raw, 'L1', [
      { op: 'add_node', type: 'LLM', label: 'A', boundaryId: 'b-1' },
      { op: 'delete_node', id: 'n-db' },
      { op: 'add_boundary', type: 'RECT', trustLevel: 'Partner', around: ['n-user'] },
      { op: 'add_annotation', kind: 'label', text: 't' },
    ]);
    const pick = (p: typeof before) =>
      JSON.stringify([p.suppressions, p.riskScores, p.controlStatuses, p.manualThreats, p.projectMeta, p.dreadScores, p.disabledLibraryIds, p.activeFramework, p.activeLayer, p.schemaVersion]);
    expect(pick(project)).toBe(pick(before));
    for (const k of ['L0', 'L2', 'L3'] as const) {
      expect(JSON.stringify(project.layers![k])).toBe(JSON.stringify(before.layers![k]));
      expect(project.idCounters![k]).toEqual(before.idCounters![k]);
    }
  });

  it('L0 を対象にしても L1 以降は変わらず、updatedAt は更新される', () => {
    const raw = fixture();
    const before = deserializeProject(raw)!;
    const { project, results } = applyOperations(raw, 'L0', [{ op: 'add_node', type: 'DB', label: 'L0-DB' }]);
    expect(JSON.stringify(project.layers!.L1)).toBe(JSON.stringify(before.layers!.L1));
    expect(project.layers!.L0.nodes).toHaveLength(2);
    expect(project.layers!.L0.nodes.find((n) => n.id === results[0].id)!.seq).toBe(2);
    expect(project.idCounters!.L0.node).toBe(2);
    expect(project.updatedAt).toBeGreaterThan(before.updatedAt);
  });

  it('出力は deserializeProject を通る', () => {
    const { project } = apply([{ op: 'add_node', type: 'LLM', label: 'A', boundaryId: 'b-1' }]);
    expect(deserializeProject(JSON.parse(JSON.stringify(project)))).not.toBeNull();
  });
});
