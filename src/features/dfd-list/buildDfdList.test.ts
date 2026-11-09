import { describe, expect, it } from 'vitest';
import { buildDfdList, sortDfdFlows, type DfdFlowRow } from './buildDfdList';
import type { DiagramEdge, DiagramNode, LayerData } from '../../core/model/types';

function layer(nodes: DiagramNode[], edges: DiagramEdge[] = []): LayerData {
  return {
    nodes,
    edges,
    boundaries: [
      { id: 'b-out', seq: 1, type: 'RECT', x: 0, y: 0, width: 1000, height: 1000, trustLevel: 'Internal', label: 'データ管理領域' },
      { id: 'b-in', seq: 2, type: 'RECT', x: 0, y: 0, width: 300, height: 300, trustLevel: 'Internal', label: 'DB 区画' },
    ],
    annotations: [],
  };
}

const edge = (extra: Partial<DiagramEdge>): DiagramEdge => ({
  id: 'e1', source: 'n-app', target: 'n-db', auth: 'Password', network: 'VPC', encryption: 'TLS', ...extra,
});

const nodes: DiagramNode[] = [
  { id: 'n-db', seq: 2, type: 'DATABASE', x: 100, y: 100, label: 'D1 ユーザーDB', description: ' 管理主体：DB管理者 ' },
  { id: 'n-app', seq: 1, type: 'BACKEND_API', x: 2000, y: 2000, label: 'P3 ユーザー登録' },
  { id: 'n-pii', seq: 3, type: 'PERSONAL_INFO', x: 100, y: 100, parentId: 'n-db', label: '利用者属性' },
];

describe('buildDfdList', () => {
  it('構成要素：採番順に並べ、境界は内側から、親と内包を名前つきで返す', () => {
    const { components } = buildDfdList(layer(nodes));
    expect(components.map((c) => c.displayId)).toEqual(['C1', 'C2', 'C3']);
    const db = components[1];
    expect(db).toMatchObject({ name: 'D1 ユーザーDB', description: '管理主体：DB管理者', type: 'DATABASE' });
    expect(db.zones.map((z) => z.displayId)).toEqual(['Z2', 'Z1']);
    expect(db.contains).toEqual([{ displayId: 'C3', name: '利用者属性' }]);
    expect(components[2].parent).toEqual({ displayId: 'C2', name: 'D1 ユーザーDB' });
    expect(components[0].zones).toEqual([]);
  });

  it('データフロー：名前・プロトコル・説明・認証等をそのまま返す', () => {
    const { flows } = buildDfdList(
      layer(nodes, [edge({ seq: 4, dataFlowName: 'F4 登録データ', protocol: 'db_sql', description: '同期・書込み' })]),
    );
    expect(flows[0]).toMatchObject({
      displayId: 'DF4',
      name: 'F4 登録データ',
      from: { displayId: 'C1', name: 'P3 ユーザー登録' },
      to: { displayId: 'C2', name: 'D1 ユーザーDB' },
      bidirectional: false,
      protocol: 'db_sql',
      network: 'VPC',
      auth: 'Password',
      encryption: 'TLS',
      description: '同期・書込み',
    });
  });

  it('データフロー：inbound は送信元と送信先を入れ替え、bidirectional は印を立てる', () => {
    const [inbound] = buildDfdList(layer(nodes, [edge({ dataFlow: 'inbound' })])).flows;
    expect(inbound.from.displayId).toBe('C2');
    expect(inbound.to.displayId).toBe('C1');
    const [both] = buildDfdList(layer(nodes, [edge({ dataFlow: 'bidirectional' })])).flows;
    expect(both).toMatchObject({ bidirectional: true, from: { displayId: 'C1' } });
  });

  it('データフロー：未設定の名前・説明は空文字、プロトコルは持たない', () => {
    const [f] = buildDfdList(layer(nodes, [edge({})])).flows;
    expect(f.name).toBe('');
    expect(f.description).toBe('');
    expect(f.protocol).toBeUndefined();
    expect(f.displayId).toBe('e1');
  });
});

describe('sortDfdFlows', () => {
  const row = (displayId: string, from: string, to: string, extra: Partial<DfdFlowRow> = {}): DfdFlowRow => ({
    id: displayId, displayId, name: '', from: { displayId: from, name: '' }, to: { displayId: to, name: '' },
    bidirectional: false, network: 'VPC', auth: 'None', encryption: 'TLS', description: '', ...extra,
  });
  const rows = [
    row('DF10', 'C2', 'C1', { protocol: 'db_sql' }),
    row('DF2', 'C10', 'C3'),
    row('DF1', 'C1', 'C2', { protocol: 'http_rest' }),
  ];
  const label = (p: string) => ({ db_sql: 'DB 接続（SQL）', http_rest: 'HTTP（REST）' })[p] ?? p;

  it('id：番号順（DF2 < DF10）で昇順・降順に並べ、元の配列は変えない', () => {
    expect(sortDfdFlows(rows, 'id', 'asc', label).map((r) => r.displayId)).toEqual(['DF1', 'DF2', 'DF10']);
    expect(sortDfdFlows(rows, 'id', 'desc', label).map((r) => r.displayId)).toEqual(['DF10', 'DF2', 'DF1']);
    expect(rows[0].displayId).toBe('DF10');
  });

  it('from / to：表示 ID の番号順で並べる', () => {
    expect(sortDfdFlows(rows, 'from', 'asc', label).map((r) => r.from.displayId)).toEqual(['C1', 'C2', 'C10']);
    expect(sortDfdFlows(rows, 'to', 'desc', label).map((r) => r.to.displayId)).toEqual(['C3', 'C2', 'C1']);
  });

  it('protocol：表示名で比べ、未設定は昇順でも降順でも末尾', () => {
    expect(sortDfdFlows(rows, 'protocol', 'asc', label).map((r) => r.displayId)).toEqual(['DF10', 'DF1', 'DF2']);
    expect(sortDfdFlows(rows, 'protocol', 'desc', label).map((r) => r.displayId)).toEqual(['DF1', 'DF10', 'DF2']);
  });
});
