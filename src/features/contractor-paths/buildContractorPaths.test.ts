import { describe, expect, it } from 'vitest';
import { buildContractorPaths, type ContractorPathsInput } from './buildContractorPaths';
import { contractorPathsToCsv, contractorPathsToJson, contractorPathsToMarkdown } from './contractorPathsOutput';
import {
  EMPTY_PROJECT_META,
  type AuthType,
  type DiagramBoundary,
  type DiagramEdge,
  type DiagramNode,
} from '../../core/model/types';

const NOW = new Date('2026-11-07T00:00:00Z');

const node = (id: string, seq: number, type: string, extra: Partial<DiagramNode> = {}): DiagramNode =>
  ({ id, seq, type, x: 0, y: 0, label: id, ...extra }) as unknown as DiagramNode;
const edge = (id: string, source: string, target: string, auth: AuthType = 'Password'): DiagramEdge => ({
  id,
  source,
  target,
  auth,
  network: 'Internet',
  encryption: 'TLS',
});

const input = (nodes: DiagramNode[], edges: DiagramEdge[], boundaries: DiagramBoundary[] = []): ContractorPathsInput => ({
  threats: [],
  nodes,
  edges,
  boundaries,
  projectMeta: EMPTY_PROJECT_META,
  layer: 'L1',
});

describe('buildContractorPaths', () => {
  it('USER の信頼区分が Contractor → 根拠 userAttr。Employee は拾わない', () => {
    const nodes = [
      node('u1', 1, 'USER', { userTrustAttribute: 'Contractor' }),
      node('u2', 2, 'USER', { userTrustAttribute: 'Employee' }),
      node('app', 3, 'FRONT_END_SERVER'),
    ];
    const r = buildContractorPaths(input(nodes, [edge('e1', 'u1', 'app'), edge('e2', 'u2', 'app')]), NOW);
    expect(r.rows).toHaveLength(1);
    expect(r.rows[0].fromId).toBe('u1');
    expect(r.rows[0].bases).toEqual(['userAttr']);
  });

  it('外部組織 → VPN_GATEWAY → 社内: 接続口を経由する行になり、根拠は externalToGateway と remoteMaintenance', () => {
    const nodes = [node('ext', 1, 'EXTERNAL_ENTITY'), node('vpn', 2, 'VPN_GATEWAY'), node('srv', 3, 'DB')];
    const r = buildContractorPaths(input(nodes, [edge('e1', 'ext', 'vpn'), edge('e2', 'vpn', 'srv')]), NOW);
    expect(r.rows).toHaveLength(1);
    const row = r.rows[0];
    expect([row.fromId, row.viaId, row.toId]).toEqual(['ext', 'vpn', 'srv']);
    expect(row.bases).toEqual(['externalToGateway', 'remoteMaintenance']);
    expect(row.reachableData.map((d) => d.id)).toEqual(['srv']);
  });

  it('インターネット側の利用者端末 → API の GATEWAY は拾わない（会員等の通常の利用）。外部組織からなら拾う', () => {
    const internet: DiagramBoundary = {
      id: 'b1',
      type: 'RECT',
      x: -400,
      y: -400,
      width: 380,
      height: 380,
      trustLevel: 'Internet',
    };
    const nodes = [
      node('phone', 1, 'SMARTPHONE', { x: -300, y: -300 }),
      node('ext', 2, 'EXTERNAL_ENTITY'),
      node('gw', 3, 'GATEWAY', { x: 500, y: 500 }),
      node('api', 4, 'BACKEND_API', { x: 600, y: 600 }),
    ];
    const r = buildContractorPaths(
      input(nodes, [edge('e1', 'phone', 'gw'), edge('e2', 'ext', 'gw'), edge('e3', 'gw', 'api')], [internet]),
      NOW,
    );
    expect(r.rows.map((x) => x.fromId)).toEqual(['ext']);
  });

  it('社内どうしの線は拾わない（外部でも委託先でもない）', () => {
    const nodes = [node('a', 1, 'FRONT_END_SERVER'), node('b', 2, 'BASTION')];
    expect(buildContractorPaths(input(nodes, [edge('e1', 'a', 'b')]), NOW).rows).toHaveLength(0);
  });

  it('未入力の対策は「無し」と同じに数える。入力できない型は対象外', () => {
    const nodes = [
      node('ext', 1, 'EXTERNAL_ENTITY'),
      node('bst', 2, 'GATEWAY', { attackSurface: { hasSourceIpRestriction: true } }),
    ];
    const row = buildContractorPaths(input(nodes, [edge('e1', 'ext', 'bst')]), NOW).rows[0];
    expect(row.sourceIpRestriction).toBe('yes');
    expect(row.remoteAccessRestriction).toBe('unset');
    const unsetCount = [row.sourceIpRestriction, row.remoteAccessRestriction, row.accessLog].filter(
      (s) => s === 'unset' || s === 'no',
    ).length;
    expect(row.weakCount).toBe(unsetCount);
  });

  it('MFA 切り替え順: MFA 相当でない → 到達データ多い → 対策なし多い', () => {
    const nodes = [
      node('ext1', 1, 'EXTERNAL_ENTITY'),
      node('ext2', 2, 'EXTERNAL_ENTITY'),
      node('ext3', 3, 'EXTERNAL_ENTITY'),
      node('vpn', 4, 'VPN_GATEWAY'),
      node('db', 5, 'DB'),
      node('adm', 6, 'ADMIN_CONSOLE'),
    ];
    const edges = [
      edge('e1', 'ext1', 'vpn', 'MFA'),
      edge('e2', 'ext2', 'vpn', 'Password'),
      edge('e3', 'ext3', 'adm', 'Password'),
      edge('e4', 'vpn', 'db'),
    ];
    const rows = buildContractorPaths(input(nodes, edges), NOW).rows;
    expect(rows.map((r) => r.rank)).toEqual(rows.map((_, i) => i + 1));
    // MFA 相当は最後
    expect(rows[rows.length - 1].fromId).toBe('ext1');
    expect(rows[rows.length - 1].mfaEquivalent).toBe(true);
    // 到達できる DB を持つ行が、持たない行より先
    expect(rows[0].reachableData.length).toBeGreaterThan(0);
    expect(rows[0].reasons).toContain('notMfa');
  });

  it('インターネット境界の PC は外部扱い、内部境界の PC は拾わない', () => {
    const boundaries = [
      { id: 'b1', type: 'RECT', x: 0, y: 0, width: 400, height: 400, trustLevel: 'Internal' },
    ] as unknown as DiagramBoundary[];
    const nodes = [
      node('in', 1, 'PC', { x: 10, y: 10 }),
      node('out', 2, 'PC', { x: 500, y: 500 }),
      node('vpn', 3, 'VPN_GATEWAY', { x: 20, y: 20 }),
    ];
    const rows = buildContractorPaths(input(nodes, [edge('e1', 'in', 'vpn'), edge('e2', 'out', 'vpn')], boundaries), NOW).rows;
    expect(rows.map((r) => r.fromId)).toEqual(['out']);
  });

  it('出力: md / csv / json に注記が入り、en でも出る', () => {
    const nodes = [node('ext', 1, 'EXTERNAL_ENTITY'), node('vpn', 2, 'VPN_GATEWAY', { logSinkId: 'siem' }), node('siem', 3, 'SIEM')];
    const p = buildContractorPaths(input(nodes, [edge('e1', 'ext', 'vpn')]), NOW, 'en');
    expect(contractorPathsToMarkdown(p)).toContain('Contractors themselves are not evaluated');
    expect(contractorPathsToMarkdown(p)).toContain('siem');
    expect(contractorPathsToCsv(p).split('\n')[0]).toContain('Contractors');
    expect(JSON.parse(contractorPathsToJson(p)).rows).toHaveLength(1);
    const ja = buildContractorPaths(input(nodes, [edge('e1', 'ext', 'vpn')]), NOW, 'ja');
    expect(contractorPathsToMarkdown(ja)).toContain('確認すべき候補');
  });

  it('該当なしでも注記と案内を出す', () => {
    const p = buildContractorPaths(input([node('a', 1, 'FRONT_END_SERVER')], []), NOW);
    expect(p.rows).toHaveLength(0);
    expect(contractorPathsToMarkdown(p)).toContain('見つかりませんでした');
  });
});
