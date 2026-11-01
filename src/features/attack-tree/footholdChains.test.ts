import { describe, expect, it } from 'vitest';
import { BUNDLED_FOOTHOLD_MAP, findFootholdChains, loadFootholdMap } from './footholdChains';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';
import type { DiagramBoundary, DiagramEdge, DiagramNode, ThreatView } from '../../core/model/types';

function node(id: string, type: string, extra: Partial<DiagramNode> = {}): DiagramNode {
  return { id, type, x: 0, y: 0, ...extra };
}

function edge(id: string, source: string, target: string): DiagramEdge {
  return { id, source, target, auth: 'None', network: 'Internet', encryption: 'TLS' };
}

function boundary(id: string, trustLevel: DiagramBoundary['trustLevel'], x: number): DiagramBoundary {
  return { id, type: 'ROUNDED', x, y: -100, width: 500, height: 500, trustLevel } as DiagramBoundary;
}

function threat(nodeId: string, canonicalId: string, extra: Partial<ThreatView> = {}): ThreatView {
  return {
    id: `${canonicalId}-${nodeId}`,
    origin: 'detected',
    nodeId,
    subject: { kind: 'node', id: nodeId },
    canonicalId,
    framework: 'STRIDE',
    category: 'Information Disclosure',
    name: canonicalId,
    severity: 'Medium',
    description: 'd',
    ...extra,
  } as ThreatView;
}

// 攻撃者（Internet、x=-1000）→ Web・API・管理画面（同じサイト、x=0..500）→ DB
const attacker = node('atk', 'AGENTIC_ATTACKER', { x: -900 });
const web = node('web', 'FRONT_END_SERVER', { x: 50 });
const api = node('api', 'BACKEND_API', { x: 100 });
const adm = node('adm', 'ADMIN_CONSOLE', { x: 150 });
const db = node('db', 'DATABASE', { x: 200 });
const other = node('other', 'FRONT_END_SERVER', { x: 2050 });
const nodes = [attacker, web, api, adm, db, other];
const boundaries = [boundary('inet', 'Internet', -1000), boundary('site', 'Internal', 0), boundary('far', 'Internal', 2000)];
const edges = [edge('e1', 'atk', 'web'), edge('e2', 'atk', 'api'), edge('e3', 'atk', 'adm'), edge('e4', 'api', 'db'), edge('e5', 'adm', 'db')];
const routeNodeIds = ['atk', 'api', 'adm', 'db'];
const run = (threats: ThreatView[], extra: { edges?: DiagramEdge[]; nodes?: DiagramNode[] } = {}) =>
  findFootholdChains({
    nodes: extra.nodes ?? nodes,
    edges: extra.edges ?? edges,
    boundaries,
    threats,
    attackerId: 'atk',
    routeNodeIds,
  });

describe('findFootholdChains', () => {
  it('経路外のノードの手がかりでも、同じゾーンの経路上のノードを弱めるものとして返す', () => {
    const [link] = run([threat('web', 'web-public-dir-sensitive-file-exposure')]);
    expect(link).toMatchObject({ sourceNodeId: 'web', yields: ['credential', 'path'] });
    expect(link.affectedNodeIds.sort()).toEqual(['adm', 'api', 'db']);
  });

  it('対応表に無い canonicalId・受容した脅威は数えない', () => {
    expect(run([threat('web', 'web-shell-implant')])).toEqual([]);
    const accepted = threat('web', 'credential-sprawl', { suppression: { status: 'accepted', at: 0 } });
    expect(run([accepted])).toEqual([]);
  });

  it('攻撃者から線で届かないノード・別ゾーンで経路上のノードが無いものは返さない', () => {
    // 線を外すと web は届かない
    expect(run([threat('web', 'credential-sprawl')], { edges: edges.filter((e) => e.id !== 'e1') })).toEqual([]);
    // 別ゾーンのノードは届いても、同じゾーンの経路上のノードが無い
    expect(run([threat('other', 'credential-sprawl')], { edges: [...edges, edge('e6', 'atk', 'other')] })).toEqual([]);
  });

  it('子ノード（バックアップの中の認証材料）は親が届けば届くとみなす', () => {
    const cred = node('cred', 'CREDENTIAL', { x: 60, parentId: 'web' });
    const [link] = run([threat('cred', 'credential-sprawl')], { nodes: [...nodes, cred] });
    expect(link.sourceNodeId).toBe('cred');
    expect(link.affectedNodeIds.sort()).toEqual(['adm', 'api', 'db']);
  });

  it('ゾーンに入っていないノードは自分自身が経路上にあるときだけ返す', () => {
    const lone = node('lone', 'ADMIN_CONSOLE', { x: -5000 });
    const r = findFootholdChains({
      nodes: [attacker, lone],
      edges: [edge('e1', 'atk', 'lone')],
      boundaries: [],
      threats: [threat('lone', 'web-content-credential-hint')],
      attackerId: 'atk',
      routeNodeIds: ['atk', 'lone'],
    });
    expect(r.map((l) => l.affectedNodeIds)).toEqual([['lone']]);
  });
});

describe('loadFootholdMap', () => {
  it('同じ canonicalId を 2 回書くとエラー', () => {
    const yaml = 'schemaVersion: 1\nfootholds:\n  - canonicalId: a\n    yields: [hint]\n  - canonicalId: a\n    yields: [path]\n';
    expect(() => loadFootholdMap(yaml)).toThrow(/複数回/);
  });

  it('同梱の対応表の canonicalId はすべて脅威ライブラリに存在する', () => {
    const known = new Set(BUNDLED_THREAT_LIBRARY.rules.map((r) => r.canonicalId));
    const missing = [...BUNDLED_FOOTHOLD_MAP.keys()].filter((id) => !known.has(id));
    expect(BUNDLED_FOOTHOLD_MAP.size).toBeGreaterThan(0);
    expect(missing).toEqual([]);
  });
});
