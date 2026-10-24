import { describe, expect, it } from 'vitest';
import { buildEntryEdges, findEntryPoints, isEntryEdgeId } from './findEntryPoints';
import type { DiagramBoundary, DiagramEdge, DiagramNode, ThreatView } from '../../core/model/types';

function node(id: string, type: string, extra: Partial<DiagramNode> = {}): DiagramNode {
  return { id, type, x: 0, y: 0, ...extra };
}

function edge(id: string, source: string, target: string, extra: Partial<DiagramEdge> = {}): DiagramEdge {
  return { id, source, target, auth: 'MFA', network: 'VPC', encryption: 'TLS', ...extra };
}

function boundary(id: string, trustLevel: DiagramBoundary['trustLevel'], x: number): DiagramBoundary {
  return { id, type: 'RECT', x, y: -100, width: 500, height: 500, trustLevel } as DiagramBoundary;
}

function threat(nodeId: string, severity: ThreatView['severity'], extra: Partial<ThreatView> = {}): ThreatView {
  return { id: `${nodeId}-${severity}`, origin: 'detected', nodeId, framework: 'STRIDE', category: 'c', severity, description: 'd', ...extra } as ThreatView;
}

const attacker = node('atk', 'AGENTIC_ATTACKER');
const ids = (r: ReturnType<typeof findEntryPoints>) => r.map((c) => c.nodeId);

describe('findEntryPoints', () => {
  it('公開サーバー型は Global IP が未入力でも「あり」と仮定して候補にし、未入力の防御策を弱点に数える', () => {
    const [web] = findEntryPoints([attacker, node('web', 'FRONT_END_SERVER')], [], [], [], 'atk');
    expect(web).toMatchObject({ nodeId: 'web', rank: 1, reasons: ['publicSurface'], assumed: true });
    expect(web.weaknesses).toEqual(['noUserAuth', 'noSourceIpRestriction', 'noRemoteAccessRestriction', 'noWaf']);
  });

  it('Global IP なしと明示した公開サーバー型は候補にしない。防御策を入力すれば弱点と仮定の印が消える', () => {
    const r = findEntryPoints(
      [
        attacker,
        node('closed', 'GATEWAY', { attackSurface: { hasGlobalIp: false } }),
        node('hardened', 'GATEWAY', {
          attackSurface: {
            hasGlobalIp: true,
            hasUserAuthentication: true,
            hasSourceIpRestriction: true,
            hasRemoteAccessRestriction: true,
            hasWafProtection: true,
          },
        }),
      ],
      [],
      [],
      [],
      'atk',
    );
    expect(ids(r)).toEqual(['hardened']);
    expect(r[0]).toMatchObject({ weaknesses: [], assumed: false });
  });

  it('インターネット経由のエッジは受ける側だけを候補にする（dataFlow で判定）', () => {
    const r = findEntryPoints(
      [attacker, node('app', 'PROCESS'), node('saas', 'SAAS'), node('vpn', 'PROCESS')],
      [
        // app → saas の outbound：受けるのは saas
        edge('e1', 'app', 'saas', { network: 'Internet' }),
        // 外 → vpn を inbound で表した線（source 側の vpn が受ける）、認証なし
        edge('e2', 'vpn', 'app', { network: 'Internet', dataFlow: 'inbound', auth: 'None' }),
      ],
      [],
      [],
      'atk',
    );
    expect(ids(r).sort()).toEqual(['saas', 'vpn']);
    expect(r.find((c) => c.nodeId === 'vpn')?.weaknesses).toEqual(['unauthenticatedEdge']);
  });

  it('宣言されたインターネット境界の中は候補にし、どの境界にも属さないノードは候補にしない', () => {
    const r = findEntryPoints(
      [attacker, node('cloud', 'SAAS', { x: 10, y: 10 }), node('dc', 'DB', { x: 1000, y: 10 }), node('loose', 'DB', { x: 3000, y: 10 })],
      [],
      [boundary('z1', 'Internet', -100), boundary('z2', 'Internal', 900)],
      [],
      'atk',
    );
    expect(ids(r)).toEqual(['cloud']);
    expect(r[0].reasons).toEqual(['internetZone']);
  });

  it('攻撃者から線が引かれているノードは候補にする。利用者・端末・攻撃者・内包されたデータ資産は候補にしない', () => {
    const r = findEntryPoints(
      [
        attacker,
        node('db', 'DB'),
        node('pii', 'PERSONAL_INFO', { parentId: 'db' }),
        node('user', 'USER'),
        node('other', 'THREAT_ACTOR'),
      ],
      [edge('e1', 'atk', 'db'), edge('e2', 'atk', 'pii'), edge('e3', 'atk', 'user', { network: 'Internet' })],
      [],
      [],
      'atk',
    );
    expect(ids(r)).toEqual(['db']);
    expect(r[0].reasons).toEqual(['attackerEdge']);
  });

  it('順位は弱点の数 → 脅威の最大重大度 → 件数。抑制した脅威と内包するデータ資産の脅威の扱い', () => {
    const r = findEntryPoints(
      [
        attacker,
        node('a', 'SAAS', { seq: 1 }),
        node('b', 'SAAS', { seq: 2 }),
        node('c', 'SAAS', { seq: 3 }),
        node('cpii', 'PERSONAL_INFO', { parentId: 'c' }),
        node('web', 'FRONT_END_SERVER', { seq: 9 }),
      ],
      ['a', 'b', 'c'].map((t, i) => edge(`e${i}`, 'x', t, { network: 'Internet' })),
      [],
      [
        threat('a', 'High'),
        threat('b', 'Critical', { suppression: { status: 'accepted' } as never }),
        threat('b', 'Medium'),
        threat('cpii', 'Critical'),
      ],
      'atk',
    );
    // web は弱点 4 つで先頭。c は内包するデータ資産の Critical、a は High、b は抑制分を除いた Medium
    expect(ids(r)).toEqual(['web', 'c', 'a', 'b']);
    expect(r.map((c) => c.rank)).toEqual([1, 2, 3, 4]);
    expect(r.find((c) => c.nodeId === 'b')).toMatchObject({ threatCount: 1, maxSeverity: 'Medium' });
  });

  it('攻撃者が AI エージェント攻撃者でなければ空', () => {
    expect(findEntryPoints([node('t', 'THREAT_ACTOR'), node('web', 'FRONT_END_SERVER')], [], [], [], 't')).toEqual([]);
    expect(findEntryPoints([node('web', 'FRONT_END_SERVER')], [], [], [], 'missing')).toEqual([]);
  });
});

describe('buildEntryEdges', () => {
  it('攻撃者から線の無い入口だけを仮想の線にし、攻撃経路分析で標的まで辿れるようにする', async () => {
    const { buildAttackGraph } = await import('./buildAttackGraph');
    const nodes = [attacker, node('web', 'FRONT_END_SERVER'), node('gw', 'GATEWAY'), node('db', 'DB')];
    const edges = [edge('e1', 'atk', 'gw'), edge('e2', 'web', 'db'), edge('e3', 'gw', 'db')];
    const entryEdges = buildEntryEdges('atk', findEntryPoints(nodes, edges, [], [], 'atk'));

    // gw は攻撃者からの線があるので作らない
    expect(entryEdges.map((e) => [e.id, e.source, e.target])).toEqual([['entry:web', 'atk', 'web']]);
    expect(isEntryEdgeId(entryEdges[0].id)).toBe(true);
    expect(isEntryEdgeId('e1')).toBe(false);

    const before = buildAttackGraph(nodes, edges, 'atk', 'db');
    const after = buildAttackGraph(nodes, [...edges, ...entryEdges], 'atk', 'db');
    expect(before.routes.map((r) => r.nodeIds.join('>'))).toEqual(['atk>gw>db']);
    expect(after.routes.map((r) => r.nodeIds.join('>')).sort()).toEqual(['atk>gw>db', 'atk>web>db']);
  });
});
