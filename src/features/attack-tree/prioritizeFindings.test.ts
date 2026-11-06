import { describe, expect, it } from 'vitest';
import { prioritizeFindings, type LayerContext } from './prioritizeFindings';
import type { DiagramEdge, DiagramNode, Finding, Severity } from '../../core/model/types';

function node(id: string, type: string, extra: Partial<DiagramNode> = {}): DiagramNode {
  return { id, type, x: 0, y: 0, ...extra } as DiagramNode;
}

function edge(id: string, source: string, target: string): DiagramEdge {
  return { id, source, target, auth: 'MFA', network: 'VPC', encryption: 'TLS' };
}

function finding(id: string, nodeId: string | undefined, severity: Severity, extra: Partial<Finding> = {}): Finding {
  return {
    id,
    source: { format: 'cyclonedx', product: 'x', importedAt: '2026-11-01T00:00:00Z' },
    externalId: id,
    identifiers: [],
    severity,
    canonicalIds: [],
    ...(nodeId ? { subject: { layer: 'L1', nodeId } } : {}),
    ...extra,
  } as Finding;
}

/** 入口の設定を全部入力した公開サーバー（仮定なし）。 */
const FIRM = { hasGlobalIp: true, hasUserAuthentication: true, hasSourceIpRestriction: true, hasRemoteAccessRestriction: true, hasWafProtection: true };

function ctx(nodes: DiagramNode[], edges: DiagramEdge[]): LayerContext[] {
  return [{ layer: 'L1', nodes, edges, boundaries: [], threats: [] }];
}

const atk = node('atk', 'AGENTIC_ATTACKER');
// web(入口) - mid(DB) - pii(標的)。iso は線なし。
const nodes = [
  atk,
  node('web', 'FRONT_END_SERVER', { attackSurface: FIRM }),
  node('mid', 'DB'),
  node('pii', 'PERSONAL_INFO'),
  node('iso', 'DB'),
];
const edges = [edge('e1', 'web', 'mid'), edge('e2', 'mid', 'pii')];

const byId = (r: ReturnType<typeof prioritizeFindings>, id: string) => r.items.find((i) => i.finding.id === id)!;

describe('prioritizeFindings', () => {
  it('入口のノードで標的に届く指摘は entry・P1。標的までのホップ数を持つ', () => {
    const r = prioritizeFindings(ctx(nodes, edges), [finding('f', 'web', 'Low')]);
    expect(byId(r, 'f')).toMatchObject({ exposure: 'entry', exposureAssumed: false, priority: 'P1', exploitation: 'unknown' });
    expect(byId(r, 'f').reachesTargets).toEqual([{ nodeId: 'pii', hops: 2 }]);
    expect(r.attackers).toEqual({ L1: 'atk' });
  });

  it('入口の奥で標的に届く指摘は reachable・P2。別の入口にしか繋がらず標的に届かなければ P3', () => {
    const extra = [...nodes, node('web2', 'FRONT_END_SERVER', { attackSurface: FIRM }), node('side', 'DB')];
    const r = prioritizeFindings(ctx(extra, [...edges, edge('e3', 'web2', 'side')]), [
      finding('mid', 'mid', 'Medium'),
      finding('side', 'side', 'Critical'),
      finding('web2', 'web2', 'High'),
    ]);
    expect(byId(r, 'mid')).toMatchObject({ exposure: 'reachable', priority: 'P2' });
    expect(byId(r, 'side')).toMatchObject({ exposure: 'reachable', priority: 'P3', reachesTargets: [] });
    expect(byId(r, 'web2')).toMatchObject({ exposure: 'entry', priority: 'P3', reachesTargets: [] });
  });

  it('図の線が無いノードは unreachable・P4。未結合・消えたノードは unbound・P4', () => {
    const r = prioritizeFindings(ctx(nodes, edges), [
      finding('iso', 'iso', 'Critical'),
      finding('none', undefined, 'High'),
      finding('gone', 'ghost', 'High'),
    ]);
    expect(byId(r, 'iso')).toMatchObject({ exposure: 'unreachable', priority: 'P4' });
    expect(byId(r, 'none')).toMatchObject({ exposure: 'unbound', priority: 'P4' });
    expect(byId(r, 'gone')).toMatchObject({ exposure: 'unbound', priority: 'P4' });
  });

  it('入口の判定が未入力の攻撃面属性に依存すると exposureAssumed の印が付き、そこから到達するノードにも付く', () => {
    const open = [atk, node('web', 'FRONT_END_SERVER'), node('mid', 'DB'), node('pii', 'PERSONAL_INFO')];
    const r = prioritizeFindings(ctx(open, edges), [finding('w', 'web', 'Low'), finding('m', 'mid', 'Low')]);
    expect(byId(r, 'w')).toMatchObject({ exposure: 'entry', exposureAssumed: true });
    expect(byId(r, 'm')).toMatchObject({ exposure: 'reachable', exposureAssumed: true });
  });

  it('KEV の印があれば exploitation: active で、到達できない指摘でも P1', () => {
    const r = prioritizeFindings(ctx(nodes, edges), [
      finding('k', 'iso', 'Low', { kev: { dateAdded: '2026-01-01' } }),
      finding('n', 'iso', 'Low'),
    ]);
    expect(byId(r, 'k')).toMatchObject({ exploitation: 'active', exposure: 'unreachable', priority: 'P1' });
    expect(byId(r, 'n').priority).toBe('P4');
  });

  it('入口と奥の指摘が同じ経路に並ぶと連鎖になり、Medium 以下だけなら強調の対象になる', () => {
    // web は標的に届くので Low でも P1。奥の mid は連鎖で P2 以上。
    const r = prioritizeFindings(ctx(nodes, edges), [finding('a', 'web', 'Medium'), finding('b', 'mid', 'Low')]);
    expect(r.chains).toHaveLength(1);
    expect(r.chains[0]).toMatchObject({ targetId: 'pii', nodeIds: ['web', 'mid'], allMediumOrBelow: true });
    expect(byId(r, 'b').chainIndexes).toEqual([0]);
    expect(byId(r, 'b').priority).toBe('P2');

    const high = prioritizeFindings(ctx(nodes, edges), [finding('a', 'web', 'High'), finding('b', 'mid', 'Low')]);
    expect(high.chains[0].allMediumOrBelow).toBe(false);
  });

  it('同じ段の中は深刻度 → ホップ数の順に並ぶ', () => {
    const r = prioritizeFindings(ctx(nodes, edges), [
      finding('low', 'web', 'Low'),
      finding('crit', 'web', 'Critical'),
      finding('p4', 'iso', 'Critical'),
    ]);
    expect(r.items.map((i) => i.finding.id)).toEqual(['crit', 'low', 'p4']);
  });

  it('攻撃者が図に無ければ全件 unevaluated（KEV の印があれば P1）。--attacker で他のノードを指定すると評価しない', () => {
    const noAtk = nodes.filter((n) => n.id !== 'atk');
    const r = prioritizeFindings(ctx(noAtk, edges), [finding('a', 'web', 'High'), finding('k', 'web', 'Low', { kev: {} })]);
    expect(r.attackers).toEqual({});
    expect(byId(r, 'a')).toMatchObject({ exposure: 'unevaluated', priority: 'P4' });
    expect(byId(r, 'k')).toMatchObject({ exposure: 'unevaluated', priority: 'P1' });

    const wrong = prioritizeFindings(ctx(nodes, edges), [finding('a', 'web', 'High')], 'web');
    expect(byId(wrong, 'a').exposure).toBe('unevaluated');
  });
});
