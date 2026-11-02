import { describe, expect, it } from 'vitest';
import { assessRouteDetection } from './detectionGaps';
import type { DiagramNode } from '../../core/model/types';

function node(id: string, type: string, extra: Partial<DiagramNode> = {}): DiagramNode {
  return { id, type, x: 0, y: 0, ...extra };
}

const atk = node('atk', 'AGENTIC_ATTACKER');
const run = (routeNodeIds: string[], nodes: DiagramNode[], isLogInputAvailable: (n: DiagramNode) => boolean = () => true) =>
  assessRouteDetection({ routeNodeIds, nodes, attackerId: 'atk', isLogInputAvailable });

describe('assessRouteDetection', () => {
  it('全て未入力 → 全 none・assumed true・blind・1 区間', () => {
    const nodes = [atk, node('a', 'FRONT_END_SERVER'), node('b', 'DATABASE')];
    const r = run(['atk', 'a', 'b'], nodes);
    expect(r.nodes).toEqual([
      { nodeId: 'a', state: 'none', assumed: true },
      { nodeId: 'b', state: 'none', assumed: true },
    ]);
    expect(r.gaps).toEqual([['a', 'b']]);
    expect(r.blind).toBe(true);
  });

  it('SIEM への logSinkId → forwarded', () => {
    const nodes = [atk, node('a', 'DATABASE', { logSinkId: 's' }), node('s', 'SIEM')];
    const r = run(['atk', 'a'], nodes);
    expect(r.nodes[0]).toEqual({ nodeId: 'a', state: 'forwarded', assumed: false });
    expect(r.gaps).toEqual([]);
    expect(r.blind).toBe(false);
  });

  it('経路上の SIEM 自身 → forwarded', () => {
    const r = run(['atk', 's'], [atk, node('s', 'SIEM')]);
    expect(r.nodes[0].state).toBe('forwarded');
  });

  it('送信先の宣言は hasAccessLog false・NotCollected より優先する', () => {
    const nodes = [
      atk,
      node('a', 'FRONT_END_SERVER', { logSinkId: 's', attackSurface: { hasAccessLog: false } }),
      node('b', 'DATABASE', { logSinkId: 's', posture: { logCollection: 'NotCollected' } }),
      node('s', 'SIEM'),
    ];
    const r = run(['atk', 'a', 'b'], nodes);
    expect(r.nodes.map((n) => n.state)).toEqual(['forwarded', 'forwarded']);
  });

  it('自分自身や不在ノードを指す logSinkId は forwarded にしない（入力なし扱い）', () => {
    const nodes = [atk, node('a', 'DATABASE', { logSinkId: 'a' }), node('b', 'DATABASE', { logSinkId: 'gone' })];
    const r = run(['atk', 'a', 'b'], nodes);
    expect(r.nodes).toEqual([
      { nodeId: 'a', state: 'none', assumed: true },
      { nodeId: 'b', state: 'none', assumed: true },
    ]);
  });

  it('hasAccessLog true → localOnly で空白に含む', () => {
    const nodes = [atk, node('a', 'FRONT_END_SERVER', { attackSurface: { hasAccessLog: true } })];
    const r = run(['atk', 'a'], nodes);
    expect(r.nodes[0]).toEqual({ nodeId: 'a', state: 'localOnly', assumed: false });
    expect(r.gaps).toEqual([['a']]);
    expect(r.blind).toBe(true);
  });

  it('hasAccessLog false → none・assumed false', () => {
    const r = run(['atk', 'a'], [atk, node('a', 'FRONT_END_SERVER', { attackSurface: { hasAccessLog: false } })]);
    expect(r.nodes[0]).toEqual({ nodeId: 'a', state: 'none', assumed: false });
  });

  it('hasAccessLog を入力できない型（AI_GATEWAY）の値は無視する', () => {
    const nodes = [
      atk,
      node('a', 'AI_GATEWAY', { attackSurface: { hasAccessLog: true } }),
      node('b', 'AI_GATEWAY', { attackSurface: { hasAccessLog: false } }),
    ];
    const r = run(['atk', 'a', 'b'], nodes);
    expect(r.nodes).toEqual([
      { nodeId: 'a', state: 'none', assumed: true },
      { nodeId: 'b', state: 'none', assumed: true },
    ]);
  });

  it('攻撃面を持たない型の hasAccessLog は無視する', () => {
    const r = run(['atk', 'a'], [atk, node('a', 'DATABASE', { attackSurface: { hasAccessLog: true } })]);
    expect(r.nodes[0]).toEqual({ nodeId: 'a', state: 'none', assumed: true });
  });

  it('posture.logCollection: Collected → localOnly、NotCollected → none（assumed false）', () => {
    const nodes = [
      atk,
      node('a', 'DATABASE', { posture: { logCollection: 'Collected' } }),
      node('b', 'DATABASE', { posture: { logCollection: 'NotCollected' } }),
    ];
    const r = run(['atk', 'a', 'b'], nodes);
    expect(r.nodes).toEqual([
      { nodeId: 'a', state: 'localOnly', assumed: false },
      { nodeId: 'b', state: 'none', assumed: false },
    ]);
  });

  it('中央だけ forwarded → 2 区間に分かれ blind でない', () => {
    const nodes = [atk, node('a', 'DATABASE'), node('s', 'SIEM'), node('b', 'DATABASE')];
    const r = run(['atk', 'a', 's', 'b'], nodes);
    expect(r.gaps).toEqual([['a'], ['b']]);
    expect(r.blind).toBe(false);
  });

  it('全 forwarded → gaps 空・blind false', () => {
    const nodes = [atk, node('s1', 'SIEM'), node('s2', 'SIEM')];
    const r = run(['atk', 's1', 's2'], nodes);
    expect(r.gaps).toEqual([]);
    expect(r.blind).toBe(false);
  });

  it('攻撃者は評価対象にしない', () => {
    const r = run(['atk', 'a'], [atk, node('a', 'DATABASE')]);
    expect(r.nodes.map((n) => n.nodeId)).toEqual(['a']);
  });

  it('対象外ノード・図に無いノードは区間を分断しない', () => {
    const nodes = [atk, node('a', 'DATABASE'), node('doc', 'DOCUMENT'), node('b', 'DATABASE')];
    const r = run(['atk', 'a', 'doc', 'missing', 'b'], nodes, (n) => n.type !== 'DOCUMENT');
    expect(r.nodes.map((n) => n.nodeId)).toEqual(['a', 'b']);
    expect(r.gaps).toEqual([['a', 'b']]);
  });

  it('SHADOW は対象外判定に関わらず none・assumed false', () => {
    const nodes = [atk, node('sh', 'SHADOW'), node('sa', 'SHADOW_APP')];
    const r = run(['atk', 'sh', 'sa'], nodes, () => false);
    expect(r.nodes).toEqual([
      { nodeId: 'sh', state: 'none', assumed: false },
      { nodeId: 'sa', state: 'none', assumed: false },
    ]);
  });

  it('評価対象 0 件 → nodes 空・gaps 空・blind false', () => {
    const r = run(['atk'], [atk]);
    expect(r).toEqual({ nodes: [], gaps: [], blind: false });
  });
});
