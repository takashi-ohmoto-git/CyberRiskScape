import { describe, expect, it } from 'vitest';
import { enumeratePaths } from './enumeratePaths';
import type { DiagramEdge, DiagramNode } from '../model/types';

const node = (id: string): DiagramNode => ({ id, type: 'PROCESS', x: 0, y: 0 });
const edge = (id: string, source: string, target: string, extra: Partial<DiagramEdge> = {}) =>
  ({
    id,
    source,
    target,
    auth: 'None',
    network: 'VPC',
    encryption: 'TLS',
    ...extra,
  }) as DiagramEdge;

const abc = [node('a'), node('b'), node('c')];

describe('enumeratePaths', () => {
  it('無向では逆向きの edge も辿る', () => {
    const edges = [edge('e1', 'b', 'a'), edge('e2', 'c', 'b')];
    const r = enumeratePaths(abc, edges, 'a', 'c');
    expect(r.paths).toEqual([{ nodeIds: ['a', 'b', 'c'], edgeIds: ['e1', 'e2'] }]);
  });

  it('有向では逆向きの edge を辿らない', () => {
    const edges = [edge('e1', 'b', 'a'), edge('e2', 'c', 'b')];
    expect(enumeratePaths(abc, edges, 'a', 'c', { directed: true }).paths).toEqual([]);
    expect(enumeratePaths(abc, edges, 'c', 'a', { directed: true }).paths).toHaveLength(1);
  });

  it('有向でも bidirectional の edge は両方向に辿る', () => {
    const edges = [edge('e1', 'b', 'a', { dataFlow: 'bidirectional' }), edge('e2', 'b', 'c')];
    expect(enumeratePaths(abc, edges, 'a', 'c', { directed: true }).paths).toHaveLength(1);
    // bidirectional でなければ a→b は通れない
    const plain = [edge('e1', 'b', 'a'), edge('e2', 'b', 'c')];
    expect(enumeratePaths(abc, plain, 'a', 'c', { directed: true }).paths).toHaveLength(0);
  });

  it('dangling edge は無視する', () => {
    const edges = [edge('e1', 'a', 'x'), edge('e2', 'x', 'c'), edge('e3', 'a', 'c')];
    const r = enumeratePaths(abc, edges, 'a', 'c');
    expect(r.paths).toEqual([{ nodeIds: ['a', 'c'], edgeIds: ['e3'] }]);
  });

  it('並行 edge は別パスになる', () => {
    const edges = [edge('e1', 'a', 'b'), edge('e2', 'a', 'b'), edge('e3', 'b', 'c')];
    const r = enumeratePaths(abc, edges, 'a', 'c');
    expect(r.paths.map((p) => p.edgeIds)).toEqual([
      ['e1', 'e3'],
      ['e2', 'e3'],
    ]);
  });

  it('maxPaths / maxLength を超えると truncated', () => {
    const mids = ['m1', 'm2', 'm3'].map(node);
    const nodes = [node('a'), ...mids, node('z')];
    const edges = mids.flatMap((m) => [edge(`i${m.id}`, 'a', m.id), edge(`o${m.id}`, m.id, 'z')]);
    const r = enumeratePaths(nodes, edges, 'a', 'z', { maxPaths: 2 });
    expect(r.paths).toHaveLength(2);
    expect(r.truncated).toBe(true);
    const long = enumeratePaths(abc, [edge('e1', 'a', 'b'), edge('e2', 'b', 'c')], 'a', 'c', {
      maxLength: 1,
    });
    expect(long.paths).toEqual([]);
    expect(long.truncated).toBe(true);
  });

  it('始点・終点が存在しない、または同一なら空', () => {
    expect(enumeratePaths(abc, [], 'a', 'a').paths).toEqual([]);
    expect(enumeratePaths(abc, [], 'a', 'zz').paths).toEqual([]);
  });
});
