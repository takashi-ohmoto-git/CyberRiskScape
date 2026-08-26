import { describe, expect, it } from 'vitest';
import { buildAttackGraph } from './buildAttackGraph';
import { MAX_PATHS } from './buildAttackGraph';
import type { DiagramEdge, DiagramNode } from '../../core/model/types';

function node(id: string, type = 'PROCESS'): DiagramNode {
  return { id, type, x: 0, y: 0 };
}

function edge(id: string, source: string, target: string): DiagramEdge {
  return { id, source, target, auth: 'None', network: 'Internet', encryption: 'Plain' };
}

describe('buildAttackGraph', () => {
  it('単純な一本鎖 A→B→C を 1 経路・2 ホップとして返す', () => {
    const r = buildAttackGraph(
      [node('a'), node('b'), node('c')],
      [edge('e1', 'a', 'b'), edge('e2', 'b', 'c')],
      'a',
      'c',
    );
    expect(r.routes).toHaveLength(1);
    expect(r.routes[0]).toMatchObject({ nodeIds: ['a', 'b', 'c'], hopKeys: ['a--b', 'b--c'] });
    expect(r.hops.size).toBe(2);
    expect(r.channelCombinations).toBe(1);
    expect(r.truncated).toBe(false);
  });

  it('並行エッジは 1 本の経路・論理ホップへ畳み込まれる（チャネル組合せは 4）', () => {
    // A-B 間に 2 本（df1, df4）、B-C 間に 2 本（df2, df3）
    const r = buildAttackGraph(
      [node('a'), node('b'), node('c')],
      [
        edge('df1', 'a', 'b'),
        edge('df4', 'a', 'b'),
        edge('df2', 'b', 'c'),
        edge('df3', 'b', 'c'),
      ],
      'a',
      'c',
    );
    expect(r.routes).toHaveLength(1);
    expect(r.channelCombinations).toBe(4);
    expect(r.hops.size).toBe(2);
    const hopAB = r.hops.get('a--b');
    const hopBC = r.hops.get('b--c');
    expect(hopAB?.edgeIds).toHaveLength(2);
    expect(hopAB?.edgeIds.sort()).toEqual(['df1', 'df4']);
    expect(hopBC?.edgeIds).toHaveLength(2);
    expect(hopBC?.edgeIds.sort()).toEqual(['df2', 'df3']);
  });

  it('真に異なる 2 経路（A→B→D, A→C→D）を別経路として返す', () => {
    const r = buildAttackGraph(
      [node('a'), node('b'), node('c'), node('d')],
      [
        edge('e1', 'a', 'b'),
        edge('e2', 'b', 'd'),
        edge('e3', 'a', 'c'),
        edge('e4', 'c', 'd'),
      ],
      'a',
      'd',
    );
    expect(r.routes).toHaveLength(2);
    expect(r.channelCombinations).toBe(2);
    const nodeSeqs = r.routes.map((route) => route.nodeIds.join('->')).sort();
    expect(nodeSeqs).toEqual(['a->b->d', 'a->c->d']);
  });

  it('エッジ向きが target→source 定義でも辿れる（無向探索）', () => {
    const r = buildAttackGraph([node('a'), node('b')], [edge('e1', 'b', 'a')], 'a', 'b');
    expect(r.routes).toHaveLength(1);
    expect(r.routes[0].nodeIds).toEqual(['a', 'b']);
  });

  it('攻撃者/標的が存在しない、または同一のときは空結果', () => {
    const nodes = [node('a'), node('b')];
    const edges = [edge('e1', 'a', 'b')];
    expect(buildAttackGraph(nodes, edges, 'a', 'missing')).toEqual({
      nodeIds: [],
      hops: new Map(),
      routes: [],
      channelCombinations: 0,
      truncated: false,
    });
    expect(buildAttackGraph(nodes, edges, 'missing', 'b')).toEqual({
      nodeIds: [],
      hops: new Map(),
      routes: [],
      channelCombinations: 0,
      truncated: false,
    });
    expect(buildAttackGraph(nodes, edges, 'a', 'a')).toEqual({
      nodeIds: [],
      hops: new Map(),
      routes: [],
      channelCombinations: 0,
      truncated: false,
    });
  });

  it('dangling エッジ（存在しないノードを指す）は無視する', () => {
    const r = buildAttackGraph(
      [node('a'), node('b')],
      [edge('e1', 'a', 'b'), edge('e2', 'a', 'ghost')],
      'a',
      'b',
    );
    expect(r.routes).toHaveLength(1);
    expect(r.hops.size).toBe(1);
  });

  it('パス数が上限を超えると truncated を立てる', () => {
    const mids = Array.from({ length: MAX_PATHS + 10 }, (_, i) => `m${i}`);
    const nodes = [node('a'), node('t'), ...mids.map((m) => node(m))];
    const edges = mids.flatMap((m, i) => [edge(`ea${i}`, 'a', m), edge(`eb${i}`, m, 't')]);
    const r = buildAttackGraph(nodes, edges, 'a', 't');
    expect(r.channelCombinations).toBe(MAX_PATHS);
    expect(r.truncated).toBe(true);
  });

  it('hop key は a/b の順序が入れ替わっても同一 key に畳み込まれる', () => {
    const r = buildAttackGraph(
      [node('a'), node('b')],
      [edge('e1', 'a', 'b')],
      'a',
      'b',
    );
    const hop = r.hops.get('a--b');
    expect(hop).toBeDefined();
    expect(hop?.a).toBe('a');
    expect(hop?.b).toBe('b');
    // 逆向き定義でも同じ key へ畳み込まれることを確認
    const r2 = buildAttackGraph([node('b'), node('a')], [edge('e1', 'b', 'a')], 'b', 'a');
    expect(r2.hops.has('a--b')).toBe(true);
  });
});
