import { describe, expect, it } from 'vitest';
import { resolveNodeTrust } from './resolveNodeTrust';
import type { DiagramBoundary, DiagramNode } from '../model/types';

describe('resolveNodeTrust', () => {
  it('境界に含まれるノードはその trustLevel を取得する', () => {
    const nodes: DiagramNode[] = [{ id: 'n1', type: 'PROCESS', x: 250, y: 250 }];
    const boundaries: DiagramBoundary[] = [
      { id: 'b1', type: 'RECT', x: 100, y: 100, width: 400, height: 400, trustLevel: 'Partner' },
    ];
    const map = resolveNodeTrust(nodes, boundaries);
    expect(map.get('n1')).toBe('Partner');
  });

  it('どの境界にも属さないノードは Internet になる', () => {
    const nodes: DiagramNode[] = [{ id: 'n1', type: 'PROCESS', x: 1000, y: 1000 }];
    const boundaries: DiagramBoundary[] = [
      { id: 'b1', type: 'RECT', x: 0, y: 0, width: 100, height: 100, trustLevel: 'Internal' },
    ];
    const map = resolveNodeTrust(nodes, boundaries);
    expect(map.get('n1')).toBe('Internet');
  });

  it('境界が一つも無いときは全ノードが Internet', () => {
    const nodes: DiagramNode[] = [
      { id: 'a', type: 'USER', x: 0, y: 0 },
      { id: 'b', type: 'LLM', x: 999, y: 999 },
    ];
    const map = resolveNodeTrust(nodes, []);
    expect(map.get('a')).toBe('Internet');
    expect(map.get('b')).toBe('Internet');
  });

  it('入れ子境界では最内側（面積最小）の trustLevel を採用する', () => {
    // 外側: Internet, 内側: Internal —— 内側のノードは Internal になるべき
    const nodes: DiagramNode[] = [{ id: 'n1', type: 'PROCESS', x: 300, y: 300 }];
    const boundaries: DiagramBoundary[] = [
      { id: 'outer', type: 'RECT', x: 0, y: 0, width: 800, height: 800, trustLevel: 'Internet' },
      { id: 'inner', type: 'RECT', x: 200, y: 200, width: 200, height: 200, trustLevel: 'Internal' },
    ];
    const map = resolveNodeTrust(nodes, boundaries);
    expect(map.get('n1')).toBe('Internal');
  });

  it('入れ子の定義順に依存しない', () => {
    // boundaries を逆順で渡しても結果は同じであるべき
    const nodes: DiagramNode[] = [{ id: 'n1', type: 'PROCESS', x: 300, y: 300 }];
    const boundaries: DiagramBoundary[] = [
      { id: 'inner', type: 'RECT', x: 200, y: 200, width: 200, height: 200, trustLevel: 'Partner' },
      { id: 'outer', type: 'RECT', x: 0, y: 0, width: 800, height: 800, trustLevel: 'Internet' },
    ];
    const map = resolveNodeTrust(nodes, boundaries);
    expect(map.get('n1')).toBe('Partner');
  });

  it('矩形境界上の座標も内側として扱う（包含）', () => {
    const nodes: DiagramNode[] = [
      { id: 'tl', type: 'PROCESS', x: 100, y: 100 }, // 左上角
      { id: 'br', type: 'PROCESS', x: 500, y: 500 }, // 右下角
    ];
    const boundaries: DiagramBoundary[] = [
      { id: 'b1', type: 'RECT', x: 100, y: 100, width: 400, height: 400, trustLevel: 'Internal' },
    ];
    const map = resolveNodeTrust(nodes, boundaries);
    expect(map.get('tl')).toBe('Internal');
    expect(map.get('br')).toBe('Internal');
  });

  it('内包ノード（parentId 持ち）は親の trustLevel を継承する', () => {
    // 親は境界内（Internal）、子の x/y はスタールで境界外（Internet 相当）
    const nodes: DiagramNode[] = [
      { id: 'parent', type: 'DB', x: 250, y: 250 },
      { id: 'child', type: 'PERSONAL_INFO', x: 999, y: 999, parentId: 'parent' },
    ];
    const boundaries: DiagramBoundary[] = [
      { id: 'b1', type: 'RECT', x: 100, y: 100, width: 400, height: 400, trustLevel: 'Internal' },
    ];
    const map = resolveNodeTrust(nodes, boundaries);
    expect(map.get('parent')).toBe('Internal');
    expect(map.get('child')).toBe('Internal');
  });

  it('多段の内包でも最上位の祖先 trustLevel を継承する', () => {
    // USER (in Internal) > PC > LOG。LOG/PC の座標は境界外でも Internal になる。
    const nodes: DiagramNode[] = [
      { id: 'user', type: 'USER', x: 250, y: 250 },
      { id: 'pc', type: 'PC', x: 999, y: 999, parentId: 'user' },
      { id: 'log', type: 'LOG', x: -50, y: -50, parentId: 'pc' },
    ];
    const boundaries: DiagramBoundary[] = [
      { id: 'b1', type: 'RECT', x: 100, y: 100, width: 400, height: 400, trustLevel: 'Internal' },
    ];
    const map = resolveNodeTrust(nodes, boundaries);
    expect(map.get('log')).toBe('Internal');
    expect(map.get('pc')).toBe('Internal');
  });

  it('親が存在しない孤児は自身の座標で判定する', () => {
    const nodes: DiagramNode[] = [
      { id: 'orphan', type: 'LOG', x: 250, y: 250, parentId: 'nonexistent' },
    ];
    const boundaries: DiagramBoundary[] = [
      { id: 'b1', type: 'RECT', x: 100, y: 100, width: 400, height: 400, trustLevel: 'Internal' },
    ];
    const map = resolveNodeTrust(nodes, boundaries);
    expect(map.get('orphan')).toBe('Internal');
  });
});
