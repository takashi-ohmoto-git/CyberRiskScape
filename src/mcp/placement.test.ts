import { describe, expect, it } from 'vitest';
import { boundaryAround, emptyBoundaryRect, placeAnnotation, placeNode, PlacementError } from './placement';
import { resolveNodeBoundaries } from '../core/canvas/boundaryCrossing';
import type { DiagramBoundary, DiagramNode, LayerData } from '../core/model/types';

function boundary(id: string, x: number, y: number, width: number, height: number): DiagramBoundary {
  return { id, type: 'RECT', x, y, width, height, trustLevel: 'Internal' };
}

function node(id: string, x: number, y: number, type = 'LLM'): DiagramNode {
  return { id, type, x, y };
}

function layer(partial: Partial<LayerData>): LayerData {
  return { nodes: [], edges: [], boundaries: [], annotations: [], ...partial };
}

/** 配置結果を反映した後の、新ノードの所属境界 id（内側が先）。 */
function owningAfter(l: LayerData, id: string, type: string, x: number, y: number, expanded?: { height: number }, bid?: string) {
  const boundaries = l.boundaries.map((b) => (b.id === bid && expanded ? { ...b, ...expanded } : b));
  return resolveNodeBoundaries([...l.nodes, node(id, x, y, type)], boundaries)
    .get(id)!
    .map((b) => b.id);
}

describe('placeNode: 境界内', () => {
  it('空き位置が境界の内側に置かれ、最内側の境界がその境界になる', () => {
    const l = layer({ boundaries: [boundary('z', 0, 0, 400, 200)], nodes: [node('a', 32, 32)] });
    const r = placeNode(l, 'DB', 'z');
    expect(r.expandedBoundary).toBeUndefined();
    expect(owningAfter(l, 'new', 'DB', r.x, r.y)).toEqual(['z']);
  });

  it('既存ノードと重ならない', () => {
    const l = layer({ boundaries: [boundary('z', 0, 0, 400, 200)], nodes: [node('a', 32, 32)] });
    const r = placeNode(l, 'LLM', 'z');
    expect(r.x === 32 && r.y === 32).toBe(false);
  });

  it('入れ子の境界では最内側の境界を指定すればそこに入る', () => {
    const l = layer({
      boundaries: [boundary('outer', 0, 0, 800, 600), boundary('inner', 40, 40, 300, 200)],
    });
    const r = placeNode(l, 'LLM', 'inner');
    expect(owningAfter(l, 'new', 'LLM', r.x, r.y, r.expandedBoundary, 'inner')[0]).toBe('inner');
  });

  it('空きが無ければ境界を下へ広げる', () => {
    const l = layer({
      boundaries: [boundary('z', 0, 0, 400, 200)],
      nodes: [node('a', 32, 32), node('b', 192, 32)],
    });
    const r = placeNode(l, 'LLM', 'z');
    expect(r.expandedBoundary).toBeDefined();
    expect(r.expandedBoundary!.height).toBeGreaterThan(200);
    expect(r.expandedBoundary!.x).toBe(0);
    expect(r.expandedBoundary!.width).toBe(400);
    expect(owningAfter(l, 'new', 'LLM', r.x, r.y, r.expandedBoundary, 'z')).toEqual(['z']);
  });

  it('広げると境界に属さない既存ノードを巻き込む場合は拒否する', () => {
    const l = layer({
      boundaries: [boundary('z', 0, 0, 400, 200)],
      nodes: [node('a', 32, 32), node('b', 192, 32), node('outside', 32, 220)],
    });
    expect(() => placeNode(l, 'LLM', 'z')).toThrow(PlacementError);
    expect(() => placeNode(l, 'LLM', 'z')).toThrow(/outside/);
  });

  it('広げると他の境界を巻き込む場合は拒否する', () => {
    const l = layer({
      boundaries: [boundary('z', 0, 0, 400, 200), boundary('other', 50, 210, 100, 60)],
      nodes: [node('a', 32, 32), node('b', 192, 32)],
    });
    expect(() => placeNode(l, 'LLM', 'z')).toThrow(/other/);
  });

  it('存在しない境界は拒否する', () => {
    expect(() => placeNode(layer({}), 'LLM', 'nope')).toThrow(PlacementError);
  });
});

describe('placeNode: 境界の外', () => {
  it('どの境界にも入らず、既存要素の右側に置く', () => {
    const l = layer({ boundaries: [boundary('z', 0, 0, 400, 200)], nodes: [node('a', 32, 32)] });
    const r = placeNode(l, 'LLM', null);
    expect(r.x).toBeGreaterThan(400);
    expect(owningAfter(l, 'new', 'LLM', r.x, r.y)).toEqual([]);
  });

  it('空のレイヤーにも置ける', () => {
    const r = placeNode(layer({}), 'LLM', null);
    expect(Number.isFinite(r.x) && Number.isFinite(r.y)).toBe(true);
  });

  it('ignoreNodeId のノード自身は障害物・範囲に数えない', () => {
    const l = layer({ nodes: [node('a', 0, 0)] });
    const r = placeNode(l, 'LLM', null, 'a');
    expect(r.x).toBeLessThan(200);
  });
});

describe('boundaryAround', () => {
  it('対象ノードの外接矩形＋余白で囲み、対象は境界の内側に入る', () => {
    const l = layer({ nodes: [node('a', 100, 100), node('b', 300, 100), node('far', 2000, 2000)] });
    const rect = boundaryAround(l, ['a', 'b']);
    const b: DiagramBoundary = { id: 'new', type: 'RECT', trustLevel: 'Internal', ...rect };
    const owning = resolveNodeBoundaries(l.nodes, [b]);
    expect(owning.get('a')!.length).toBe(1);
    expect(owning.get('b')!.length).toBe(1);
    expect(owning.get('far')!.length).toBe(0);
  });

  it('対象以外のノードの中心を包含する場合は拒否する', () => {
    const l = layer({ nodes: [node('a', 100, 100), node('b', 500, 100), node('mid', 300, 100)] });
    expect(() => boundaryAround(l, ['a', 'b'])).toThrow(/mid/);
  });

  it('内包された子は対象とみなし、巻き込みにならない', () => {
    const l = layer({
      nodes: [node('u', 100, 100, 'USER'), { ...node('pc', 0, 0, 'PC'), parentId: 'u' }],
    });
    expect(() => boundaryAround(l, ['u'])).not.toThrow();
  });

  it('存在しない id・空配列は拒否する', () => {
    expect(() => boundaryAround(layer({}), ['x'])).toThrow(PlacementError);
    expect(() => boundaryAround(layer({}), [])).toThrow(PlacementError);
  });
});

describe('emptyBoundaryRect / placeAnnotation', () => {
  it('空の境界は既存要素の右側で、ノードを巻き込まない', () => {
    const l = layer({ nodes: [node('a', 0, 0)] });
    const rect = emptyBoundaryRect(l);
    const b: DiagramBoundary = { id: 'new', type: 'RECT', trustLevel: 'Internal', ...rect };
    expect(resolveNodeBoundaries(l.nodes, [b]).get('a')).toEqual([]);
  });

  it('注釈は対象ノードの右隣、無ければ既存要素の下', () => {
    const l = layer({ nodes: [node('a', 0, 0)] });
    expect(placeAnnotation(l, 'a').x).toBeGreaterThan(100);
    expect(placeAnnotation(l).y).toBeGreaterThan(96);
    expect(() => placeAnnotation(l, 'nope')).toThrow(PlacementError);
  });
});
