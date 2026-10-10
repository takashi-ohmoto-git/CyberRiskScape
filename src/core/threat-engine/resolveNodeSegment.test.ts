import { describe, expect, it } from 'vitest';
import { resolveNodeSegment, segmentRelationOf } from './resolveNodeSegment';
import type { DiagramBoundary, DiagramNode } from '../model/types';

function seg(
  id: string,
  x: number,
  size: number,
  extra: Partial<DiagramBoundary> = {},
): DiagramBoundary {
  return {
    id,
    type: 'ROUNDED_DASHED',
    x,
    y: x,
    width: size,
    height: size,
    trustLevel: 'Internal',
    microTrust: 'Production',
    microSegmentationStatus: '未適用',
    sensitiveData: '無し',
    ...extra,
  };
}

describe('resolveNodeSegment', () => {
  it('区画の属性をルール側の英語値に写像する', () => {
    const nodes: DiagramNode[] = [{ id: 'n', type: 'PROCESS', x: 200, y: 200 }];
    const map = resolveNodeSegment(nodes, [
      seg('s', 100, 400, { microSegmentationStatus: '部分適用', sensitiveData: '機密情報' }),
    ]);
    expect(map.get('n')).toEqual({
      boundaryId: 's',
      status: 'PartiallyEnforced',
      environment: 'Production',
      sensitiveData: 'Confidential',
    });
  });

  it('区画外のノードは Unsegmented で、環境と機密データ区分を持たない', () => {
    const nodes: DiagramNode[] = [{ id: 'n', type: 'PROCESS', x: 2000, y: 2000 }];
    expect(resolveNodeSegment(nodes, [seg('s', 0, 400)]).get('n')).toEqual({ status: 'Unsegmented' });
  });

  it('ROUNDED_DASHED 以外の境界は区画とみなさない', () => {
    const nodes: DiagramNode[] = [{ id: 'n', type: 'PROCESS', x: 200, y: 200 }];
    const boundaries: DiagramBoundary[] = [
      { id: 'macro', type: 'ROUNDED', x: 0, y: 0, width: 800, height: 800, trustLevel: 'Internal' },
    ];
    expect(resolveNodeSegment(nodes, boundaries).get('n')?.status).toBe('Unsegmented');
  });

  it('入れ子は最内側の区画を採用する（定義順に依存しない）', () => {
    const nodes: DiagramNode[] = [{ id: 'n', type: 'PROCESS', x: 300, y: 300 }];
    const inner = seg('inner', 200, 300, { microSegmentationStatus: '適用済み' });
    const outer = seg('outer', 0, 1000);
    expect(resolveNodeSegment(nodes, [inner, outer]).get('n')?.boundaryId).toBe('inner');
    expect(resolveNodeSegment(nodes, [outer, inner]).get('n')?.status).toBe('Enforced');
  });

  it('適用状態が未設定の区画（旧データ）は NotEnforced とみなす', () => {
    const nodes: DiagramNode[] = [{ id: 'n', type: 'PROCESS', x: 200, y: 200 }];
    const legacy = seg('s', 100, 400, { microSegmentationStatus: undefined });
    expect(resolveNodeSegment(nodes, [legacy]).get('n')?.status).toBe('NotEnforced');
  });
});

describe('segmentRelationOf', () => {
  it('同じ区画は Same、別の区画や片側だけ区画外は Cross、両端とも区画外は None', () => {
    const a = { boundaryId: 'a', status: 'NotEnforced' as const };
    const b = { boundaryId: 'b', status: 'Enforced' as const };
    const out = { status: 'Unsegmented' as const };
    expect(segmentRelationOf(a, { ...a })).toBe('Same');
    expect(segmentRelationOf(a, b)).toBe('Cross');
    expect(segmentRelationOf(a, out)).toBe('Cross');
    expect(segmentRelationOf(out, out)).toBe('None');
  });
});
