import { describe, expect, it } from 'vitest';
import type { DiagramAnnotation, DiagramBoundary, DiagramNode } from '../../../core/model/types';
import { getNodeDimensions } from '../../../core/canvas/nodeGeometry';
import { computeContentBounds } from './contentBounds';

const node = (id: string, x: number, y: number): DiagramNode =>
  ({ id, type: 'unknown-type', x, y, label: id }) as unknown as DiagramNode;
const boundary = (x: number, y: number, width: number, height: number): DiagramBoundary =>
  ({ id: 'b', x, y, width, height, label: 'b' }) as unknown as DiagramBoundary;
const annotation = (x: number, y: number, kind: 'text' | 'callout'): DiagramAnnotation =>
  ({ id: 'a', kind, x, y, text: 'abc' }) as DiagramAnnotation;

describe('computeContentBounds', () => {
  it('空レイヤーは null', () => {
    expect(computeContentBounds({ nodes: [], boundaries: [], annotations: [] })).toBeNull();
  });

  it('ノードのみ：ノード寸法を含む', () => {
    const n = node('n1', 100, 50);
    const { w, h } = getNodeDimensions(n);
    expect(computeContentBounds({ nodes: [n], boundaries: [], annotations: [] })).toEqual({
      minX: 100,
      minY: 50,
      maxX: 100 + w,
      maxY: 50 + h,
    });
  });

  it('境界を含めて外側へ広がる', () => {
    const b = computeContentBounds({
      nodes: [node('n1', 100, 100)],
      boundaries: [boundary(0, 10, 500, 400)],
      annotations: [],
    });
    expect(b).toMatchObject({ minX: 0, minY: 10, maxX: 500, maxY: 410 });
  });

  it('注釈（callout は幅 224）を含む', () => {
    const b = computeContentBounds({
      nodes: [node('n1', 0, 0)],
      boundaries: [],
      annotations: [annotation(300, 20, 'callout')],
    });
    expect(b!.maxX).toBe(300 + 224);
    expect(b!.maxY).toBeGreaterThan(20);
    expect(b!.minX).toBe(0);
  });

  it('注釈のみでも bbox が出る', () => {
    expect(
      computeContentBounds({ nodes: [], boundaries: [], annotations: [annotation(5, 6, 'text')] }),
    ).not.toBeNull();
  });
});
