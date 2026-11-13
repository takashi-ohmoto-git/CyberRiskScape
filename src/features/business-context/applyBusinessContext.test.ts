import { describe, expect, it } from 'vitest';
import type { DiagramNode } from '../../core/model/types';
import { applyBusinessContext } from './applyBusinessContext';
import type { BusinessContextRow } from './parseBusinessContextTable';

const NOW = new Date('2026-11-13T00:00:00.000Z');
const node = (id: string, seq: number, extra: Partial<DiagramNode> = {}): DiagramNode => ({ id, seq, type: 'DATABASE', x: 0, y: 0, label: `N${seq}`, ...extra });
const layers = () => ({
  L1: { nodes: [node('sap', 1, { posture: { recordVolume: 'Over1M' } }), node('crm', 2), node('other', 3)] },
  L2: { nodes: [node('wh', 1)] },
});
const row = (r: Partial<BusinessContextRow> & { node: string }): BusinessContextRow => ({ process: 'P', ...r });

describe('applyBusinessContext', () => {
  it('ID と C 番号でノードを引き、割合から重要度を決める（30% 以上 High・10% 以上 Medium・それ未満 Low）', () => {
    const { layers: out, summary } = applyBusinessContext(
      layers(),
      [row({ node: 'sap', process: 'O2C', value: 600, currency: 'JPY' }), row({ node: 'C2', process: 'P2P', value: 300, currency: 'JPY' }), row({ node: 'other', value: 100, currency: 'JPY' })],
      { now: NOW },
    );
    const by = (id: string) => out.L1?.nodes.find((n) => n.id === id)?.businessContext;
    expect(by('sap')).toMatchObject({ criticality: 'High', criticalitySource: 'derived', source: { product: 'business-context', retrievedAt: NOW.toISOString() } });
    expect(by('crm')).toMatchObject({ criticality: 'High' }); // 30%
    expect(by('other')).toMatchObject({ criticality: 'Medium' }); // 10%
    expect(summary.basis).toBe('value');
    expect(summary.applied.find((a) => a.nodeId === 'sap')?.share).toBeCloseTo(0.6);
  });

  it('同じノードの同じプロセスは合算し、通貨が食い違えば落として注意に書く。他の項目は触らない', () => {
    const { layers: out, summary } = applyBusinessContext(
      layers(),
      [
        row({ node: 'sap', process: 'O2C', cases: 10, value: 100, currency: 'JPY', period: '2026-10' }),
        row({ node: 'sap', process: 'O2C', cases: 5, value: 50, currency: 'USD', period: '2026-10' }),
        row({ node: 'sap', process: 'P2P', cases: 1 }),
      ],
      { now: NOW },
    );
    const sap = out.L1?.nodes.find((n) => n.id === 'sap');
    expect(sap?.businessContext?.processes).toEqual([
      { name: 'O2C', cases: 15, value: 150, period: '2026-10' },
      { name: 'P2P', cases: 1 },
    ]);
    expect(sap?.posture).toEqual({ recordVolume: 'Over1M' });
    expect(summary.notes.join('\n')).toContain('通貨が食い違う');
    expect(summary.notes.join('\n')).toContain('通貨が混在');
    expect(summary.basis).toBe('cases'); // 通貨混在 → 件数
  });

  it('行に重要度があれば最大値を使い declared。他のノードの決め方（割合）とは独立', () => {
    const { layers: out, summary } = applyBusinessContext(
      layers(),
      [row({ node: 'sap', criticality: 'Low' }), row({ node: 'sap', process: 'Q', criticality: 'High' }), row({ node: 'crm', value: 1 })],
      { now: NOW },
    );
    expect(out.L1?.nodes.find((n) => n.id === 'sap')?.businessContext).toMatchObject({ criticality: 'High', criticalitySource: 'declared' });
    expect(out.L1?.nodes.find((n) => n.id === 'crm')?.businessContext).toMatchObject({ criticality: 'High', criticalitySource: 'derived' });
    expect(summary.applied).toHaveLength(2);
  });

  it('金額も件数も重要度も無いノードは見送り（決められない）', () => {
    const { layers: out, summary } = applyBusinessContext(layers(), [row({ node: 'sap' })], { now: NOW });
    expect(summary.skipped).toEqual([expect.objectContaining({ nodeId: 'sap', reason: 'noCriticality' })]);
    expect(summary.basis).toBe('none');
    expect(out.L1?.nodes.find((n) => n.id === 'sap')?.businessContext).toBeUndefined();
  });

  it('図に無い参照・全レイヤーで複数に当たる C 番号を報告し、表に出ないノードと元の入力は変えない', () => {
    const input = layers();
    const snapshot = JSON.stringify(input);
    const { layers: out, summary } = applyBusinessContext(input, [row({ node: 'ghost', value: 1 }), row({ node: 'C1', value: 1 }), row({ node: 'crm', value: 1 })], { now: NOW });
    expect(summary.unknownRefs).toEqual(['ghost']);
    expect(summary.ambiguousRefs).toEqual(['C1']); // sap（L1）と wh（L2）がどちらも C1
    expect(out.L1?.nodes.find((n) => n.id === 'other')).toBe(input.L1.nodes[2]);
    expect(out.L2).toBe(input.L2);
    expect(JSON.stringify(input)).toBe(snapshot);
  });

  it('取り込み直しは表に出たノードだけ置き換える。source の製品・参照を記録する', () => {
    const first = applyBusinessContext(layers(), [row({ node: 'sap', value: 1 }), row({ node: 'crm', value: 1 })], { now: NOW });
    const second = applyBusinessContext(first.layers, [row({ node: 'sap', criticality: 'Low' })], {
      now: new Date('2026-11-14T00:00:00.000Z'),
      source: { product: 'Celonis', ref: 'km:k/record:r' },
    });
    const get = (id: string) => second.layers.L1?.nodes.find((n) => n.id === id)?.businessContext;
    expect(get('sap')).toMatchObject({ criticality: 'Low', source: { product: 'Celonis', ref: 'km:k/record:r', retrievedAt: '2026-11-14T00:00:00.000Z' } });
    expect(get('crm')).toEqual(first.layers.L1?.nodes.find((n) => n.id === 'crm')?.businessContext);
  });
});
