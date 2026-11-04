import { describe, expect, it } from 'vitest';
import type { BomComponent, NodeInventory } from '../../core/model/types';
import { listBomComponents } from './listBomComponents';

const inventory = (items: { name: string; version?: string; pinned?: boolean }[]): NodeInventory => ({
  kind: 'npm',
  source: 'package-lock.json',
  collectedAt: '2026-11-01T00:00:00.000Z',
  items,
});
const imported = (purl: string, nodeId?: string): BomComponent => ({
  id: `x:${purl}`,
  source: { format: 'cyclonedx', product: 'x', scope: 's', importedAt: '2026-11-01T00:00:00.000Z' },
  externalId: purl,
  identifiers: [{ scheme: 'purl', value: purl }],
  kind: 'software',
  name: 'imported',
  ...(nodeId ? { subject: { layer: 'L1', nodeId } } : {}),
});

describe('listBomComponents', () => {
  it('依存パッケージのインベントリを部品の形にする', () => {
    const out = listBomComponents([], [{ layer: 'L1', node: { id: 'n1', inventory: inventory([{ name: 'a', version: '1.0.0' }]) } }]);
    expect(out[0]).toMatchObject({
      source: { format: 'inventory', product: 'package-lock.json' },
      identifiers: [{ scheme: 'purl', value: 'pkg:npm/a@1.0.0' }],
      subject: { layer: 'L1', nodeId: 'n1' },
    });
  });
  it('版が固定されていなければ、版なしの purl にする', () => {
    const out = listBomComponents([], [{ layer: 'L1', node: { id: 'n1', inventory: inventory([{ name: 'a', version: '^1.0.0' }]) } }]);
    expect(out[0].identifiers[0].value).toBe('pkg:npm/a');
    expect(out[0].version).toBe('^1.0.0');
  });
  it('環境変数のインベントリは部品にしない', () => {
    const env: NodeInventory = { kind: 'env', source: '.env', collectedAt: '2026-11-01', template: true, items: [{ name: 'A', valueKind: 'text', length: 1 }] };
    expect(listBomComponents([], [{ layer: 'L1', node: { id: 'n1', inventory: env } }])).toEqual([]);
  });
  it('同じノードに同じ purl があれば取り込んだ部品を優先する', () => {
    const out = listBomComponents(
      [imported('pkg:npm/a@1.0.0', 'n1')],
      [{ layer: 'L1', node: { id: 'n1', inventory: inventory([{ name: 'a', version: '1.0.0' }]) } }],
    );
    expect(out.map((c) => c.name)).toEqual(['imported']);
  });
  it('別のノードの同じ purl は別の部品として残す', () => {
    const out = listBomComponents(
      [imported('pkg:npm/a@1.0.0', 'n2')],
      [{ layer: 'L1', node: { id: 'n1', inventory: inventory([{ name: 'a', version: '1.0.0' }]) } }],
    );
    expect(out).toHaveLength(2);
  });
});
