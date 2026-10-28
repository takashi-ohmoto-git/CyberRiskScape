import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { InventorySection } from './InventorySection';
import type { DiagramNode, NodeInventory } from '../../core/model/types';

function node(inventory?: NodeInventory): DiagramNode {
  return { id: 'n1', type: 'PACKAGE_DEPENDENCIES', inventory } as unknown as DiagramNode;
}

describe('InventorySection', () => {
  it('inventory があるノードでは折りたたみ欄（閉じた状態）を出す', () => {
    const html = renderToStaticMarkup(
      <InventorySection
        node={node({
          kind: 'npm',
          source: 'package.json',
          collectedAt: '2026-10-29T00:00:00Z',
          items: [{ name: 'react' }],
        })}
      />,
    );
    expect(html).toContain('package.json');
    expect(html).toContain('2026-10-29T00:00:00Z');
    expect(html).toContain('aria-expanded="false"');
    expect(html).not.toContain('<pre');
  });

  it('inventory がないノードでは何も出さない', () => {
    expect(renderToStaticMarkup(<InventorySection node={node()} />)).toBe('');
  });
});
