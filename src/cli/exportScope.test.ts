import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { exportScope, exportScopeToText } from './exportScope';
import { asmReconcile } from './asmReconcile';

const FIXTURE_PATH = new URL('./__fixtures__/sample-project.json', import.meta.url);
const raw = () => JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as Record<string, unknown>;

const withScope = (serviceScope: unknown[]) => {
  const base = raw();
  return { ...base, projectMeta: { ...(base.projectMeta as Record<string, unknown>), serviceScope } };
};

describe('exportScope', () => {
  it('担当範囲を正規化して出し、重複はまとめ、解釈できない値は invalid に分ける', () => {
    const r = exportScope(
      withScope([
        { kind: 'domain', value: '*.Order.Example.com' },
        { kind: 'domain', value: 'order.example.com.' },
        { kind: 'cidr', value: '203.0.113.5/28', note: '公開セグメント' },
        { kind: 'url-prefix', value: 'https://api.example.com:443/v1/orders/' },
        { kind: 'cidr', value: 'nope' },
      ]),
    );
    expect(r.entries).toEqual([
      { kind: 'domain', value: 'order.example.com' },
      { kind: 'cidr', value: '203.0.113.0/28', note: '公開セグメント' },
      { kind: 'url-prefix', value: 'https://api.example.com/v1/orders' },
    ]);
    expect(r.invalid).toEqual([{ kind: 'cidr', value: 'nope' }]);
  });

  it('text：種類を絞れば値だけ、絞らなければ 種類<TAB>値', () => {
    const p = withScope([
      { kind: 'domain', value: 'order.example.com' },
      { kind: 'host', value: 'partner.example.com' },
    ]);
    expect(exportScopeToText(exportScope(p, 'domain'), 'domain')).toBe('order.example.com\n');
    expect(exportScopeToText(exportScope(p))).toBe('domain\torder.example.com\nhost\tpartner.example.com\n');
  });

  it('担当範囲が無ければ空', () => {
    expect(exportScope(raw()).entries).toEqual([]);
    expect(exportScopeToText(exportScope(raw()))).toBe('');
  });

  it('asm-reconcile は保存データの担当範囲で観測を分ける', () => {
    const p = {
      ...withScope([{ kind: 'domain', value: 'order.example.com' }]),
      assets: [
        {
          id: 'Shodan:s:1',
          source: { format: 'shodan', product: 'Shodan', scope: 's', importedAt: '2026-11-14T00:00:00Z' },
          externalId: '1',
          identifiers: [],
          kind: 'service',
          host: 'shop.order.example.com',
          ip: '203.0.113.1',
          port: 443,
        },
      ],
    };
    const r = asmReconcile(p);
    expect(r.scope?.unboundInScope.map((l) => l.host)).toEqual(['shop.order.example.com']);
  });
});
