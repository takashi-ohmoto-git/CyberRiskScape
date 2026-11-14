import { describe, expect, it } from 'vitest';
import { lookupContext, type ContextInput } from './lookupContext';
import type { Asset, BomComponent } from '../../core/model/types';

const asset = (extra: Partial<Asset>): Asset => ({
  id: 'a1',
  source: { format: 'shodan', product: 'Shodan', scope: 's', importedAt: '2026-11-01T00:00:00Z' },
  externalId: 'x',
  identifiers: [],
  kind: 'service',
  host: 'unrelated.example.org',
  ...extra,
});

const component = (purl: string): BomComponent => ({
  id: 'c1',
  source: { format: 'cyclonedx', product: 'Syft', importedAt: '2026-11-01T00:00:00Z' },
  externalId: purl,
  identifiers: [{ scheme: 'purl', value: purl }],
  kind: 'software',
  name: 'lib',
});

const input = (assets: Asset[], bomComponents: BomComponent[] = []): ContextInput => ({
  layers: [],
  assets,
  bomComponents,
  findings: [],
});

const matched = (i: ContextInput, q: Parameters<typeof lookupContext>[1]) => lookupContext(i, q).matches.length;

describe('lookupContext（表記の違いで取りこぼさない）', () => {
  it('IPv6 は書き方が違っても同じ資産に当たる（項目・識別子とも）', () => {
    expect(matched(input([asset({ ip: '2001:0DB8:0000:0000:0000:0000:0000:0001' })]), { ip: '2001:db8::1' })).toBe(1);
    expect(matched(input([asset({ identifiers: [{ scheme: 'IP', value: '2001:db8::1' }] })]), { ip: '2001:DB8:0::1' })).toBe(1);
  });

  it('IPv4 は従来どおり一致し、別の IP には当たらない', () => {
    const i = input([asset({ ip: '203.0.113.5' })]);
    expect(matched(i, { ip: '203.0.113.5' })).toBe(1);
    expect(matched(i, { ip: '203.0.113.6' })).toBe(0);
  });

  it('ホストは大文字小文字と末尾のドットを区別しない（項目・識別子とも）', () => {
    expect(matched(input([asset({ host: 'API.Example.com' })]), { host: 'api.example.com.' })).toBe(1);
    expect(matched(input([asset({ domain: 'api.example.com.' })]), { host: 'API.EXAMPLE.COM' })).toBe(1);
    expect(matched(input([asset({ identifiers: [{ scheme: 'hostname', value: 'DB01' }] })]), { host: 'db01' })).toBe(1);
    expect(matched(input([asset({ host: 'api.example.com' })]), { host: 'other.example.com' })).toBe(0);
  });

  it('purl は修飾子の有無で取りこぼさない。版なしの照会は全ての版に当たり、版つきはその版だけ', () => {
    const i = input([], [component('pkg:npm/lib@1.2.3?repository_url=https://registry.example')]);
    expect(matched(i, { purl: 'pkg:npm/lib@1.2.3' })).toBe(1);
    expect(matched(i, { purl: 'PKG:NPM/lib' })).toBe(1);
    expect(matched(i, { purl: 'pkg:npm/lib@9.9.9' })).toBe(0);
  });
});
