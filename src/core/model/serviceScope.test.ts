import { describe, expect, it } from 'vitest';
import { matchServiceScope, normalizeScopeValue, scopeContains, type ServiceScopeEntry } from './serviceScope';

const e = (kind: ServiceScopeEntry['kind'], value: string): ServiceScopeEntry => ({ kind, value });

describe('normalizeScopeValue', () => {
  it.each([
    ['host', 'Partner.Example.COM.', 'partner.example.com'],
    ['domain', '*.Order.example.com', 'order.example.com'],
    ['cidr', '203.0.113.5/28', '203.0.113.0/28'],
    ['cidr', '203.0.113.5', '203.0.113.5/32'],
    ['cidr', '2001:DB8::1/32', '2001:db8::/32'],
    ['url-prefix', 'HTTPS://API.Example.com:443/v1/orders/?q=1#x', 'https://api.example.com/v1/orders'],
    ['url-prefix', 'https://api.example.com', 'https://api.example.com/'],
  ] as const)('%s: %s → %s', (kind, value, expected) => {
    expect(normalizeScopeValue(kind, value)).toBe(expected);
  });

  it.each([
    ['host', 'bad host'],
    ['domain', 'example..com'],
    ['cidr', '203.0.113.0/33'],
    ['cidr', '300.1.1.1/24'],
    ['url-prefix', 'ftp://example.com/'],
    ['url-prefix', 'api.example.com/v1'],
  ] as const)('解釈できない値は undefined：%s %s', (kind, value) => {
    expect(normalizeScopeValue(kind, value)).toBeUndefined();
  });
});

describe('scopeContains', () => {
  it('host：完全一致だけ（配下は含まない）', () => {
    expect(scopeContains(e('host', 'partner.example.com'), { host: 'PARTNER.example.com.' })).toBe(true);
    expect(scopeContains(e('host', 'partner.example.com'), { host: 'a.partner.example.com' })).toBe(false);
  });

  it('domain：ラベルの区切りで配下を含み、似た名前は含まない', () => {
    const d = e('domain', 'example.com');
    expect(scopeContains(d, { host: 'example.com' })).toBe(true);
    expect(scopeContains(d, { host: 'a.b.example.com' })).toBe(true);
    expect(scopeContains(d, { host: 'badexample.com' })).toBe(false);
    expect(scopeContains(d, { url: 'https://api.example.com/v1' })).toBe(true);
  });

  it('cidr：範囲内の IP を含み、IPv4 と IPv6 は互いに含まない', () => {
    expect(scopeContains(e('cidr', '203.0.113.0/28'), { ip: '203.0.113.15' })).toBe(true);
    expect(scopeContains(e('cidr', '203.0.113.0/28'), { ip: '203.0.113.16' })).toBe(false);
    expect(scopeContains(e('cidr', '2001:db8::/32'), { ip: '2001:db8:ffff::1' })).toBe(true);
    expect(scopeContains(e('cidr', '0.0.0.0/0'), { ip: '2001:db8::1' })).toBe(false);
    expect(scopeContains(e('cidr', '203.0.113.0/28'), { host: 'example.com' })).toBe(false);
  });

  it('url-prefix：同じ scheme・ホスト・ポートでパスの区切りで配下を含む', () => {
    const p = e('url-prefix', 'https://api.example.com/v1');
    expect(scopeContains(p, { url: 'https://API.example.com:443/v1/orders?id=1' })).toBe(true);
    expect(scopeContains(p, { url: 'https://api.example.com/v1' })).toBe(true);
    expect(scopeContains(p, { url: 'https://api.example.com/v10' })).toBe(false);
    expect(scopeContains(p, { url: 'http://api.example.com/v1/orders' })).toBe(false);
    expect(scopeContains(p, { url: 'https://api.example.com:8443/v1/orders' })).toBe(false);
  });

  it('url-prefix：URL を持たないホストだけの観測は、同じホストなら含む', () => {
    const p = e('url-prefix', 'https://api.example.com/v1');
    expect(scopeContains(p, { host: 'api.example.com' })).toBe(true);
    expect(scopeContains(p, { host: 'www.example.com' })).toBe(false);
  });

  it('解釈できない範囲は何も含まない', () => {
    expect(scopeContains(e('cidr', 'nope'), { ip: '203.0.113.1' })).toBe(false);
  });
});

describe('matchServiceScope', () => {
  it('含む最初の範囲を返し、無ければ undefined', () => {
    const entries = [e('host', 'a.example.com'), e('cidr', '198.51.100.0/24')];
    expect(matchServiceScope(entries, { host: 'x.example.com', ip: '198.51.100.7' })).toEqual(entries[1]);
    expect(matchServiceScope(entries, { host: 'x.example.com' })).toBeUndefined();
  });
});
