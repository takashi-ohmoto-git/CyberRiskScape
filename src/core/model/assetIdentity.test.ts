import { describe, expect, it } from 'vitest';
import { assetIdentifiers, hostIdentifier, toIsoTimestamp } from './assetIdentity';

describe('hostIdentifier', () => {
  it.each([
    ['203.0.113.10', 'ip', '203.0.113.10'],
    ['2001:db8::1', 'ip', '2001:db8::1'],
    ['WWW.Example.com', 'fqdn', 'www.example.com'],
    ['intranet', 'hostname', 'intranet'],
  ])('%s → %s', (host, scheme, value) => {
    expect(hostIdentifier(host)).toEqual({ scheme, value });
  });
});

describe('assetIdentifiers', () => {
  it('IP・ドメイン・URL を鍵にし、重複を除く', () => {
    expect(
      assetIdentifiers({
        host: '203.0.113.10',
        ip: '203.0.113.10',
        domain: 'www.example.com',
        url: 'https://www.example.com/a',
      }),
    ).toEqual([
      { scheme: 'ip', value: '203.0.113.10' },
      { scheme: 'fqdn', value: 'www.example.com' },
      { scheme: 'url', value: 'https://www.example.com/a' },
    ]);
  });
});

describe('toIsoTimestamp', () => {
  it('PostgreSQL の表記 → UTC の ISO 8601', () => {
    expect(toIsoTimestamp('2026-11-04 06:58:29.773049+00')).toBe('2026-11-04T06:58:29.773Z');
  });
  it('時差つき → UTC に直す', () => {
    expect(toIsoTimestamp('2026-11-04T09:00:00+09:00')).toBe('2026-11-04T00:00:00.000Z');
  });
  it('日付だけ → その日の UTC の 0 時', () => {
    expect(toIsoTimestamp('2026-11-01')).toBe('2026-11-01T00:00:00.000Z');
  });
  it('解釈できない → undefined', () => {
    expect(toIsoTimestamp('昨日')).toBeUndefined();
  });
});
