import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  IDENTIFIER_SCHEMES,
  identifierSchemeOf,
  identifierScope,
  identifierValues,
  identityKey,
  isGloballyUniqueIp,
  normalizeIdentifier,
  normalizeIdentifiers,
} from './identifierSchemes';

const norm = (scheme: string, value: string) => normalizeIdentifier({ scheme, value });

describe('normalizeIdentifier', () => {
  it.each([
    ['CVE', ' cve-2024-1234 ', 'cve', 'CVE-2024-1234'],
    ['ghsa', 'ghsa-ABCD-1234-efgh', 'ghsa', 'GHSA-abcd-1234-efgh'],
    ['fqdn', 'API.Example.COM.', 'fqdn', 'api.example.com'],
    ['hostname', 'DB01', 'hostname', 'db01'],
    ['cpe', 'CPE:2.3:a:Vendor:Product:1.0', 'cpe', 'cpe:2.3:a:vendor:product:1.0'],
    ['sha-256', 'SHA256:ABCDEF', 'sha-256', 'abcdef'],
    ['cwe', 'CWE-079', 'cwe', '79'],
    ['cwe', '79', 'cwe', '79'],
    ['cce', 'cce-12345-6', 'cce', 'CCE-12345-6'],
    ['purl', 'PKG:NPM/%40scope/Name@1.2.3?repository_url=https://x.example#sub', 'purl', 'pkg:npm/%40scope/Name@1.2.3'],
    ['url', 'HTTPS://API.Example.com:443/Path?Q=1#frag', 'url', 'https://api.example.com/Path?Q=1'],
    ['url', 'not a url', 'url', 'not a url'],
    ['ip', '010.001.000.001', 'ip', '10.1.0.1'],
    ['ip', '[2001:0DB8:0000:0000:0000:0000:0000:0001]', 'ip', '2001:db8::1'],
    ['ip', 'fe80::1%eth0', 'ip', 'fe80::1'],
    ['ip', '::ffff:192.0.2.1', 'ip', '::ffff:c000:201'],
    ['ip', '2001:db8:0:1:0:0:0:1', 'ip', '2001:db8:0:1::1'],
    ['ip', '0:0:0:0:0:0:0:0', 'ip', '::'],
    ['ip', 'not-an-ip', 'ip', 'not-an-ip'],
    ['prowler-check', 's3_bucket_default_encryption', 'prowler-check', 's3_bucket_default_encryption'],
  ])('%s %s → %s %s', (scheme, value, expectedScheme, expectedValue) => {
    expect(norm(scheme, value)).toEqual({ scheme: expectedScheme, value: expectedValue });
  });

  it('一覧に無い scheme は、scheme の小文字化と空白の除去だけ', () => {
    expect(norm(' Example-DB ', ' EXMPL-2026-77 ')).toEqual({ scheme: 'example-db', value: 'EXMPL-2026-77' });
  });

  it('2 回かけても変わらない', () => {
    for (const [scheme, value] of [
      ['ip', '2001:0DB8::0001'],
      ['url', 'HTTP://Example.com'],
      ['purl', 'pkg:PyPI/Django@4.2?x=1'],
      ['cve', 'cve-2024-1'],
    ]) {
      const once = norm(scheme, value);
      expect(normalizeIdentifier(once)).toEqual(once);
    }
  });
});

describe('normalizeIdentifiers', () => {
  it('表記をそろえ、同じになったものは先のものだけを残す', () => {
    expect(
      normalizeIdentifiers([
        { scheme: 'CVE', value: 'cve-2024-1' },
        { scheme: 'cve', value: 'CVE-2024-1' },
        { scheme: 'fqdn', value: 'A.example.com.' },
        { scheme: 'fqdn', value: 'a.example.com' },
        { scheme: 'cwe', value: '79' },
      ]),
    ).toEqual([
      { scheme: 'cve', value: 'CVE-2024-1' },
      { scheme: 'fqdn', value: 'a.example.com' },
      { scheme: 'cwe', value: '79' },
    ]);
  });

  it('正規化で値が長くなること・空になることはない（保存スキーマの上限と下限を超えない）', () => {
    const samples = [
      ['url', 'HTTPS://User:Pw@API.Example.com:443/a b?q=日本語#frag'],
      ['url', 'http://example.com'],
      ['url', '#only-fragment'],
      ['ip', '::ffff:192.0.2.1'],
      ['ip', '1:0:0:0:0:0:0:1'],
      ['ip', '001.002.003.004'],
      ['fqdn', '.'],
      ['sha-256', 'sha256:'],
      ['purl', '?x=1'],
      ['ghsa', 'GHSA-ABCD-1234-EFGH'],
      ['cwe', 'CWE-0079'],
      ['unknown', '  x  '],
    ];
    for (const [scheme, value] of samples) {
      const n = normalizeIdentifier({ scheme, value });
      expect(n.value.length, `${scheme} ${value}`).toBeLessThanOrEqual(value.length);
      expect(n.value.length, `${scheme} ${value}`).toBeGreaterThan(0);
    }
  });

  it('URL：利用者情報とパス・クエリは触らず、既定でないポートは残す', () => {
    expect(norm('url', 'HTTP://User:Pw@Example.com:8080/A?B=C').value).toBe('http://User:Pw@example.com:8080/A?B=C');
    expect(norm('url', 'http://example.com:80').value).toBe('http://example.com');
    expect(norm('url', 'https://example.com:80/').value).toBe('https://example.com:80/');
  });
});

describe('isGloballyUniqueIp', () => {
  it.each(['8.8.8.8', '203.0.113.5', '172.32.0.1', '100.128.0.1', '2001:db8::1', '2606:4700::1111'])(
    '%s は全体で一意',
    (ip) => expect(isGloballyUniqueIp(ip)).toBe(true),
  );

  it.each([
    '10.0.0.1',
    '172.16.0.1',
    '172.31.255.254',
    '192.168.1.1',
    '127.0.0.1',
    '169.254.10.1',
    '100.64.0.1',
    '0.0.0.0',
    '224.0.0.1',
    '::1',
    '::',
    'fc00::1',
    'fd12:3456::1',
    'fe80::1',
    'ff02::1',
    'not-an-ip',
  ])('%s は組織の中でだけ一意', (ip) => expect(isGloballyUniqueIp(ip)).toBe(false));
});

describe('identifierScope', () => {
  it('IP は値で決まる。ホスト名は組織、FQDN・purl・CVE は全体', () => {
    expect(identifierScope({ scheme: 'ip', value: '8.8.8.8' })).toBe('global');
    expect(identifierScope({ scheme: 'ip', value: '10.0.0.1' })).toBe('organization');
    expect(identifierScope({ scheme: 'hostname', value: 'db01' })).toBe('organization');
    expect(identifierScope({ scheme: 'fqdn', value: 'a.example.com' })).toBe('global');
    expect(identifierScope({ scheme: 'purl', value: 'pkg:npm/a@1' })).toBe('global');
    expect(identifierScope({ scheme: 'artex-asset-id', value: '1' })).toBe('product');
    expect(identifierScope({ scheme: 'unknown-scheme', value: '1' })).toBeUndefined();
  });
});

describe('identityKey', () => {
  it('表記が違っても同じものなら同じ鍵になる', () => {
    expect(identityKey({ scheme: 'CVE', value: 'cve-2024-1234' })).toBe(identityKey({ scheme: 'cve', value: 'CVE-2024-1234' }));
    expect(identityKey({ scheme: 'fqdn', value: 'API.example.com.' })).toBe('fqdn:api.example.com');
    expect(identityKey({ scheme: 'ip', value: '2001:0db8::0001' })).toBe('ip:2001:db8::1');
  });

  it('分類・製品内の ID・付加情報・一覧に無い scheme は鍵を持たない', () => {
    expect(identityKey({ scheme: 'cwe', value: '79' })).toBeUndefined();
    expect(identityKey({ scheme: 'artex-asset-id', value: '1' })).toBeUndefined();
    expect(identityKey({ scheme: 'epss', value: '0.5' })).toBeUndefined();
    expect(identityKey({ scheme: 'example-db', value: 'X' })).toBeUndefined();
  });

  it('プライベート IP とドメインなしのホスト名は、範囲が違えば別の鍵になる', () => {
    const ip = { scheme: 'ip', value: '10.0.0.1' };
    expect(identityKey(ip, 'org-a')).not.toBe(identityKey(ip, 'org-b'));
    expect(identityKey(ip, 'org-a')).toBe(identityKey(ip, 'org-a'));
    expect(identityKey(ip)).toBe(identityKey(ip)); // 1 つのプロジェクトの中では範囲を省略できる
    const host = { scheme: 'hostname', value: 'DB01' };
    expect(identityKey(host, 'org-a')).not.toBe(identityKey(host, 'org-b'));
  });

  it('公開 IP・FQDN・purl・CVE は、範囲によらず同じ鍵になる', () => {
    for (const id of [
      { scheme: 'ip', value: '8.8.8.8' },
      { scheme: 'fqdn', value: 'a.example.com' },
      { scheme: 'purl', value: 'pkg:npm/a@1' },
      { scheme: 'cve', value: 'CVE-2024-1' },
    ]) {
      expect(identityKey(id, 'org-a')).toBe(identityKey(id, 'org-b'));
    }
  });
});

describe('identifierValues', () => {
  const ids = [
    { scheme: 'CVE', value: ' cve-2024-1 ' },
    { scheme: 'cve', value: 'CVE-2024-1' },
    { scheme: 'cve', value: 'CVE-2024-2' },
    { scheme: 'fqdn', value: 'A.example.com' },
    { scheme: 'hostname', value: 'DB01' },
  ];

  it('scheme の大文字小文字を区別せず、値を正規化し、重複を除いて元の順で返す', () => {
    expect(identifierValues(ids, 'cve')).toEqual(['CVE-2024-1', 'CVE-2024-2']);
  });

  it('複数の scheme をまとめて取り出せる。無ければ空', () => {
    expect(identifierValues(ids, 'fqdn', 'hostname')).toEqual(['a.example.com', 'db01']);
    expect(identifierValues(ids, 'purl')).toEqual([]);
  });
});

describe('identifierSchemeOf', () => {
  it('大文字小文字を区別しない。プロトタイプの名前では引けない', () => {
    expect(identifierSchemeOf('CVE')?.kind).toBe('identity');
    expect(identifierSchemeOf('toString')).toBeUndefined();
    expect(identifierSchemeOf('constructor')).toBeUndefined();
  });
});

/** src 配下の .ts を集める（テストと、この定義ファイル自身は除く）。 */
function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = join(dir, e.name);
    if (e.isDirectory()) return e.name === '__fixtures__' ? [] : sourceFiles(p);
    return /\.tsx?$/.test(e.name) && !/\.test\.tsx?$/.test(e.name) && e.name !== 'identifierSchemes.ts' ? [p] : [];
  });
}

describe('scheme の一覧（コードとの整合）', () => {
  it('コード中で識別子として書いている scheme は、すべて一覧に載っている', () => {
    const srcDir = fileURLToPath(new URL('../../', import.meta.url));
    const used = new Set<string>();
    for (const file of sourceFiles(srcDir)) {
      const text = readFileSync(file, 'utf8');
      for (const m of text.matchAll(/scheme: '([a-z0-9-]+)'/g)) used.add(m[1]);
      // 資産のホストの識別子（`hostIdentifier`）は三項演算子で書いている
      for (const m of text.matchAll(/scheme: [^,}]*\? '([a-z0-9-]+)' : '([a-z0-9-]+)'/g)) {
        used.add(m[1]);
        used.add(m[2]);
      }
    }
    expect(used.size).toBeGreaterThan(15);
    const missing = [...used].filter((s) => !(s in IDENTIFIER_SCHEMES)).sort();
    expect(missing).toEqual([]);
  });
});
