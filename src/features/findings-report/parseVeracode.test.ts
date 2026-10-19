import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseVeracodeFindings, stripSecrets } from './parseVeracode';

const load = (name: string): unknown =>
  JSON.parse(readFileSync(new URL(`./__fixtures__/${name}`, import.meta.url), 'utf-8'));

describe('parseVeracodeFindings', () => {
  it('Pipeline Scan の results.json を STATIC・未解決として読む', () => {
    const r = parseVeracodeFindings(load('pipeline-results.json'));
    if (!r.ok) throw new Error(r.error);
    expect(r.source).toBe('pipeline');
    expect(r.findings).toHaveLength(4);
    expect(r.findings[0]).toMatchObject({
      id: '1001',
      scanType: 'STATIC',
      cwe: 89,
      severity: 5,
      location: 'com/example/UserDao.java:42',
      status: 'open',
    });
    expect(r.excluded).toEqual({ sca: 0, closed: 0 });
  });

  it('Findings API は cwe が数値でもオブジェクトでも読み、SCA と CLOSED を除いて数える', () => {
    const r = parseVeracodeFindings(load('findings-api.json'));
    if (!r.ok) throw new Error(r.error);
    expect(r.source).toBe('findings-api');
    expect(r.excluded).toEqual({ sca: 1, closed: 1 });
    expect(r.findings.map((f) => f.id)).toEqual(['2001', '2002', '2003']);
    const [obj, num, manual] = r.findings;
    expect(obj).toMatchObject({ cwe: 89, scanType: 'STATIC', location: 'src/dao/UserDao.java:42' });
    expect(obj.cweName).toContain('SQL');
    expect(num).toMatchObject({
      cwe: 918,
      scanType: 'DYNAMIC',
      title: 'Server-Side Request Forgery',
      location: 'https://app.example.invalid/fetch',
    });
    expect(manual).toMatchObject({ scanType: 'MANUAL', capec: 'CAPEC-1', location: 'search form' });
  });

  it('どちらの形でもなければ日本語のエラーを返す', () => {
    for (const bad of [[], {}, { findings: 'x' }, { _embedded: {} }, null, 'text']) {
      const r = parseVeracodeFindings(bad);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error).toContain('Veracode');
    }
  });
});

describe('stripSecrets', () => {
  it('URL の userinfo・クエリ・フラグメントを捨てる', () => {
    expect(stripSecrets('https://user:pass@api.example.com/orders/1?token=abc#x')).toBe('https://api.example.com/orders/1');
    expect(stripSecrets('/orders/1?token=abc')).toBe('/orders/1');
    expect(stripSecrets(undefined)).toBeUndefined();
  });

  it('DYNAMIC の URL にトークンが載っていても取り込まない', () => {
    const r = parseVeracodeFindings({
      _embedded: {
        findings: [
          {
            issue_id: 1,
            scan_type: 'DYNAMIC',
            finding_status: { status: 'OPEN' },
            finding_details: { cwe: 89, severity: 4, URL: 'https://api.example.com/search?q=1&access_token=SECRET' },
          },
        ],
      },
    });
    if (!r.ok) throw new Error(r.error);
    expect(JSON.stringify(r.findings)).not.toContain('SECRET');
    expect(r.findings[0]?.location).toBe('https://api.example.com/search');
  });
});
