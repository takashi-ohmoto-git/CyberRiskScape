import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { nucleiLabel, nucleiToFindings } from './nucleiToFindings';
import { parseNuclei } from './parseNuclei';
import { BUNDLED_FINDING_MAP } from '../findings-report/findingMap';
import { applyKev, parseKevCatalog } from '../kev-import/applyKev';

const text = readFileSync(new URL('./__fixtures__/nuclei.jsonl', import.meta.url), 'utf-8');
const parsed = parseNuclei(text);
if (!parsed.ok) throw new Error(parsed.error);
const conv = nucleiToFindings({ results: parsed.results, map: BUNDLED_FINDING_MAP, scope: 'dast', importedAt: '2026-11-07T00:00:00.000Z' });
const by = (tid: string) => conv.findings.find((f) => f.identifiers.some((i) => i.value === tid));

describe('nucleiToFindings', () => {
  it('件数：info と不一致を除き 4 件保存、除外を数える', () => {
    expect(conv.findings).toHaveLength(4);
    expect(conv.report).toMatchObject({ results: 6, stored: 4, excludedInfo: 1, excludedNoMatch: 1, withCve: 1, truncated: 0 });
  });

  it('CVE あり → known-vulnerability-unpatched のみ。CVE は大文字、CWE と EPSS も識別子', () => {
    const f = by('CVE-2099-0001');
    expect(f?.canonicalIds).toEqual(['known-vulnerability-unpatched']);
    expect(f?.identifiers).toEqual([
      { scheme: 'rule', value: 'CVE-2099-0001' },
      { scheme: 'cve', value: 'CVE-2099-0001' },
      { scheme: 'cwe', value: '94' },
      { scheme: 'epss', value: '0.91' },
    ]);
    expect(f).toMatchObject({ severity: 'Critical', sourceSeverity: 'critical', title: 'Example Framework RCE', observedAt: '2026-11-07T01:00:00Z', source: { format: 'nuclei', product: 'Nuclei', scope: 'dast' } });
  });

  it('CVE なし・CWE-89 → 対応表の canonicalId', () => {
    const f = by('sqli-error-based');
    expect(f?.canonicalIds).toContain('api-query-injection');
    expect(f?.severity).toBe('High');
  });

  it('辞書に無い CWE は canonicalIds 空で cweUnmapped に数える', () => {
    expect(by('exposed-config-file')?.canonicalIds).toEqual([]);
    expect(conv.report.cweUnmapped).toBeGreaterThanOrEqual(1);
  });

  it('場所：クエリ・userinfo・フラグメントを落とす。host:port はそのまま', () => {
    expect(by('sqli-error-based')?.resource?.label).toBe('https://app.example.com/search');
    expect(by('exposed-config-file')?.resource?.label).toBe('https://app.example.com/config.json');
    expect(by('redis-unauth')?.resource?.label).toBe('192.0.2.10:6379');
    expect(by('redis-unauth')?.externalId).toBe('redis-unauth:192.0.2.10:6379:');
  });

  it.each([
    ['https://u:p@a.example.com/x?y=1#z', undefined, 'https://a.example.com/x'],
    ['https://a.example.com/', undefined, 'https://a.example.com'],
    ['bad value with spaces', 'a.example.com:8080', 'a.example.com:8080'],
    [undefined, undefined, undefined],
  ])('nucleiLabel(%s, %s) → %s', (m, h, expected) => {
    expect(nucleiLabel(m, h)).toBe(expected);
  });

  it('秘密のマーカー・IP・クエリは出力に残らない', () => {
    const out = JSON.stringify(conv);
    expect(out).not.toContain('NUCLEI-SECRET-MARKER');
    expect(out).not.toContain('192.0.2.20');
    expect(out).not.toContain('OR%201');
  });

  it('subject を渡すと全指摘に付く', () => {
    const c = nucleiToFindings({ results: parsed.results, map: BUNDLED_FINDING_MAP, scope: 's', subject: { layer: 'L1', nodeId: 'n1' }, importedAt: 'x' });
    expect(c.findings.every((f) => f.subject?.nodeId === 'n1')).toBe(true);
  });

  it('import-kev：取り込んだ CVE で KEV の印が付く', () => {
    const cat = parseKevCatalog({ vulnerabilities: [{ cveID: 'CVE-2099-0001' }] });
    if (!cat.ok) throw new Error(cat.error);
    expect(applyKev(conv.findings, cat.catalog).marked).toBe(1);
  });
});
