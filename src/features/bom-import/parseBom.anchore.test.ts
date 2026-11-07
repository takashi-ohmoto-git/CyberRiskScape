import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseBom } from './parseBom';
import { vulnerabilitiesToFindings } from './vulnerabilitiesToFindings';
import type { FindingSource } from '../../core/model/types';

const load = (name: string): unknown => JSON.parse(readFileSync(new URL(`./__fixtures__/${name}`, import.meta.url), 'utf-8'));
const SOURCE: FindingSource = { format: 'cyclonedx', product: 'grype', scope: 'app', importedAt: '2026-11-07T00:00:00.000Z' };

describe('parseBom（Syft の CycloneDX）', () => {
  it('形式・版・製品を tools.components から読み、部品 3 を返し脆弱性は持たない', () => {
    const r = parseBom(load('syft.cdx.json'));
    expect(r).toMatchObject({ ok: true, format: 'cyclonedx', specVersion: '1.7', product: 'syft', productVersion: '1.57.0' });
    expect(r.ok && r.items).toHaveLength(3);
    expect(r.ok && (r.vulnerabilities ?? [])).toHaveLength(0);
  });

  it('licenses の id を読む', () => {
    const r = parseBom(load('syft.cdx.json'));
    const lib = r.ok ? r.items.find((i) => i.name === 'example-lib') : undefined;
    expect(lib?.licenses).toEqual(['MIT']);
  });
});

describe('parseBom・vulnerabilitiesToFindings（Grype の CycloneDX）', () => {
  const parsed = parseBom(load('grype.cdx.json'));
  if (!parsed.ok) throw new Error(parsed.error);
  const out = vulnerabilitiesToFindings(parsed.vulnerabilities ?? [], SOURCE, undefined, parsed.observedAt);

  it('製品は grype、部品 3・脆弱性 2 を返す', () => {
    expect(parsed).toMatchObject({ format: 'cyclonedx', specVersion: '1.7', product: 'grype', productVersion: '0.121.2' });
    expect(parsed.items).toHaveLength(3);
    expect(parsed.vulnerabilities).toHaveLength(2);
  });

  it('affects を bom-ref で部品に解決し、脆弱性 × 影響部品で 3 件 → 除外なし', () => {
    expect(out.findings).toHaveLength(3);
    expect(out.excluded).toBe(0);
    expect(out.withoutAffects).toBe(0);
  });

  it('canonicalIds は known-vulnerability-unpatched のみ → CVE は cve、GHSA は ghsa を持ち CWE は持たない', () => {
    for (const f of out.findings) {
      expect(f.canonicalIds).toEqual(['known-vulnerability-unpatched']);
      expect(f.identifiers.some((i) => i.scheme === 'cwe')).toBe(false);
    }
    const cve = out.findings.filter((f) => f.externalId.startsWith('CVE-2026-0301'));
    const ghsa = out.findings.filter((f) => f.externalId.startsWith('GHSA-'));
    expect(cve).toHaveLength(1);
    expect(ghsa).toHaveLength(2);
    expect(cve[0].identifiers.some((i) => i.scheme === 'cve')).toBe(true);
    expect(ghsa.every((f) => f.identifiers.some((i) => i.scheme === 'ghsa'))).toBe(true);
  });

  it('深刻度は ratings の最大（CVSS high → High、medium → Medium。EPSS は含めない）', () => {
    const sev = (id: string) => out.findings.find((f) => f.externalId.startsWith(id))?.severity;
    expect(sev('CVE-2026-0301')).toBe('High');
    expect(sev('GHSA-')).toBe('Medium');
  });

  it('method が EPSS の rating は深刻度に使わず、epss に確率として保存する', () => {
    const cve = out.findings.find((f) => f.externalId.startsWith('CVE-2026-0301'));
    expect(cve?.epss).toEqual({ score: 0.12 });
    expect(cve?.severity).toBe('High');
    expect(out.findings.filter((f) => f.externalId.startsWith('GHSA-')).every((f) => f.epss === undefined)).toBe(true);
  });

  it('EPSS の rating しか無い脆弱性は、深刻度が rating なしの既定（Low）で epss が付く。範囲外の score は無視', () => {
    const part = parsed.items[0];
    const base = { id: 'CVE-2026-0999', references: [], affects: [part] };
    const only = vulnerabilitiesToFindings([{ ...base, ratings: [{ score: 0.8, method: 'epss' }] }], SOURCE, undefined, undefined);
    expect(only.findings[0]).toMatchObject({ severity: 'Low', epss: { score: 0.8 } });
    expect(only.findings[0].sourceSeverity).toBeUndefined();
    const bad = vulnerabilitiesToFindings([{ ...base, ratings: [{ score: 7.5, method: 'EPSS' }] }], SOURCE, undefined, undefined);
    expect(bad.findings[0].epss).toBeUndefined();
    expect(bad.findings[0].severity).toBe('Low');
  });

  it('description の本文は保存しない', () => {
    expect(JSON.stringify(out.findings)).not.toContain('GRYPE-SECRET-MARKER');
  });
});
