import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseBom } from './parseBom';
import { vulnerabilitiesToFindings } from './vulnerabilitiesToFindings';
import type { FindingSource } from '../../core/model/types';

const raw: unknown = JSON.parse(readFileSync(new URL('./__fixtures__/trivy.cdx.json', import.meta.url), 'utf-8'));
const SOURCE: FindingSource = { format: 'cyclonedx', product: 'trivy', scope: 'app', importedAt: '2026-11-07T00:00:00.000Z' };

describe('parseBom（Trivy の CycloneDX）', () => {
  it('形式・版・製品を tools.components から読み、部品 2・脆弱性 2 を返す', () => {
    const r = parseBom(raw);
    expect(r).toMatchObject({ ok: true, format: 'cyclonedx', specVersion: '1.6', product: 'trivy', productVersion: '0.76.2' });
    expect(r.ok && r.items).toHaveLength(2);
    expect(r.ok && r.vulnerabilities).toHaveLength(2);
  });
});

describe('vulnerabilitiesToFindings（Trivy の CycloneDX）', () => {
  const parsed = parseBom(raw);
  if (!parsed.ok) throw new Error(parsed.error);
  const out = vulnerabilitiesToFindings(parsed.vulnerabilities ?? [], SOURCE, undefined, parsed.observedAt);

  it('脆弱性 × 影響部品ごとに 1 件（3 件）→ 除外なし', () => {
    expect(out.findings).toHaveLength(3);
    expect(out.excluded).toBe(0);
    expect(out.withoutAffects).toBe(0);
  });

  it('canonicalIds は known-vulnerability-unpatched のみ → 識別子は cve と purl で CWE は持たない', () => {
    for (const f of out.findings) {
      expect(f.canonicalIds).toEqual(['known-vulnerability-unpatched']);
      expect(f.identifiers.some((i) => i.scheme === 'cve')).toBe(true);
      expect(f.identifiers.some((i) => i.scheme === 'purl')).toBe(true);
      expect(f.identifiers.some((i) => i.scheme === 'cwe')).toBe(false);
    }
  });

  it('深刻度は ratings の最大（high → High、medium と low → Medium）', () => {
    const sev = (id: string, name: string) => out.findings.find((f) => f.externalId.startsWith(id) && f.title?.includes(name))?.severity;
    expect(sev('CVE-2026-0101', 'example-lib')).toBe('High');
    expect(sev('CVE-2026-0102', 'example-lib')).toBe('Medium');
    expect(sev('CVE-2026-0102', 'example-os-pkg')).toBe('Medium');
  });

  it('description・recommendation の本文は保存しない', () => {
    const text = JSON.stringify(out.findings);
    expect(text).not.toContain('fictitious-vuln-description-body');
    expect(text).not.toContain('fictitious-shared-vuln-description-body');
    expect(text).not.toContain('Upgrade example-lib');
  });
});
