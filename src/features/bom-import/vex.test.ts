import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseBom } from './parseBom';
import { vulnerabilitiesToFindings } from './vulnerabilitiesToFindings';
import type { FindingSource } from '../../core/model/types';

const load = (name: string): unknown => JSON.parse(readFileSync(new URL(`./__fixtures__/${name}`, import.meta.url), 'utf-8'));
const SOURCE: FindingSource = { format: 'cyclonedx', product: 'CycloneDX', scope: 'app', importedAt: '2026-11-07T00:00:00.000Z' };
const SUBJECT = { layer: 'L1', nodeId: 'n1' } as const;

function convert(subject?: typeof SUBJECT) {
  const parsed = parseBom(load('sample-vex.cdx.json'));
  if (!parsed.ok) throw new Error(parsed.error);
  return vulnerabilitiesToFindings(parsed.vulnerabilities ?? [], SOURCE, subject, parsed.observedAt);
}

describe('parseBom（ライセンス）', () => {
  it('CycloneDX：license.id・name と expression を読み、重複を除く', () => {
    const r = parseBom(load('sample-vex.cdx.json'));
    expect(r.ok && r.items.map((i) => i.licenses)).toEqual([
      ['MIT', '(Apache-2.0 OR GPL-2.0-only)'],
      ['Example Proprietary License'],
      undefined,
    ]);
  });
  it('CycloneDX：最大 10 件', () => {
    const many = Array.from({ length: 15 }, (_, i) => ({ license: { id: `L-${i}` } }));
    const r = parseBom({ bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ type: 'library', name: 'a', licenses: many }] });
    expect(r.ok && r.items[0].licenses).toHaveLength(10);
  });
  it('SPDX：licenseConcluded を優先し、NOASSERTION・NONE は declared に回して、どちらも無ければ持たない', () => {
    const r = parseBom(load('sample-licenses.spdx.json'));
    expect(r.ok && r.items.map((i) => i.licenses)).toEqual([['MIT'], ['BSD-3-Clause'], undefined, ['MIT OR Apache-2.0']]);
  });
});

describe('vulnerabilitiesToFindings', () => {
  it('脆弱性 × 影響部品ごとに 1 件。VEX 除外と影響部品なしを数える', () => {
    const r = convert(SUBJECT);
    // CVE-2026-0001 × 2 部品 + EXMPL-2026-77 × 1 部品
    expect(r.findings).toHaveLength(3);
    // not_affected(1) + false_positive(2) + resolved(1)
    expect(r.excluded).toBe(4);
    // affects が無い脆弱性と、解決できない ref だけの脆弱性
    expect(r.withoutAffects).toBe(2);
    expect(r.findings.some((f) => f.title?.startsWith('CVE-2026-0002') || f.title?.startsWith('CVE-2026-0003'))).toBe(false);
  });
  it('識別子の scheme・externalId・title・canonicalIds・subject・observedAt', () => {
    const f = convert(SUBJECT).findings.find((x) => x.externalId === 'CVE-2026-0001:pkg:npm/example-lib@1.2.3');
    expect(f).toMatchObject({
      id: 'CycloneDX:CVE-2026-0001:pkg:npm/example-lib@1.2.3',
      title: 'CVE-2026-0001 example-lib@1.2.3',
      canonicalIds: ['known-vulnerability-unpatched'],
      subject: SUBJECT,
      observedAt: '2026-11-01T00:00:00.000Z',
      source: SOURCE,
    });
    expect(f?.identifiers).toEqual([
      { scheme: 'cve', value: 'CVE-2026-0001' },
      { scheme: 'ghsa', value: 'GHSA-aaaa-bbbb-cccc' },
      { scheme: 'purl', value: 'pkg:npm/example-lib@1.2.3' },
    ]);
  });
  it('purl が無い部品は 名前@版 を外部 ID にし、purl の識別子を付けない', () => {
    const f = convert().findings.find((x) => x.externalId === 'CVE-2026-0001:sample-util@0.9.0');
    expect(f?.identifiers.map((i) => i.scheme)).toEqual(['cve', 'ghsa']);
    expect(f?.subject).toBeUndefined();
  });
  it('深刻度：ratings の最大。score だけなら CVSS の帯。別名の scheme は source.name の小文字', () => {
    const r = convert();
    expect(r.findings.find((x) => x.externalId.startsWith('CVE-2026-0001'))).toMatchObject({ severity: 'Critical', sourceSeverity: 'critical' });
    const other = r.findings.find((x) => x.externalId.startsWith('EXMPL-2026-77'));
    expect(other).toMatchObject({ severity: 'High', sourceSeverity: '7.5' });
    expect(other?.identifiers[0]).toEqual({ scheme: 'example-db', value: 'EXMPL-2026-77' });
  });
  it('説明文は持たない', () => {
    expect(JSON.stringify(convert().findings)).not.toContain('この本文');
  });
});
