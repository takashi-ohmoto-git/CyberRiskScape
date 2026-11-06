import { describe, expect, it } from 'vitest';
import type { Finding } from '../../core/model/types';
import { applyKev, parseKevCatalog } from './applyKev';

function finding(id: string, cve?: string, extra: Partial<Finding> = {}): Finding {
  return {
    id,
    source: { format: 'cyclonedx', product: 'x', importedAt: '2026-11-01T00:00:00Z' },
    externalId: id,
    identifiers: cve ? [{ scheme: 'cve', value: cve }] : [],
    severity: 'Medium',
    canonicalIds: [],
    ...extra,
  } as Finding;
}

const CATALOG = {
  catalogVersion: '2026.01.01',
  dateReleased: '2026-01-01T00:00:00Z',
  vulnerabilities: [
    { cveID: 'CVE-2099-0001', dateAdded: '2026-01-01', dueDate: '2026-01-22', knownRansomwareCampaignUse: 'Known' },
    { cveID: 'CVE-2099-0002', dateAdded: '2026-01-02', knownRansomwareCampaignUse: 'Unknown' },
  ],
};

function catalog() {
  const r = parseKevCatalog(CATALOG);
  if (!r.ok) throw new Error(r.error);
  return r.catalog;
}

describe('parseKevCatalog', () => {
  it('カタログを読み、ランサムウェア利用を真偽にする', () => {
    const c = catalog();
    expect(c.catalogVersion).toBe('2026.01.01');
    expect(c.entries.get('CVE-2099-0001')).toEqual({
      dateAdded: '2026-01-01',
      dueDate: '2026-01-22',
      ransomware: true,
      catalogVersion: '2026.01.01',
    });
    expect(c.entries.get('CVE-2099-0002')?.ransomware).toBe(false);
  });

  it.each([null, 'x', {}, { vulnerabilities: 'a' }, { vulnerabilities: [{ dateAdded: '2026-01-01' }] }])(
    '不正な JSON は拒否する: %j',
    (raw) => {
      expect(parseKevCatalog(raw).ok).toBe(false);
    },
  );
});

describe('applyKev', () => {
  it('CVE を大文字小文字を無視して照合し、印を付ける', () => {
    const r = applyKev([finding('a', 'cve-2099-0001'), finding('b', 'CVE-2099-9999'), finding('c')], catalog());
    expect(r).toMatchObject({ checked: 2, marked: 1, cleared: 0 });
    expect(r.findings[0].kev).toMatchObject({ dateAdded: '2026-01-01', ransomware: true });
    expect(r.findings[1].kev).toBeUndefined();
    expect(r.findings[2].kev).toBeUndefined();
  });

  it('カタログに無くなった指摘からは印を外す。CVE を持たない指摘の印は触らない', () => {
    const stale = { dateAdded: '2020-01-01' };
    const r = applyKev([finding('a', 'CVE-2099-9999', { kev: stale }), finding('b', undefined, { kev: stale })], catalog());
    expect(r.cleared).toBe(1);
    expect('kev' in r.findings[0]).toBe(false);
    expect(r.findings[1].kev).toEqual(stale);
  });
});
