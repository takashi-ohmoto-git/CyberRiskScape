import { describe, expect, it } from 'vitest';
import { applyVulnIntel, recordEpss, recordKev } from './vulnIntel';
import type { Finding, FindingKev, VulnIntel } from '../../core/model/types';

const finding = (id: string, cves: string[], extra: Partial<Finding> = {}): Finding => ({
  id,
  source: { format: 'sarif', product: 'Scanner', importedAt: '2026-11-01T00:00:00Z' },
  externalId: id,
  identifiers: cves.map((value) => ({ scheme: 'cve', value })),
  severity: 'High',
  canonicalIds: [],
  ...extra,
});

const KEV: FindingKev = { dateAdded: '2099-01-01', ransomware: true };
const kevEntries = (...cves: string[]) => new Map(cves.map((c) => [c, KEV] as const));

describe('recordKev', () => {
  it('指摘が持つ CVE のうち、カタログに載っているものだけを記録する', () => {
    const intel = recordKev(undefined, [finding('a', ['CVE-2099-0001', 'CVE-2099-0002'])], kevEntries('CVE-2099-0001', 'CVE-2099-9999'));
    expect(intel).toEqual({ 'CVE-2099-0001': { kev: KEV } });
  });

  it('CVE の表記が違っても同じ CVE として記録する（キーは大文字）', () => {
    const f = { ...finding('a', []), identifiers: [{ scheme: 'CVE', value: 'cve-2099-0001' }] };
    expect(recordKev(undefined, [f], kevEntries('CVE-2099-0001'))).toEqual({ 'CVE-2099-0001': { kev: KEV } });
  });

  it('前回の KEV の記録は入れ替え、EPSS の記録は残す', () => {
    const prev: VulnIntel = {
      'CVE-2099-0001': { kev: KEV, epss: { score: 0.5 } },
      'CVE-2099-0002': { kev: KEV },
    };
    const intel = recordKev(prev, [finding('a', ['CVE-2099-0001', 'CVE-2099-0002', 'CVE-2099-0003'])], kevEntries('CVE-2099-0003'));
    expect(intel).toEqual({
      'CVE-2099-0001': { epss: { score: 0.5 } },
      'CVE-2099-0003': { kev: KEV },
    });
  });

  it('何も当たらず、前回の記録も残らなければ undefined', () => {
    expect(recordKev({ 'CVE-2099-0001': { kev: KEV } }, [finding('a', ['CVE-2099-0001'])], new Map())).toBeUndefined();
  });
});

describe('recordEpss', () => {
  it('スコア・パーセンタイル・日付を記録し、KEV の記録は残す', () => {
    const scores = new Map([['CVE-2099-0001', { score: 0.9, percentile: 0.99 }]]);
    const intel = recordEpss({ 'CVE-2099-0001': { kev: KEV } }, [finding('a', ['CVE-2099-0001'])], scores, '2099-01-02');
    expect(intel).toEqual({ 'CVE-2099-0001': { kev: KEV, epss: { score: 0.9, percentile: 0.99, date: '2099-01-02' } } });
  });
});

describe('applyVulnIntel', () => {
  const intel: VulnIntel = {
    'CVE-2099-0001': { kev: KEV, epss: { score: 0.2 } },
    'CVE-2099-0002': { epss: { score: 0.8 } },
  };

  it('記録が無ければ同じ配列を返す', () => {
    const fs = [finding('a', ['CVE-2099-0001'])];
    expect(applyVulnIntel(fs, undefined)).toBe(fs);
  });

  it('記録に載っている CVE を持つ指摘に、KEV と EPSS を付ける', () => {
    const [a] = applyVulnIntel([finding('a', ['CVE-2099-0001'])], intel);
    expect(a.kev).toEqual(KEV);
    expect(a.epss).toEqual({ score: 0.2 });
  });

  it('CVE が複数なら、EPSS は最大の score を採る', () => {
    const [a] = applyVulnIntel([finding('a', ['CVE-2099-0001', 'CVE-2099-0002'])], intel);
    expect(a.kev).toEqual(KEV);
    expect(a.epss).toEqual({ score: 0.8 });
  });

  it('記録の値を優先する（診断ツールが付けた古い EPSS を上書きする）', () => {
    const [a] = applyVulnIntel([finding('a', ['CVE-2099-0002'], { epss: { score: 0.1 } })], intel);
    expect(a.epss).toEqual({ score: 0.8 });
  });

  it('記録に無い CVE の指摘・CVE を持たない指摘は触らない（ツールが付けた EPSS も残す）', () => {
    const fs = [finding('a', ['CVE-2099-7777'], { epss: { score: 0.3 } }), finding('b', [])];
    expect(applyVulnIntel(fs, intel)).toBe(fs);
  });

  it('プロトタイプの名前を CVE に持つ指摘で誤って当たらない', () => {
    const f = { ...finding('a', []), identifiers: [{ scheme: 'cve', value: 'constructor' }] };
    const fs = [f];
    expect(applyVulnIntel(fs, intel)).toBe(fs);
  });
});
