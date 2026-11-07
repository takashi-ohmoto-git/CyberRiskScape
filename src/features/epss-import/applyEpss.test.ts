import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { applyEpss, parseEpssCsv } from './applyEpss';
import type { Finding } from '../../core/model/types';

const fixture = readFileSync(new URL('./__fixtures__/epss_scores.csv', import.meta.url), 'utf-8');

function finding(id: string, cves: string[], extra: Partial<Finding> = {}): Finding {
  return {
    id,
    source: { format: 'cyclonedx', product: 'x', importedAt: '2026-11-01T00:00:00Z' },
    externalId: id,
    identifiers: cves.map((value) => ({ scheme: 'cve', value })),
    severity: 'Low',
    canonicalIds: [],
    ...extra,
  } as Finding;
}

describe('parseEpssCsv', () => {
  it('コメント行・ヘッダ・行を読み、CVE は大文字にする', () => {
    const r = parseEpssCsv(fixture);
    if (!r.ok) throw new Error(r.error);
    expect(r.date).toBe('2099-01-02T00:00:00+0000');
    expect(r.modelVersion).toBe('v2099.01.01');
    expect(r.scores.size).toBe(4);
    expect(r.scores.get('CVE-2099-0001')).toEqual({ score: 0.5, percentile: 0.97 });
    expect(r.invalid).toBe(0);
  });

  it('コメント行が無くても読め、CRLF も可。範囲外・数値でない・CVE でない行は invalid に数える', () => {
    const r = parseEpssCsv(
      'cve,epss,percentile\r\ncve-2099-0001,0.1,0.2\r\nCVE-2099-0002,1.5,0.2\r\nCVE-2099-0003,abc,0.2\r\nnot-a-cve,0.1,0.1\r\nCVE-2099-0005,0.3,\r\n',
    );
    if (!r.ok) throw new Error(r.error);
    expect(r.date).toBeUndefined();
    expect([...r.scores.keys()]).toEqual(['CVE-2099-0001', 'CVE-2099-0005']);
    expect(r.scores.get('CVE-2099-0005')).toEqual({ score: 0.3 });
    expect(r.invalid).toBe(3);
  });

  it('ヘッダが無い・空は不正', () => {
    expect(parseEpssCsv('CVE-2099-0001,0.1,0.2\n').ok).toBe(false);
    expect(parseEpssCsv('').ok).toBe(false);
  });

  it('30 万行でも読める', () => {
    const rows = Array.from({ length: 300_000 }, (_, i) => `CVE-2099-${String(i + 1).padStart(6, '0')},0.01000,0.50000`);
    const r = parseEpssCsv(`cve,epss,percentile\n${rows.join('\n')}\n`);
    expect(r.ok && r.scores.size).toBe(300_000);
  });
});

describe('applyEpss', () => {
  const parsed = parseEpssCsv(fixture);
  if (!parsed.ok) throw new Error(parsed.error);

  it('付ける：score・percentile・date。複数 CVE は最大の score とその percentile', () => {
    const r = applyEpss([finding('a', ['cve-2099-0001']), finding('b', ['CVE-2099-0002', 'CVE-2099-0004'])], parsed);
    expect(r).toMatchObject({ checked: 2, matched: 2, removed: 0 });
    expect(r.findings[0].epss).toEqual({ score: 0.5, percentile: 0.97, date: '2099-01-02T00:00:00+0000' });
    expect(r.findings[1].epss?.score).toBe(0.9);
  });

  it('一覧に CVE が無い指摘は、付いていた epss を外す。付いていなければ数えない', () => {
    const r = applyEpss([finding('a', ['CVE-2099-9999'], { epss: { score: 0.7 } }), finding('b', ['CVE-2099-9998'])], parsed);
    expect(r).toMatchObject({ checked: 2, matched: 0, removed: 1 });
    expect(r.findings[0].epss).toBeUndefined();
  });

  it('CVE を持たない指摘は触らない（出し手が付けた epss も残す）', () => {
    const f = finding('n', [], { epss: { score: 0.4 } });
    const r = applyEpss([f], parsed);
    expect(r).toMatchObject({ checked: 0, matched: 0, removed: 0 });
    expect(r.findings[0]).toBe(f);
  });
});
