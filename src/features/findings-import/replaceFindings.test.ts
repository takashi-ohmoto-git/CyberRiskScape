import { describe, expect, it } from 'vitest';
import { MAX_FINDINGS, type Finding } from '../../core/model/types';
import { capFindings, normalizeSeverity, replaceFindings } from './replaceFindings';

const mk = (product: string, id: string, scope?: string): Finding => ({
  id,
  source: { format: 'ocsf', product, importedAt: 't', ...(scope ? { scope } : {}) },
  externalId: id,
  identifiers: [],
  severity: 'Low',
  canonicalIds: [],
});

describe('replaceFindings', () => {
  it('同じ製品を置き換え、他製品は残し、新規・解消・継続を数える', () => {
    const existing = [mk('Prowler', 'a'), mk('Prowler', 'b'), mk('Other', 'o')];
    const out = replaceFindings(existing, [mk('Prowler', 'b'), mk('Prowler', 'c')], 'Prowler');
    expect(out.findings.map((x) => x.id).sort()).toEqual(['b', 'c', 'o']);
    expect(out.diff).toEqual({ added: 1, resolved: 1, continued: 1 });
  });

  it('既存が無ければ全て新規', () => {
    expect(replaceFindings(undefined, [mk('Prowler', 'a')], 'Prowler').diff).toEqual({
      added: 1,
      resolved: 0,
      continued: 0,
    });
  });

  it('範囲（ホスト）が違う指摘は置き換えない', () => {
    const existing = [mk('OpenSCAP', 'a1', 'host-a'), mk('OpenSCAP', 'b1', 'host-b')];
    const out = replaceFindings(existing, [mk('OpenSCAP', 'b2', 'host-b')], 'OpenSCAP', 'host-b');
    expect(out.findings.map((x) => x.id).sort()).toEqual(['a1', 'b2']);
    expect(out.diff).toEqual({ added: 1, resolved: 1, continued: 0 });
  });

  it('範囲なしの取り込みは範囲ありの指摘を消さない', () => {
    const out = replaceFindings([mk('X', 'h', 'host-a'), mk('X', 'n')], [], 'X');
    expect(out.findings.map((x) => x.id)).toEqual(['h']);
  });
});

describe('replaceFindings（識別子の表記）', () => {
  it('取り込む指摘の識別子の表記をそろえて書き込む。指摘の ID と既存の指摘は変えない', () => {
    const existing = { ...mk('Other', 'o1'), identifiers: [{ scheme: 'CVE', value: 'cve-2020-1' }] };
    const incoming = {
      ...mk('Scanner', 's1'),
      identifiers: [
        { scheme: 'CVE', value: ' cve-2024-1234 ' },
        { scheme: 'cve', value: 'CVE-2024-1234' },
        { scheme: 'cwe', value: 'CWE-79' },
      ],
    };
    const { findings } = replaceFindings([existing], [incoming], 'Scanner');
    expect(findings.find((f) => f.id === 's1')?.identifiers).toEqual([
      { scheme: 'cve', value: 'CVE-2024-1234' },
      { scheme: 'cwe', value: '79' },
    ]);
    expect(findings.find((f) => f.id === 'o1')).toBe(existing);
  });
});

describe('normalizeSeverity', () => {
  it.each([
    ['critical', 'Critical'],
    ['High', 'High'],
    ['Important', 'High'],
    ['medium', 'Medium'],
    ['Moderate', 'Medium'],
    ['low', 'Low'],
    ['info', 'Low'],
    ['Informational', 'Low'],
    ['unknown', 'Low'],
    [undefined, 'Low'],
  ] as const)('%s → %s', (raw, expected) => {
    expect(normalizeSeverity(raw)).toBe(expected);
  });
});

describe('capFindings', () => {
  it('上限を超えた分を切り、件数を返す', () => {
    const many = Array.from({ length: MAX_FINDINGS + 3 }, (_, i) => mk('P', `p${i}`));
    const out = capFindings(many);
    expect(out.findings).toHaveLength(MAX_FINDINGS);
    expect(out.truncated).toBe(3);
  });
});
