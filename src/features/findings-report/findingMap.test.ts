import { describe, expect, it } from 'vitest';
import { BUNDLED_FINDING_MAP, cweToCanonicalIds, loadFindingMap } from './findingMap';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';

describe('finding map (cwe.yaml)', () => {
  it('同梱の対応表を読める', () => {
    expect(BUNDLED_FINDING_MAP.length).toBeGreaterThan(0);
    expect(cweToCanonicalIds(BUNDLED_FINDING_MAP, 89)).toContain('api-query-injection');
    expect(cweToCanonicalIds(BUNDLED_FINDING_MAP, 79)).toBeUndefined();
  });

  it('対応表の canonicalId はすべて同梱の脅威ライブラリに実在する', () => {
    const known = new Set(BUNDLED_THREAT_LIBRARY.rules.map((r) => r.canonicalId));
    for (const m of BUNDLED_FINDING_MAP) {
      for (const c of m.canonicalIds) expect(known.has(c), `${m.cwe.join(',')}: ${c}`).toBe(true);
    }
  });

  it('CWE が複数の mapping に載るとエラー', () => {
    const text = [
      'schemaVersion: 1',
      'mappings:',
      '  - cwe: [89]',
      '    canonicalIds: [a]',
      '  - cwe: [89, 90]',
      '    canonicalIds: [b]',
      '',
    ].join('\n');
    expect(() => loadFindingMap(text)).toThrow(/CWE-89/);
  });
});
