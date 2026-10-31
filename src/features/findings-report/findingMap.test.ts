import { describe, expect, it } from 'vitest';
import {
  BUNDLED_AITECH_MAP,
  BUNDLED_FINDING_MAP,
  aitechToCanonicalIds,
  cweToCanonicalIds,
  loadAitechMap,
  loadFindingMap,
} from './findingMap';
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

describe('AITech 対応表（aitech.yaml）', () => {
  it('同梱の対応表を読める', () => {
    expect(BUNDLED_AITECH_MAP.length).toBeGreaterThan(0);
  });

  it('対応表の canonicalId はすべて同梱の脅威ライブラリに実在する', () => {
    const known = new Set(BUNDLED_THREAT_LIBRARY.rules.map((r) => r.canonicalId));
    for (const m of BUNDLED_AITECH_MAP) {
      for (const c of m.canonicalIds) expect(known.has(c), `${[...(m.aitech ?? []), ...(m.aisubtech ?? [])]}: ${c}`).toBe(true);
    }
  });

  it('AISubtech の行 → 無ければ親の AITech の行で引く', () => {
    const map = loadAitechMap(
      [
        'schemaVersion: 1',
        'mappings:',
        '  - aisubtech: [AISubtech-2.1.1]',
        '    canonicalIds: [sub]',
        '  - aitech: [AITech-2.1, AITech-12.1]',
        '    canonicalIds: [tech]',
        '',
      ].join('\n'),
    );
    expect(aitechToCanonicalIds(map, 'AITech-2.1', 'AISubtech-2.1.1')).toEqual(['sub']);
    expect(aitechToCanonicalIds(map, 'AITech-2.1', 'AISubtech-2.1.9')).toEqual(['tech']);
    expect(aitechToCanonicalIds(map, 'AITech-2.1', undefined)).toEqual(['tech']);
    expect(aitechToCanonicalIds(map, undefined, 'AISubtech-12.1.5')).toEqual(['tech']);
    expect(aitechToCanonicalIds(map, 'AITech-15.1', 'AISubtech-15.1.9')).toBeUndefined();
    expect(aitechToCanonicalIds(map, undefined, undefined)).toBeUndefined();
  });

  it('同じコードが複数の mapping に載るとエラー', () => {
    const text = ['schemaVersion: 1', 'mappings:', '  - aitech: [AITech-1.1]', '    canonicalIds: [a]', '  - aitech: [AITech-1.1]', '    canonicalIds: [b]', ''].join('\n');
    expect(() => loadAitechMap(text)).toThrow(/AITech-1\.1/);
  });

  it('aitech と aisubtech はどちらか一方が必須（両方・無しはエラー）', () => {
    const both = ['schemaVersion: 1', 'mappings:', '  - aitech: [AITech-1.1]', '    aisubtech: [AISubtech-1.1.1]', '    canonicalIds: [a]', ''].join('\n');
    const none = ['schemaVersion: 1', 'mappings:', '  - canonicalIds: [a]', ''].join('\n');
    expect(() => loadAitechMap(both)).toThrow();
    expect(() => loadAitechMap(none)).toThrow();
  });
});
