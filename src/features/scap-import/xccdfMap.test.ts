import { describe, expect, it } from 'vitest';
import { BUNDLED_XCCDF_MAP, loadXccdfMap, xccdfRuleToCanonicalIds } from './xccdfMap';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';

describe('xccdf.yaml', () => {
  it('同梱の対応表を読め、接頭辞つきの idref でも引ける', () => {
    expect(Object.keys(BUNDLED_XCCDF_MAP.rules).length).toBeGreaterThan(0);
    expect(xccdfRuleToCanonicalIds(BUNDLED_XCCDF_MAP, 'xccdf_org.ssgproject.content_rule_service_auditd_enabled')).toEqual([
      'log-not-collected',
    ]);
    expect(xccdfRuleToCanonicalIds(BUNDLED_XCCDF_MAP, 'xccdf_org.ssgproject.content_rule_unknown_rule')).toEqual([]);
    expect(BUNDLED_XCCDF_MAP.ovalClasses.vulnerability).toEqual(['known-vulnerability-unpatched']);
  });

  it('canonicalId はすべて同梱の脅威ライブラリに実在する', () => {
    const known = new Set(BUNDLED_THREAT_LIBRARY.rules.map((r) => r.canonicalId));
    const all = [
      ...Object.entries(BUNDLED_XCCDF_MAP.rules).flatMap(([k, v]) => v.canonicalIds.map((c) => [k, c])),
      ...Object.entries(BUNDLED_XCCDF_MAP.ovalClasses).flatMap(([k, v]) => v.map((c) => [k, c])),
    ];
    for (const [k, c] of all) expect(known.has(c), `${k}: ${c}`).toBe(true);
  });

  it('ルール名が重複するとエラー', () => {
    const text = [
      'schemaVersion: 1',
      'rules:',
      '  a:',
      '    canonicalIds: [x]',
      '  a:',
      '    canonicalIds: [y]',
      'ovalClasses: {}',
      '',
    ].join('\n');
    expect(() => loadXccdfMap(text)).toThrow();
  });
});
