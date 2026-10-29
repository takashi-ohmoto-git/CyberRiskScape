import { describe, expect, it } from 'vitest';
import {
  BUNDLED_PROWLER_MAP,
  FIELD_VALUE_ORDER,
  attackSurfaceKeyOf,
  betterValue,
  findProwlerMapping,
  loadProwlerMap,
  worseValue,
} from './prowlerMap';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';
import { POSTURE_FIELD_VALUES, type PostureEnumKey } from '../../core/model/types';

describe('prowler map (prowler.yaml)', () => {
  it('同梱の対応表を読める', () => {
    expect(BUNDLED_PROWLER_MAP.length).toBeGreaterThan(0);
    expect(findProwlerMapping(BUNDLED_PROWLER_MAP, 's3_bucket_default_encryption')?.set?.field).toBe(
      'encryptionAtRest',
    );
    expect(findProwlerMapping(BUNDLED_PROWLER_MAP, 'no_such_check')).toBeUndefined();
  });

  it('検査 ID に重複がない', () => {
    const all = BUNDLED_PROWLER_MAP.flatMap((m) => m.checks);
    expect(new Set(all).size).toBe(all.length);
  });

  it('canonicalIds はすべて同梱の脅威ライブラリに実在する', () => {
    const known = new Set(BUNDLED_THREAT_LIBRARY.rules.map((r) => r.canonicalId));
    for (const m of BUNDLED_PROWLER_MAP) {
      for (const c of m.canonicalIds ?? []) expect(known.has(c), `${m.checks[0]}: ${c}`).toBe(true);
    }
  });

  it('set の項目と値は型定義の列挙に適合する', () => {
    for (const m of BUNDLED_PROWLER_MAP) {
      if (!m.set) continue;
      const order = FIELD_VALUE_ORDER[m.set.field];
      expect(order, m.set.field).toBeDefined();
      for (const v of [m.set.pass, m.set.fail]) {
        if (v === undefined) continue;
        expect(order).toContain(v);
        if (attackSurfaceKeyOf(m.set.field)) expect(typeof v).toBe('boolean');
      }
    }
  });

  it('値の順序表は運用状況の列挙と同じ集合', () => {
    for (const [field, order] of Object.entries(FIELD_VALUE_ORDER)) {
      if (attackSurfaceKeyOf(field)) {
        expect([...order].sort()).toEqual([false, true]);
      } else {
        const enumValues = POSTURE_FIELD_VALUES[field as PostureEnumKey] as readonly string[];
        expect([...order].sort()).toEqual([...enumValues].sort());
      }
    }
  });

  it('accountReview は FAIL の Irregular のみ（PASS では値を入れない）', () => {
    for (const m of BUNDLED_PROWLER_MAP) {
      if (m.set?.field !== 'accountReview') continue;
      expect(m.set.pass).toBeUndefined();
      expect(m.set.fail).toBe('Irregular');
    }
  });

  it('logRetention は PASS の OneYearOrMore のみ', () => {
    const m = findProwlerMapping(BUNDLED_PROWLER_MAP, 'cloudwatch_log_group_retention_policy_specific_days_enabled');
    expect(m?.set).toEqual({ field: 'logRetention', pass: 'OneYearOrMore' });
  });

  it('keyTypeUnverified は暗号化の PASS の ProviderManagedKey にだけ付き、CMK の検査には付かない', () => {
    const flagged = BUNDLED_PROWLER_MAP.filter((m) => m.set?.keyTypeUnverified);
    expect(flagged.length).toBeGreaterThan(0);
    for (const m of flagged) expect(m.set).toMatchObject({ field: 'encryptionAtRest', pass: 'ProviderManagedKey' });
    for (const m of BUNDLED_PROWLER_MAP) {
      if (m.set?.pass === 'CustomerManagedKey') expect(m.set.keyTypeUnverified).toBeUndefined();
    }
    expect(findProwlerMapping(BUNDLED_PROWLER_MAP, 's3_bucket_kms_encryption')?.set?.keyTypeUnverified).toBe(true);
    expect(() =>
      loadProwlerMap(
        'schemaVersion: 1\nmappings:\n  - checks: [a]\n    set: { field: logCollection, pass: Collected, keyTypeUnverified: true }\n',
      ),
    ).toThrow(/keyTypeUnverified/);
  });

  it('不正な対応表はエラー', () => {
    const base = (set: string, extra = '') =>
      `schemaVersion: 1\nmappings:\n  - checks: [a]\n    set: ${set}\n${extra}`;
    expect(() => loadProwlerMap(base('{ field: encryptionAtRest, pass: Nope }'))).toThrow(/不正な値/);
    expect(() => loadProwlerMap(base('{ field: nothing, pass: x }'))).toThrow(/未対応の項目/);
    expect(() => loadProwlerMap(base('{ field: encryptionAtRest }'))).toThrow(/pass も fail も/);
    expect(() =>
      loadProwlerMap('schemaVersion: 1\nmappings:\n  - checks: [a]\n  - checks: [b, a]\n'),
    ).toThrow(/複数のエントリ/);
  });

  it('良い値・悪い値の判定（順序は 1 か所）', () => {
    expect(worseValue('encryptionAtRest', 'ProviderManagedKey', 'None')).toBe('None');
    expect(betterValue('encryptionAtRest', 'ProviderManagedKey', 'CustomerManagedKey')).toBe('CustomerManagedKey');
    expect(worseValue('attackSurface.hasGlobalIp', false, true)).toBe(true);
    expect(betterValue('attackSurface.hasAccessLog', false, true)).toBe(true);
  });
});
