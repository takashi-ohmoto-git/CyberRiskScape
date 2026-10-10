import { describe, expect, it } from 'vitest';
import {
  BUNDLED_ALGORITHM_TABLE,
  BUNDLED_TERMINATION_BEHAVIORS,
  BUNDLED_TERMINATION_OVERLAYS,
  getTerminationBehavior,
  getTerminationBehaviors,
} from './bundled';
import {
  CryptoBehaviorLoadError,
  classifyAlgorithm,
  parseAlgorithmTable,
  parseTerminationFile,
} from './loader';
import { componentRegistry } from '../component-library/defaultRegistry';

describe('termination.yaml', () => {
  it('スキーマを通り、22 型を含む', () => {
    expect(BUNDLED_TERMINATION_BEHAVIORS).toHaveLength(22);
  });

  it('componentType が一意', () => {
    const ids = BUNDLED_TERMINATION_BEHAVIORS.map((b) => b.componentType);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('すべての componentType が同梱のコンポーネントライブラリに存在する', () => {
    const missing = BUNDLED_TERMINATION_BEHAVIORS.filter(
      (b) => !componentRegistry.has(b.componentType),
    );
    expect(missing.map((b) => b.componentType)).toEqual([]);
  });

  it('network-infra の型は HSM（経路外）以外すべて載っている', () => {
    const covered = new Set(BUNDLED_TERMINATION_BEHAVIORS.map((b) => b.componentType));
    const infra = componentRegistry
      .getAll()
      .filter((c) => componentRegistry.getLibraryIdOf(c.id) === 'network-infra')
      .map((c) => c.id);
    expect(infra.length).toBe(18);
    for (const id of infra) {
      if (id === 'HSM') expect(covered.has(id)).toBe(false);
      else expect(covered.has(id), id).toBe(true);
    }
  });

  it('alternatives に default を含まない（スキーマも拒否する）', () => {
    for (const b of BUNDLED_TERMINATION_BEHAVIORS) expect(b.alternatives).not.toContain(b.default);
    const bad =
      'schemaVersion: 1\nbehaviors:\n  - componentType: X\n    default: terminate\n    alternatives: [terminate]\n    note: n\n';
    expect(() => parseTerminationFile(bad, 't')).toThrow(CryptoBehaviorLoadError);
  });

  it('componentType の重複は throw', () => {
    const dup =
      'schemaVersion: 1\nbehaviors:\n  - componentType: X\n    default: terminate\n    alternatives: []\n    note: n\n  - componentType: X\n    default: tunnel\n    alternatives: []\n    note: n\n';
    expect(() => parseTerminationFile(dup, 't')).toThrow(/Duplicate/);
  });

  it('en オーバーレイは原本の全型を過不足なく訳している', () => {
    const ids = BUNDLED_TERMINATION_BEHAVIORS.map((b) => b.componentType).sort();
    expect(Object.keys(BUNDLED_TERMINATION_OVERLAYS.en ?? {}).sort()).toEqual(ids);
  });

  it('en では note が訳され default は変わらない。ja は原本そのもの', () => {
    const ja = getTerminationBehavior('LOAD_BALANCER', 'ja');
    const en = getTerminationBehavior('LOAD_BALANCER', 'en');
    expect(en?.default).toBe(ja?.default);
    expect(en?.note).not.toBe(ja?.note);
    expect(getTerminationBehaviors('ja')).toBe(BUNDLED_TERMINATION_BEHAVIORS);
  });

  it('YAML に無い型は undefined（端点扱い）', () => {
    expect(getTerminationBehavior('DATABASE', 'ja')).toBeUndefined();
  });
});

describe('classifyAlgorithm', () => {
  const t = BUNDLED_ALGORITHM_TABLE;
  it.each([
    ['X25519MLKEM768', 'pqc'],
    ['ML-DSA-65', 'pqc'],
    ['slh-dsa-sha2-128s', 'pqc'],
    ['LMS', 'pqc'],
    ['ECDHE P-256', 'vulnerable'],
    ['RSA 2048', 'vulnerable'],
    ['Ed25519', 'vulnerable'],
    ['X25519Kyber768Draft00', 'transitional'],
    ['AES-256-GCM', null],
    ['', null],
    ['   ', null],
  ])('%s -> %s', (name, expected) => {
    expect(classifyAlgorithm(name, t)).toBe(expected);
  });

  it('優先順位は YAML 側が持つ（変えればハイブリッドの判定も変わる）', () => {
    const flipped = { ...t, priority: ['vulnerable', 'transitional', 'pqc'] as typeof t.priority };
    expect(classifyAlgorithm('X25519MLKEM768', flipped)).toBe('vulnerable');
  });

  it('priority が重複していると拒否する', () => {
    const bad =
      'schemaVersion: 1\npriority: [pqc, pqc, vulnerable]\nclasses:\n  pqc: {tokens: [a]}\n  transitional: {tokens: [b]}\n  vulnerable: {tokens: [c]}\n';
    expect(() => parseAlgorithmTable(bad, 't')).toThrow(CryptoBehaviorLoadError);
  });
});
