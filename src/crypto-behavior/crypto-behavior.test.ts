import { describe, expect, it } from 'vitest';
import {
  BUNDLED_ALGORITHM_TABLE,
  BUNDLED_CRYPTO_LIBRARIES,
  BUNDLED_TERMINATION_BEHAVIORS,
  BUNDLED_TERMINATION_OVERLAYS,
  getCryptoLibraries,
  getTerminationBehavior,
  getTerminationBehaviors,
} from './bundled';
import {
  CryptoBehaviorLoadError,
  classifyAlgorithm,
  matchCryptoLibrary,
  normalizePurl,
  parseAlgorithmTable,
  parseCryptoLibraries,
  parseTerminationFile,
} from './loader';
import { componentRegistry } from '../component-library/defaultRegistry';

describe('termination.yaml', () => {
  it('スキーマを通り、27 型を含む', () => {
    expect(BUNDLED_TERMINATION_BEHAVIORS).toHaveLength(27);
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
    expect(infra.length).toBe(19);
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

describe('crypto-libraries.yaml', () => {
  const idOf = (c: { name: string; purl?: string }) =>
    matchCryptoLibrary(c, BUNDLED_CRYPTO_LIBRARIES)?.id;

  it('同梱ファイルがパースでき、id が一意', () => {
    expect(BUNDLED_CRYPTO_LIBRARIES.length).toBeGreaterThan(0);
    const ids = BUNDLED_CRYPTO_LIBRARIES.map((l) => l.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('id の重複は拒否する', () => {
    const dup =
      'schemaVersion: 1\nlibraries:\n  - {id: a, label: A, role: tls, note: n}\n  - {id: a, label: B, role: tls, note: n}\n';
    expect(() => parseCryptoLibraries(dup, 'dup.yaml')).toThrow(CryptoBehaviorLoadError);
  });

  it('purl の版・修飾子・サブパスを除いて小文字にする', () => {
    expect(normalizePurl('pkg:Deb/Debian/libssl3@3.0.11?arch=amd64#sub')).toBe('pkg:deb/debian/libssl3');
  });

  it('purl で照合する', () => {
    expect(idOf({ name: 'libssl3', purl: 'pkg:deb/debian/libssl3@3.0.11?arch=amd64' })).toBe('openssl');
    expect(idOf({ name: 'bcprov-jdk18on', purl: 'pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78' })).toBe(
      'bouncycastle-java',
    );
    expect(idOf({ name: 'stdlib', purl: 'pkg:golang/stdlib@go1.24.1' })).toBe('go-stdlib');
    expect(idOf({ name: 'lodash', purl: 'pkg:npm/lodash' })).toBeUndefined();
  });

  it('purl が無い部品は名前（小文字・完全一致）で照合する', () => {
    expect(idOf({ name: 'openssl' })).toBe('openssl');
    expect(idOf({ name: 'OpenSSL' })).toBe('openssl');
    expect(idOf({ name: 'openssl-extra' })).toBeUndefined();
  });

  it('en オーバーレイで label / note が差し替わり、訳が無い項目は原文', () => {
    const ja = BUNDLED_CRYPTO_LIBRARIES.find((l) => l.id === 'bouncycastle-java');
    const en = getCryptoLibraries('en').find((l) => l.id === 'bouncycastle-java');
    expect(en?.label).toBe('Bouncy Castle (Java)');
    expect(en?.note).not.toBe(ja?.note);
    expect(getCryptoLibraries('ja')).toBe(BUNDLED_CRYPTO_LIBRARIES);
  });
});
