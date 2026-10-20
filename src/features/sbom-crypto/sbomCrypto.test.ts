import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { DiagramEdge, DiagramNode } from '../../core/model/types';
import { BUNDLED_ALGORITHM_TABLE, getCryptoLibraries } from '../../crypto-behavior/bundled';
import { buildSbomCryptoReport, edgesTouchingNode, type SbomCryptoReport } from './buildSbomCryptoReport';
import { parseCycloneDx, parseSbomText } from './parseCycloneDx';
import { sbomCryptoToJson, sbomCryptoToMarkdown } from './sbomCryptoOutput';

const fixture = (name: string): string =>
  readFileSync(new URL(`./__fixtures__/${name}`, import.meta.url), 'utf-8');

const node = (over: Partial<DiagramNode> = {}) =>
  ({ id: 'n-1', seq: 3, type: 'WEB', label: 'API サーバー', x: 0, y: 0, ...over }) as DiagramNode;
const peer = { id: 'n-2', seq: 4, type: 'USER', label: '利用者', x: 0, y: 0 } as DiagramNode;
const edge = { id: 'e-1', seq: 2, source: 'n-2', target: 'n-1', crypto: { kex: 'ECDHE P-256' } } as DiagramEdge;

function report(name: string, n: DiagramNode = node(), locale: 'ja' | 'en' = 'ja'): SbomCryptoReport {
  const parsed = parseSbomText(fixture(name));
  if (!parsed.ok) throw new Error(parsed.error);
  return buildSbomCryptoReport({
    parsed,
    node: n,
    edges: edgesTouchingNode(n, [n, peer], [edge]),
    algorithms: BUNDLED_ALGORITHM_TABLE,
    libraries: getCryptoLibraries(locale),
    locale,
    now: new Date(2026, 9, 20),
    sourceName: name,
  });
}

describe('parseCycloneDx', () => {
  it('1.6 を読み、入れ子の部品も辿る', () => {
    const p = parseSbomText(fixture('cbom-1.6.json'));
    if (!p.ok) throw new Error(p.error);
    expect(p.specVersion).toBe('1.6');
    expect(p.componentCount).toBe(10);
    expect(p.cryptoAssets).toHaveLength(6);
    expect(p.packages.map((x) => [x.name, x.libraryId])).toEqual([
      ['libssl3', 'openssl'],
      ['app', undefined],
      ['bcprov-jdk18on', 'bouncycastle-java'],
      ['lodash', undefined],
    ]);
    // purl の修飾子は除く
    expect(p.packages[0]?.purl).toBe('pkg:deb/debian/libssl3@3.0.11');
  });

  it('1.7 の ellipticCurve を読む', () => {
    const p = parseSbomText(fixture('cbom-1.7.json'));
    if (!p.ok) throw new Error(p.error);
    expect(p.specVersion).toBe('1.7');
    expect(p.cryptoAssets[0]).toMatchObject({ kind: 'algorithm', ellipticCurve: 'P-256' });
  });

  it('CycloneDX 以外・JSON 以外を拒否する', () => {
    expect(parseCycloneDx({ bomFormat: 'SPDX', specVersion: '2.3' }).ok).toBe(false);
    expect(parseCycloneDx({ bomFormat: 'CycloneDX' }).ok).toBe(false);
    expect(parseCycloneDx(null).ok).toBe(false);
    const xml = parseSbomText('<?xml version="1.0"?><bom/>');
    expect(xml.ok).toBe(false);
    if (!xml.ok) expect(xml.error).toContain('cyclonedx-json');
  });

  it('鍵の値（value）は保持しない', () => {
    const p = parseSbomText(fixture('cbom-1.6.json'));
    expect(JSON.stringify(p)).not.toContain('SECRET-KEY-MATERIAL');
  });
});

describe('buildSbomCryptoReport', () => {
  it('アルゴリズムを判定する（ML-KEM は pqc、RSA は vulnerable、AES は要確認）', () => {
    const r = report('cbom-1.6.json');
    const v = Object.fromEntries(r.algorithms.map((a) => [a.name, a.verdict]));
    expect(v).toEqual({ 'ML-KEM-768': 'pqc', 'RSA-2048': 'vulnerable', 'AES-256-GCM': 'unknown' });
    expect(r.algorithms[0]?.nistQuantumSecurityLevel).toBe(3);
    expect(r.protocols[0]?.cipherSuites.map((c) => c.verdict)).toEqual(['pqc', 'unknown']);
  });

  it('名前で判定できなければ曲線で判定する（1.7 の ellipticCurve）', () => {
    const r = report('cbom-1.7.json');
    expect(r.algorithms[0]).toMatchObject({ curve: 'P-256', verdict: 'vulnerable' });
  });

  it('証明書の署名方式を bom-ref から解決して判定する', () => {
    const c = report('cbom-1.6.json').certificates[0];
    expect(c).toMatchObject({ subjectName: 'CN=server.example.com', signatureAlgorithm: 'RSA-2048', verdict: 'vulnerable' });
  });

  it('暗号ライブラリだけを載せ、他は件数だけ数える', () => {
    const r = report('cbom-1.6.json');
    expect(r.libraries.map((l) => l.libraryId)).toEqual(['openssl', 'bouncycastle-java']);
    expect(r.unmatchedPackageCount).toBe(2);
    expect(r.summary).toMatchObject({ libraryCount: 2, cryptoAssetCount: 6, componentCount: 10, generatedAt: '2026-10-20' });
    expect(r.summary.node).toEqual({ id: 'C3', label: 'API サーバー' });
  });

  it('図との比較に、ノードの署名・エッジの鍵交換と、SBOM の候補を並べる', () => {
    const r = report('cbom-1.6.json', node({ crypto: { signature: 'ML-DSA-65' } }));
    expect(r.comparison.nodeSignature).toEqual({ entered: 'ML-DSA-65', candidates: ['RSA-2048'] });
    expect(r.comparison.edges).toHaveLength(1);
    expect(r.comparison.edges[0]).toMatchObject({
      id: 'DF2',
      peer: '利用者',
      entered: { protocol: null, version: null, kex: 'ECDHE P-256' },
    });
    expect(r.comparison.edges[0]?.keyExchangeCandidates).toEqual(['ML-KEM-768', 'X25519MLKEM768']); // TLS 1.3 のスイート名は鍵交換を含まないので除く
    const md = sbomCryptoToMarkdown(r);
    expect(md).toContain('図の入力値 ML-DSA-65');
    expect(md).toContain('鍵交換 ECDHE P-256');
    expect(md).toContain('プロトコル 未入力');
  });
});

describe('出力', () => {
  it('Markdown はタイトルで始まり、鍵の値を含まない', () => {
    const r = report('cbom-1.6.json');
    const md = sbomCryptoToMarkdown(r);
    expect(md.startsWith('# SBOM の暗号の確認\n')).toBe(true);
    expect(md).toContain('| ML-KEM-768 | kem | 768 | - | 3 | 量子耐性あり |');
    expect(md).toContain('| AES-256-GCM | ae | 256 | - | 1 | 要確認 |');
    expect(md).not.toContain('SECRET-KEY-MATERIAL');
    expect(sbomCryptoToJson(r)).not.toContain('SECRET-KEY-MATERIAL');
  });

  it('JSON は kind と schemaVersion を持つ', () => {
    const j = JSON.parse(sbomCryptoToJson(report('cbom-1.6.json')));
    expect(j.kind).toBe('cyberriskscape-sbom-crypto-report');
    expect(j.schemaVersion).toBe(1);
  });

  it('部品だけの SBOM は、アルゴリズムが無い旨とライブラリを出す', () => {
    const r = report('packages-only.json');
    expect(r.algorithms).toEqual([]);
    expect(r.libraries.map((l) => l.libraryId)).toEqual(['openssl', 'go-stdlib']);
    const md = sbomCryptoToMarkdown(r);
    expect(md).toContain('暗号資産（アルゴリズム）の記載がありません');
  });

  it('en では英語で出し、ライブラリの注記も訳す', () => {
    const md = sbomCryptoToMarkdown(report('cbom-1.6.json', node(), 'en'));
    expect(md.startsWith('# Cryptography in the SBOM\n')).toBe(true);
    expect(md).toContain('Bouncy Castle (Java)');
    expect(md).toContain('1.79 (2024-10) added ML-KEM');
  });

  it('表のセルの | と改行をエスケープする', () => {
    const r = report('cbom-1.6.json');
    r.certificates[0]!.subjectName = 'a|b\nc';
    expect(sbomCryptoToMarkdown(r)).toContain('a\\|b<br>c');
  });
});
