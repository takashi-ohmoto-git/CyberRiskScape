import { describe, expect, it } from 'vitest';
import { parseBom } from './parseBom';

const SHA = 'a'.repeat(64);

const cyclonedx = (components: unknown[]) => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.7',
  metadata: { timestamp: '2026-11-01T09:00:00+09:00', tools: { components: [{ name: 'example-scanner', version: '2.0' }] } },
  components,
});
const spdx = (packages: unknown[]) => ({
  spdxVersion: 'SPDX-2.3',
  SPDXID: 'SPDXRef-DOCUMENT',
  creationInfo: { created: '2026-11-01T00:00:00Z', creators: ['Tool: example-sbom-1.2.3', 'Organization: Example'] },
  packages,
});

describe('parseBom（CycloneDX）', () => {
  it('ライブラリ：purl・CPE・SHA-256 を鍵にし、purl の修飾子を除く', () => {
    const r = parseBom(
      cyclonedx([
        {
          type: 'library',
          name: 'left-pad',
          version: '1.3.0',
          'bom-ref': 'ref-1',
          purl: 'pkg:npm/left-pad@1.3.0?repository_url=https://user:pw@registry.example.com',
          cpe: 'cpe:2.3:a:example:left-pad:1.3.0:*:*:*:*:*:*:*',
          hashes: [{ alg: 'SHA-256', content: SHA }],
        },
      ]),
    );
    expect(r).toMatchObject({ ok: true, format: 'cyclonedx', product: 'example-scanner', productVersion: '2.0', observedAt: '2026-11-01T00:00:00.000Z' });
    expect(JSON.stringify(r)).not.toContain('user:pw');
    expect(r.ok && r.items[0]).toMatchObject({
      externalId: 'pkg:npm/left-pad@1.3.0',
      kind: 'software',
      sourceType: 'library',
      identifiers: [
        { scheme: 'purl', value: 'pkg:npm/left-pad@1.3.0' },
        { scheme: 'cpe', value: 'cpe:2.3:a:example:left-pad:1.3.0:*:*:*:*:*:*:*' },
        { scheme: 'sha-256', value: SHA },
      ],
    });
  });
  it('暗号資産：方式は読み、鍵の値は読まない', () => {
    const r = parseBom(
      cyclonedx([
        {
          type: 'cryptographic-asset',
          name: 'ML-KEM-768',
          cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: 'kem', parameterSetIdentifier: '768', nistQuantumSecurityLevel: 3 } },
        },
        {
          type: 'cryptographic-asset',
          name: 'key',
          cryptoProperties: { assetType: 'related-crypto-material', relatedCryptoMaterialProperties: { value: 'do-not-keep' } },
        },
      ]),
    );
    expect(r.ok && r.items[0]).toMatchObject({
      kind: 'crypto',
      crypto: { assetType: 'algorithm', primitive: 'kem', parameterSet: '768', nistQuantumSecurityLevel: 3 },
    });
    expect(r.ok && r.items[1].crypto?.assetType).toBe('material');
    expect(JSON.stringify(r)).not.toContain('do-not-keep');
  });
  it.each([
    ['machine-learning-model', 'ai-model'],
    ['data', 'dataset'],
    ['未知の型', 'other'],
  ])('type %s → kind %s', (type, kind) => {
    const r = parseBom(cyclonedx([{ type, name: 'x' }]));
    expect(r.ok && r.items[0].kind).toBe(kind);
  });
  it('入れ子の部品も読み、名前の無い部品は捨てる', () => {
    const r = parseBom(cyclonedx([{ type: 'application', name: 'a', components: [{ type: 'library', name: 'b' }] }, { type: 'library' }]));
    expect(r.ok && r.items.map((i) => i.name)).toEqual(['a', 'b']);
  });
  it('型違いの項目は落とすだけで、部品は残す', () => {
    const r = parseBom(cyclonedx([{ type: 'library', name: 'a', version: 1, hashes: 'x' }]));
    expect(r.ok && r.items[0]).toMatchObject({ name: 'a' });
    expect(r.ok && r.items[0].version).toBeUndefined();
  });
  it('古い形式の tools（配列）も読む', () => {
    const r = parseBom({ ...cyclonedx([]), metadata: { tools: [{ name: 'old-tool' }] } });
    expect(r).toMatchObject({ product: 'old-tool' });
  });
});

describe('parseBom（SPDX）', () => {
  it('パッケージを部品にし、製品名と版を creators から読む', () => {
    const r = parseBom(
      spdx([
        {
          SPDXID: 'SPDXRef-Package-1',
          name: 'left-pad',
          versionInfo: '1.3.0',
          primaryPackagePurpose: 'LIBRARY',
          checksums: [{ algorithm: 'SHA256', checksumValue: SHA }],
          externalRefs: [
            { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:npm/left-pad@1.3.0' },
            { referenceCategory: 'SECURITY', referenceType: 'cpe23Type', referenceLocator: 'cpe:2.3:a:example:left-pad:1.3.0:*:*:*:*:*:*:*' },
          ],
        },
      ]),
    );
    expect(r).toMatchObject({ ok: true, format: 'spdx', specVersion: 'SPDX-2.3', product: 'example-sbom', productVersion: '1.2.3' });
    expect(r.ok && r.items[0]).toMatchObject({ externalId: 'pkg:npm/left-pad@1.3.0', kind: 'software', sourceType: 'LIBRARY', version: '1.3.0' });
    expect(r.ok && r.items[0].identifiers.map((i) => i.scheme)).toEqual(['purl', 'cpe', 'sha-256']);
  });
  it('NOASSERTION の版は持たない。purl が無ければ SPDXID を外部 ID にする', () => {
    const r = parseBom(spdx([{ SPDXID: 'SPDXRef-A', name: 'a', versionInfo: 'NOASSERTION' }]));
    expect(r.ok && r.items[0]).toMatchObject({ externalId: 'SPDXRef-A' });
    expect(r.ok && r.items[0].version).toBeUndefined();
  });
  it('SPDX 3 はエラー', () => {
    expect(parseBom({ spdxVersion: 'SPDX-3.0' }).ok).toBe(false);
  });
});

describe('parseBom（形式の判定）', () => {
  it('どちらでもなければエラー', () => {
    expect(parseBom({ assets: [] }).ok).toBe(false);
    expect(parseBom(null).ok).toBe(false);
  });
});
