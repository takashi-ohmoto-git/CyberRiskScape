import { describe, expect, it } from 'vitest';
import { deserializeProject, serializeProject, type SerializableState } from './serialize';
import { EMPTY_LAYER } from '../../core/model/types';

const STATE: SerializableState = {
  layers: { L0: EMPTY_LAYER, L1: EMPTY_LAYER, L2: EMPTY_LAYER, L3: EMPTY_LAYER, PQC: EMPTY_LAYER },
  activeLayer: 'L1',
  activeFramework: 'ALL',
};

/** 表記のそろっていない識別子を持つ、古い保存データを模したもの。 */
function legacyProject() {
  return {
    ...JSON.parse(JSON.stringify(serializeProject(STATE))),
    findings: [
      {
        id: 'Scanner:f1',
        source: { format: 'sarif', product: 'Scanner', importedAt: '2026-11-01T00:00:00Z' },
        externalId: 'f1',
        identifiers: [
          { scheme: 'CVE', value: 'cve-2024-1234' },
          { scheme: 'cve', value: 'CVE-2024-1234' },
          { scheme: 'cwe', value: 'CWE-079' },
          { scheme: 'example-db', value: 'EXMPL-1' },
        ],
        severity: 'High',
        canonicalIds: [],
      },
    ],
    assets: [
      {
        id: 'Shodan:s:x',
        source: { format: 'shodan', product: 'Shodan', scope: 's', importedAt: '2026-11-01T00:00:00Z' },
        externalId: 'x',
        identifiers: [
          { scheme: 'ip', value: '2001:0DB8:0000:0000:0000:0000:0000:0001' },
          { scheme: 'fqdn', value: 'API.Example.com.' },
          { scheme: 'url', value: 'HTTPS://API.Example.com:443/Path#frag' },
        ],
        kind: 'service',
        host: 'API.Example.com',
      },
    ],
    bomComponents: [
      {
        id: 'Syft:c1',
        source: { format: 'cyclonedx', product: 'Syft', importedAt: '2026-11-01T00:00:00Z' },
        externalId: 'pkg:NPM/lib@1.0.0?repository_url=https://registry.example',
        identifiers: [
          { scheme: 'purl', value: 'pkg:NPM/lib@1.0.0?repository_url=https://registry.example' },
          { scheme: 'sha-256', value: 'ABCDEF' },
        ],
        kind: 'software',
        name: 'lib',
      },
    ],
  };
}

describe('deserializeProject（識別子の表記をそろえる）', () => {
  const loaded = deserializeProject(legacyProject());

  it('読み込める', () => {
    expect(loaded).not.toBeNull();
  });

  it('指摘：scheme は小文字、CVE は大文字、CWE は数字だけにし、同じになったものは 1 つにまとめる。一覧に無い scheme は残す', () => {
    expect(loaded?.findings?.[0].identifiers).toEqual([
      { scheme: 'cve', value: 'CVE-2024-1234' },
      { scheme: 'cwe', value: '79' },
      { scheme: 'example-db', value: 'EXMPL-1' },
    ]);
  });

  it('資産：IPv6・FQDN・URL の表記をそろえる', () => {
    expect(loaded?.assets?.[0].identifiers).toEqual([
      { scheme: 'ip', value: '2001:db8::1' },
      { scheme: 'fqdn', value: 'api.example.com' },
      { scheme: 'url', value: 'https://api.example.com/Path' },
    ]);
  });

  it('部品：purl の修飾子を除き、ハッシュは小文字にする', () => {
    expect(loaded?.bomComponents?.[0].identifiers).toEqual([
      { scheme: 'purl', value: 'pkg:npm/lib@1.0.0' },
      { scheme: 'sha-256', value: 'abcdef' },
    ]);
  });

  it('ID と製品側の ID は変えない（結びつき・取り込み直しの同一視が外れない）', () => {
    expect(loaded?.findings?.[0]).toMatchObject({ id: 'Scanner:f1', externalId: 'f1' });
    expect(loaded?.assets?.[0]).toMatchObject({ id: 'Shodan:s:x', externalId: 'x', host: 'API.Example.com' });
    expect(loaded?.bomComponents?.[0]).toMatchObject({
      id: 'Syft:c1',
      externalId: 'pkg:NPM/lib@1.0.0?repository_url=https://registry.example',
    });
  });

  it('そろえた後のデータは、もう一度読み込んでも同じ（保存し直しても壊れない）', () => {
    const again = deserializeProject(JSON.parse(JSON.stringify({ ...legacyProject(), ...loaded })));
    expect(again?.findings?.[0].identifiers).toEqual(loaded?.findings?.[0].identifiers);
    expect(again?.assets?.[0].identifiers).toEqual(loaded?.assets?.[0].identifiers);
    expect(again?.bomComponents?.[0].identifiers).toEqual(loaded?.bomComponents?.[0].identifiers);
  });
});
