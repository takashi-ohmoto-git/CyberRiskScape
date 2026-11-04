import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { AssetViewBody, type ResolvedNode } from './AssetView';
import type { AssetViews } from '../../features/asset-view/buildAssetViews';
import type { Asset, AssetSubject } from '../../core/model/types';

const subject: AssetSubject = { layer: 'L1', nodeId: 'n1' };
const source = { product: 'ProductX' } as Asset['source'];

const endpoint = (id: string, over: Partial<Asset>): Asset => ({
  id,
  source,
  externalId: 'e',
  identifiers: [],
  kind: 'endpoint',
  host: 'api.example.com',
  ...over,
});

const views: AssetViews = {
  hosts: [
    {
      host: '203.0.113.10',
      domains: ['www.example.com'],
      ports: ['443/https'],
      technologies: ['nginx'],
      subjects: [subject],
    },
    { host: '203.0.113.11', domains: [], ports: ['22/ssh'], technologies: [], subjects: [] },
  ],
  sbom: [
    {
      id: 'p1',
      source: { format: 'spdx', product: 'ExampleSbom', importedAt: '2026-11-05T00:00:00Z' },
      externalId: 'p1',
      identifiers: [{ scheme: 'purl', value: 'pkg:npm/left-pad@1.3.0' }],
      kind: 'software',
      name: 'left-pad',
      version: '1.3.0',
      subject,
    },
    {
      id: 'p2',
      source: { format: 'cyclonedx', product: 'ExampleSbom', importedAt: '2026-11-05T00:00:00Z' },
      externalId: 'p2',
      identifiers: [],
      kind: 'crypto',
      name: 'ML-KEM-768',
    },
  ],
  requests: [
    endpoint('e1', { method: 'GET', url: 'https://www.example.com/a?x=1', params: [{ name: 'x', location: 'query' }], subject }),
    endpoint('e2', { method: 'POST', url: 'https://www.example.com/b' }),
  ],
  apis: [
    {
      subject,
      product: 'ProductX',
      fromDefinition: false,
      endpoints: [endpoint('e3', { method: 'GET', url: 'https://api.example.com/v1/users', subject })],
    },
  ],
};

const resolve = (s: AssetSubject | undefined): ResolvedNode | null =>
  s?.nodeId === 'n1' ? { label: 'C5 会員 API', findings: 3 } : null;
const noop = () => {};
const render = (mode: 'hosts' | 'requests' | 'apis' | 'sbom', v: AssetViews = views) =>
  renderToStaticMarkup(<AssetViewBody views={v} mode={mode} resolve={resolve} onOpen={noop} />);

describe('AssetViewBody', () => {
  it('hosts: ホスト・ポート・技術・対応ノード・指摘数を出し、結びつかない行は未対応', () => {
    const html = render('hosts');
    expect(html).toContain('203.0.113.10');
    expect(html).toContain('443/https');
    expect(html).toContain('nginx');
    expect(html).toContain('C5 会員 API');
    expect(html).toContain('>3<');
    expect(html).toContain('未対応');
  });

  it('requests: メソッド・アドレス・パラメータを出し、指摘の列は無い', () => {
    const html = render('requests');
    expect(html).toContain('GET');
    expect(html).toContain('POST');
    expect(html).toContain('https://www.example.com/a?x=1');
    expect(html).toContain('x(query)');
    expect(html).not.toContain('ノードの指摘');
    expect(html).toContain('未対応');
  });

  it('apis: グループ見出しに対応ノード名を出す', () => {
    const html = render('apis');
    expect(html).toContain('<h3');
    expect(html).toContain('C5 会員 API');
    expect(html).toContain('https://api.example.com/v1/users');
    expect(html).not.toContain('ノードの指摘');
  });

  it('対応ノードのある行だけ操作できる（tabindex）', () => {
    const html = render('requests');
    expect(html.match(/tabindex="0"/g)).toHaveLength(1);
  });

  it('sbom: 名前・版・種類・識別子・出どころを出し、結びつかない部品は未対応にする', () => {
    const html = render('sbom');
    expect(html).toContain('left-pad');
    expect(html).toContain('pkg:npm/left-pad@1.3.0');
    expect(html).toContain('ExampleSbom');
    expect(html).toContain('暗号');
    expect(html).toContain('未対応');
  });
  it('0 件の見方は該当なしを出す', () => {
    const html = render('requests', { hosts: [], requests: [], apis: [], sbom: [] });
    expect(html).toContain('この見方に該当する資産はありません');
  });
});
