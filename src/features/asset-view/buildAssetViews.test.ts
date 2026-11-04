import { describe, expect, it } from 'vitest';
import type { Asset, BomComponent } from '../../core/model/types';
import { buildAssetViews, type AssetViewNode } from './buildAssetViews';

const source = { format: 'artex-assets', product: 'Example', scope: 's', importedAt: '2026-11-04T00:00:00Z' } as const;
const nodes: AssetViewNode[] = [
  { id: 'web', type: 'FRONT_END_SERVER', layer: 'L1' },
  { id: 'api', type: 'BACKEND_API', layer: 'L1' },
];
const svc = (id: string, over: Partial<Asset> = {}): Asset => ({
  id,
  source,
  externalId: id,
  identifiers: [],
  kind: 'service',
  host: '203.0.113.10',
  ip: '203.0.113.10',
  port: 443,
  serviceName: 'https',
  ...over,
});
const ep = (id: string, over: Partial<Asset> = {}): Asset => ({
  id,
  source,
  externalId: id,
  identifiers: [],
  kind: 'endpoint',
  host: 'www.example.com',
  method: 'GET',
  url: `https://www.example.com/${id}`,
  ...over,
});

describe('buildAssetViews', () => {
  it('ホスト：同じ IP のサービスを 1 行にまとめ、ポート順に並べる', () => {
    const { hosts } = buildAssetViews(
      [
        svc('a', { domain: 'www.example.com', technologies: ['nginx'], observedAt: '2026-11-01' }),
        svc('b', { port: 80, serviceName: 'http', technologies: ['nginx', 'php'], observedAt: '2026-11-02' }),
      ],
      nodes,
    );
    expect(hosts).toHaveLength(1);
    expect(hosts[0]).toMatchObject({
      host: '203.0.113.10',
      domains: ['www.example.com'],
      ports: ['80/http', '443/https'],
      technologies: ['nginx', 'php'],
      observedAt: '2026-11-02',
    });
  });
  it('ホスト：IP が無いサービスはホスト名で 1 行になる', () => {
    const { hosts } = buildAssetViews([svc('a', { ip: undefined, host: 'www.example.com' })], nodes);
    expect(hosts[0].host).toBe('www.example.com');
  });
  it('ホスト：結びつかなければ subjects は空（未対応）', () => {
    expect(buildAssetViews([svc('a')], nodes).hosts[0].subjects).toEqual([]);
  });
  it('API 系のノードに結びつくエンドポイント → API だけに載る', () => {
    const v = buildAssetViews([ep('a', { subject: { layer: 'L1', nodeId: 'api' } })], nodes);
    expect(v.requests).toEqual([]);
    expect(v.apis).toHaveLength(1);
    expect(v.apis[0]).toMatchObject({ subject: { nodeId: 'api' }, fromDefinition: false });
  });
  it('API 定義から来たエンドポイント → ノードが無くても API に載る', () => {
    const v = buildAssetViews([ep('a', { source: { ...source, definition: true } })], nodes);
    expect(v.requests).toEqual([]);
    expect(v.apis[0]).toMatchObject({ product: 'Example', fromDefinition: true });
  });
  it('API に当たらないエンドポイント → URL に api を含んでもリクエストに載る', () => {
    const asset = ep('a', { url: 'https://www.example.com/api/v1', subject: { layer: 'L1', nodeId: 'web' } });
    const v = buildAssetViews([asset], nodes);
    expect(v.requests.map((r) => r.id)).toEqual(['a']);
    expect(v.apis).toEqual([]);
  });
  it('消えたノードに結びつくエンドポイント → リクエストに載る', () => {
    const v = buildAssetViews([ep('a', { subject: { layer: 'L1', nodeId: 'gone' } })], nodes);
    expect(v.requests).toHaveLength(1);
  });
  it('部品は名前順で SBOM の見方に載る', () => {
    const part = (name: string): BomComponent => ({
      id: name,
      source: { format: 'spdx', product: 'x', importedAt: '2026-11-05T00:00:00Z' },
      externalId: name,
      identifiers: [],
      kind: 'software',
      name,
    });
    expect(buildAssetViews([], nodes, [part('b'), part('a')]).sbom.map((c) => c.name)).toEqual(['a', 'b']);
  });
  it('API はノードごとにまとまる', () => {
    const subject = { layer: 'L1', nodeId: 'api' } as const;
    const v = buildAssetViews([ep('b', { subject }), ep('a', { subject })], nodes);
    expect(v.apis).toHaveLength(1);
    expect(v.apis[0].endpoints.map((e) => e.id)).toEqual(['a', 'b']);
  });
});
