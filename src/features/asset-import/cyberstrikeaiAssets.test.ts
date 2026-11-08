import { describe, expect, it } from 'vitest';
import { parseCyberStrikeAiAssets } from './cyberstrikeaiAssets';

const asset = (over: object = {}) => ({
  id: 'a1b2c3',
  host: 'www.example.com',
  ip: '203.0.113.20',
  port: 443,
  domain: 'www.example.com',
  protocol: 'HTTPS',
  title: 'Member site',
  server: 'nginx',
  responsible_person: 'Taro Example',
  department: 'Sales',
  source: 'fofa',
  status: 'active',
  last_seen_at: '2026-11-03T08:34:50Z',
  ...over,
});

describe('parseCyberStrikeAiAssets', () => {
  it('観測した資産をサービスとして読み、担当者・部署は持たない', () => {
    const r = parseCyberStrikeAiAssets({ assets: [asset()], total: 1, page: 1 });
    expect(r.ok && r.records).toEqual([
      {
        host: '203.0.113.20',
        assetId: 'a1b2c3',
        ip: '203.0.113.20',
        domain: 'www.example.com',
        port: 443,
        serviceName: 'https',
        technologies: ['nginx'],
        observedAt: '2026-11-03T08:34:50.000Z',
      },
    ]);
    expect(JSON.stringify(r)).not.toMatch(/Taro|Sales|Member site/);
  });

  it('手で登録した資産（manual）と inactive の資産は読まず、件数だけ数える', () => {
    const r = parseCyberStrikeAiAssets({ assets: [asset(), asset({ source: 'manual' }), asset({ status: 'inactive' })] });
    expect(r.ok && r.records).toHaveLength(1);
    expect(r.ok && r.skippedBySource).toBe(2);
  });

  it('IP が無ければドメイン、無ければ host をホストにし、未設定の時刻（0001-01-01）とポート 0 は持たない', () => {
    const r = parseCyberStrikeAiAssets({
      assets: [asset({ ip: '', domain: '', host: 'api.example.com', port: 0, last_seen_at: '0001-01-01T00:00:00Z' })],
    });
    expect(r.ok && r.records[0]).toEqual({ host: 'api.example.com', assetId: 'a1b2c3', serviceName: 'https', technologies: ['nginx'] });
  });

  it('形が違う → エラー', () => {
    const r = parseCyberStrikeAiAssets({ items: [] });
    expect(r.ok).toBe(false);
  });
});
