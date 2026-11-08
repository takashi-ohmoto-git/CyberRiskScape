import { describe, expect, it } from 'vitest';
import { parseArtexEndpoints, parseArtexServices, sanitizeUrl } from './artexAssets';

const service = (over: object = {}) => ({
  type: 'service',
  task_source: 'agent',
  ip: '203.0.113.10',
  domain: 'www.example.com',
  port: 443,
  service_name: 'HTTPS',
  technologies: ['nginx'],
  ...over,
});
const endpoint = (over: object = {}) => ({
  type: 'endpoint',
  task_source: 'agent',
  url: 'https://www.example.com/login',
  method: 'post',
  params: [{ name: 'password', location: 'body', value: 'do-not-keep' }],
  ...over,
});

describe('sanitizeUrl', () => {
  it('URL の資格情報を除く', () => {
    expect(sanitizeUrl('https://user:pw@www.example.com/a')).toBe('https://www.example.com/a');
  });
  it('名前が秘密に見えるクエリの値だけを伏せる', () => {
    expect(sanitizeUrl('https://x.example/?_tag=login_token&api_key=abc&page=1#top')).toBe(
      'https://x.example/?_tag=login_token&api_key=***&page=1#top',
    );
  });
  it('ひな形の値はそのまま残す', () => {
    expect(sanitizeUrl('https://x.example/?_tag=<page>')).toBe('https://x.example/?_tag=<page>');
  });
});

describe('parseArtexServices', () => {
  it('task_source が agent の資産だけを読み、他は件数だけ返す', () => {
    const r = parseArtexServices({ assets: [service(), service({ task_source: 'company', ip: '203.0.113.99' })] });
    expect(r).toMatchObject({ ok: true, skippedBySource: 1 });
    expect(r.ok && r.records.map((x) => x.host)).toEqual(['203.0.113.10']);
  });
  it('IP が無ければドメインをホストにし、IP と同じドメインは持たない', () => {
    const r = parseArtexServices({ assets: [service({ ip: undefined }), service({ domain: '203.0.113.10' })] });
    expect(r.ok && r.records[0]).toMatchObject({ host: 'www.example.com' });
    expect(r.ok && r.records[1].domain).toBeUndefined();
  });
  it('観測時刻を ISO 8601 にし、ARTEX の ID を残す', () => {
    const r = parseArtexServices({ assets: [service({ id: 62, last_seen: '2026-11-04 06:58:29.773049+00' })] });
    expect(r.ok && r.records[0]).toMatchObject({ assetId: '62', observedAt: '2026-11-04T06:58:29.773Z' });
  });
  it('解釈できない時刻は持たない', () => {
    const r = parseArtexServices({ assets: [service({ last_seen: '不明' })] });
    expect(r.ok && r.records[0].observedAt).toBeUndefined();
  });
  it('サービス名は小文字にそろえる', () => {
    const r = parseArtexServices({ assets: [service()] });
    expect(r.ok && r.records[0].serviceName).toBe('https');
  });
  it('形が違えば、または別の type を含めばエラー', () => {
    expect(parseArtexServices({ items: [] }).ok).toBe(false);
    expect(parseArtexServices({ assets: [endpoint()] }).ok).toBe(false);
  });
});

describe('parseArtexEndpoints', () => {
  it('パラメータの値を持たない', () => {
    const r = parseArtexEndpoints({ assets: [endpoint()] });
    expect(r.ok && r.records[0].params).toEqual([{ name: 'password', location: 'body' }]);
    expect(JSON.stringify(r)).not.toContain('do-not-keep');
  });
  it('メソッドを大文字にし、ホストを URL から取る', () => {
    const r = parseArtexEndpoints({ assets: [endpoint({ url: 'http://203.0.113.10:8080/?_tag=<page>' })] });
    expect(r.ok && r.records[0]).toMatchObject({ method: 'POST', host: '203.0.113.10' });
  });
  it('URL かメソッドが無い行は読まない', () => {
    const r = parseArtexEndpoints({ assets: [endpoint({ url: undefined }), endpoint({ method: undefined })] });
    expect(r.ok && r.records).toEqual([]);
  });
});
