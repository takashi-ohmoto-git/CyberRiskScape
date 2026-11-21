import { describe, expect, it } from 'vitest';
import { parseAiAsmEndpoints } from './aiAsmAssets';

describe('parseAiAsmEndpoints', () => {
  it('メソッド・URL・パラメータ・観測時刻を読み、メソッドは大文字にする', () => {
    const r = parseAiAsmEndpoints({
      endpoints: [
        { method: 'get', url: 'https://shop.example/api/items?q=1', params: [{ name: 'q', location: 'query' }], observedAt: '2026-11-21T12:00:00Z' },
      ],
    });
    expect(r).toEqual({
      ok: true,
      skippedBySource: 0,
      records: [
        {
          host: 'shop.example',
          method: 'GET',
          url: 'https://shop.example/api/items?q=1',
          params: [{ name: 'q', location: 'query' }],
          observedAt: '2026-11-21T12:00:00.000Z',
        },
      ],
    });
  });
  it('秘密に見える名前のクエリの値と URL の資格情報を伏せる', () => {
    const r = parseAiAsmEndpoints({ endpoints: [{ method: 'GET', url: 'https://u:p@shop.example/a?token=abc&q=1' }] });
    expect(r.ok && r.records[0].url).toBe('https://shop.example/a?token=***&q=1');
    expect(r.ok && r.records[0].host).toBe('shop.example');
  });
  it('メソッドが無ければ未指定のまま残し、パラメータは空にする', () => {
    const r = parseAiAsmEndpoints({ endpoints: [{ url: 'https://shop.example/static/app.js' }] });
    expect(r.ok && r.records[0].method).toBeUndefined();
    expect(r.ok && r.records[0].params).toEqual([]);
  });
  it('http(s) のホストが無い URL は読み飛ばす', () => {
    const r = parseAiAsmEndpoints({ endpoints: [{ url: '/api/items' }, { url: 'ftp://x.example/a' }, { url: 'http://ok.example/' }] });
    expect(r.ok && r.records.map((x) => x.host)).toEqual(['ok.example']);
  });
  it('形が違えば ok:false とパス付きのメッセージを返す', () => {
    const r = parseAiAsmEndpoints({ endpoints: [{ method: 'GET' }] });
    expect(r.ok).toBe(false);
    expect(!r.ok && r.error).toContain('AI-ASM の資産の形が想定と異なります（endpoints.0.url）');
  });
});
