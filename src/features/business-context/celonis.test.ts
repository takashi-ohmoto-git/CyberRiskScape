import { describe, expect, it } from 'vitest';
import {
  CELONIS_CLIENT_ID_ENV,
  CELONIS_CLIENT_SECRET_ENV,
  CELONIS_TOKEN_ENV,
  celonisRowsToTable,
  checkApiBase,
  credentialsFromEnv,
  fetchCelonisRecordRows,
  parseValueMaps,
} from './celonis';
import { parseBusinessContextTable } from './parseBusinessContextTable';

const API = 'https://acme.eu-1.celonis.cloud/intelligence/api/';

interface Call {
  url: string;
  init: RequestInit;
}

const json = (body: unknown, status = 200, type = 'application/json') =>
  ({ ok: status >= 200 && status < 300, status, headers: new Headers({ 'content-type': type }), json: async () => body }) as Response;

/** 1 ページ目に n 行ずつ返すモック。トークンの POST にも応答する。 */
function fakeFetch(pages: Record<string, unknown>[][], calls: Call[], total?: number): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    if (String(url).endsWith('/oauth2/token')) return json({ access_token: 'access-XYZ', token_type: 'Bearer', expires_in: 3600 });
    const page = Number(new URL(String(url)).searchParams.get('page'));
    return json({ page, pageSize: 50, total: total ?? pages.flat().length, content: { headers: [], data: pages[page] ?? [] } });
  }) as typeof fetch;
}

const rowsOf = (n: number, from = 0) => Array.from({ length: n }, (_, i) => ({ sys: 'SAP', amt: String(from + i) }));

describe('credentialsFromEnv / checkApiBase / parseValueMaps', () => {
  it('CELONIS_TOKEN を優先し、無ければ ID とシークレットの両方を要求する', () => {
    expect(credentialsFromEnv({ [CELONIS_TOKEN_ENV]: ' t ', [CELONIS_CLIENT_ID_ENV]: 'i', [CELONIS_CLIENT_SECRET_ENV]: 's' })).toEqual({ token: 't' });
    expect(credentialsFromEnv({ [CELONIS_CLIENT_ID_ENV]: 'i', [CELONIS_CLIENT_SECRET_ENV]: 's' })).toEqual({ clientId: 'i', clientSecret: 's' });
    expect(() => credentialsFromEnv({ [CELONIS_CLIENT_ID_ENV]: 'i' })).toThrow(CELONIS_CLIENT_SECRET_ENV);
  });

  it('--api は https・userinfo なし・クエリ/フラグメントなし。末尾のスラッシュは除く', () => {
    expect(checkApiBase(API)).toEqual({ base: 'https://acme.eu-1.celonis.cloud/intelligence/api', origin: 'https://acme.eu-1.celonis.cloud' });
    for (const bad of ['http://a.example/x', 'https://u:p@a.example/x', 'https://a.example/x?y=1', 'https://a.example/x#f', 'not a url', 'ftp://a.example']) {
      expect(() => checkApiBase(bad)).toThrow();
    }
  });

  it('--map は <値>=<ノード>。形の違い・重複・0 件はエラー', () => {
    expect([...parseValueMaps(['SAP=C2', 'CRM = ncl_crm'])]).toEqual([['SAP', 'C2'], ['CRM', 'ncl_crm']]);
    expect(() => parseValueMaps(['SAP'])).toThrow();
    expect(() => parseValueMaps(['SAP=C1', 'SAP=C2'])).toThrow('重複');
    expect(() => parseValueMaps([])).toThrow();
  });
});

describe('fetchCelonisRecordRows', () => {
  it('トークンを POST で取り、GET で 2 ページ集める。URL・ヘッダ・redirect を確かめる', async () => {
    const calls: Call[] = [];
    const r = await fetchCelonisRecordRows(
      API,
      { clientId: 'cid-1', clientSecret: 'sec-1' },
      { km: 'km/1', record: 'rec 1', fields: ['sys', 'amt'] },
      fakeFetch([rowsOf(50), rowsOf(3, 50)], calls),
    );
    expect(r).toMatchObject({ truncated: false, total: 53 });
    expect(r.rows).toHaveLength(53);
    expect(calls).toHaveLength(3);
    expect(calls[0].url).toBe('https://acme.eu-1.celonis.cloud/oauth2/token');
    expect(calls[0].init.method).toBe('POST');
    const form = new URLSearchParams(String(calls[0].init.body));
    expect(form.get('grant_type')).toBe('client_credentials');
    expect(form.get('scope')).toBe('intelligence.knowledge-models:read');
    const u = new URL(calls[1].url);
    expect(u.origin + u.pathname).toBe('https://acme.eu-1.celonis.cloud/intelligence/api/knowledge-models/km%2F1/records/rec%201/data');
    expect(u.searchParams.get('fields')).toBe('sys,amt');
    expect(u.searchParams.get('pageSize')).toBe('50');
    expect(calls[1].init.method).toBe('GET');
    expect(calls[1].init.redirect).toBe('error');
    expect(calls[1].init.headers).toMatchObject({ Authorization: 'Bearer access-XYZ' });
  });

  it('CELONIS_TOKEN があればトークン取得の POST はしない', async () => {
    const calls: Call[] = [];
    await fetchCelonisRecordRows(API, { token: 'tok-1' }, { km: 'k', record: 'r', fields: ['sys'] }, fakeFetch([rowsOf(1)], calls));
    expect(calls).toHaveLength(1);
    expect(calls[0].init.method).toBe('GET');
  });

  it('1,000 行（20 ページ）で打ち切り、総件数がそれを超えれば truncated', async () => {
    const calls: Call[] = [];
    const pages = Array.from({ length: 25 }, (_, i) => rowsOf(50, i * 50));
    const r = await fetchCelonisRecordRows(API, { token: 't' }, { km: 'k', record: 'r', fields: ['sys'] }, fakeFetch(pages, calls, 1250));
    expect(r.rows).toHaveLength(1000);
    expect(r.truncated).toBe(true);
    expect(calls).toHaveLength(20);
  });

  it('HTTP エラー・JSON でない応答・形の違う応答は、資格情報を含まないエラーにする', async () => {
    const creds = { clientId: 'cid-SECRET', clientSecret: 'sec-SECRET' };
    const failing = (res: () => Response): typeof fetch =>
      (async (url: string | URL | Request) => (String(url).endsWith('/oauth2/token') ? json({ access_token: 'tok-SECRET' }) : res())) as typeof fetch;
    const opts = { km: 'k', record: 'r', fields: ['sys'] };
    const cases = [
      failing(() => json({ error: 'cid-SECRET sec-SECRET tok-SECRET' }, 401)),
      failing(() => json('<html>tok-SECRET</html>', 200, 'text/html')),
      failing(() => json({ content: 'tok-SECRET' })),
      failing(() => {
        throw new Error('network down: Bearer tok-SECRET cid-SECRET sec-SECRET');
      }),
    ];
    for (const f of cases) {
      const err = await fetchCelonisRecordRows(API, creds, opts, f).catch((e: unknown) => e as Error);
      expect(err).toBeInstanceOf(Error);
      const msg = (err as Error).message;
      for (const s of ['cid-SECRET', 'sec-SECRET', 'tok-SECRET']) expect(msg).not.toContain(s);
    }
  });

  it('トークン取得に失敗したときもシークレットを出さない', async () => {
    const f = (async () => json({ error: 'sec-SECRET' }, 400)) as unknown as typeof fetch;
    const err = await fetchCelonisRecordRows(API, { clientId: 'cid-SECRET', clientSecret: 'sec-SECRET' }, { km: 'k', record: 'r', fields: ['sys'] }, f).catch((e: unknown) => e as Error);
    expect((err as Error).message).toContain('HTTP 400');
    expect((err as Error).message).not.toContain('SECRET');
  });

  it('http の --api は取得の前に拒否する', async () => {
    const calls: Call[] = [];
    await expect(fetchCelonisRecordRows('http://acme.example/api', { token: 't' }, { km: 'k', record: 'r', fields: ['sys'] }, fakeFetch([], calls))).rejects.toThrow('https');
    expect(calls).toHaveLength(0);
  });
});

describe('celonisRowsToTable', () => {
  const base = { km: 'km1', record: 'rec1', systemField: 'sys', map: new Map([['SAP', 'C1'], ['CRM', 'ncl_crm']]) };

  it('対応づけた行だけを表にし、対応のない値は件数で報告する。表は読み戻せる', () => {
    const { table, summary } = celonisRowsToTable(
      [
        { sys: 'SAP', p: 'Order-to-Cash', amt: '1500.5', n: 10 },
        { sys: 'CRM', p: 'Lead-to-Order', amt: 'abc', n: -1 },
        { sys: 'LEGACY', p: 'X', amt: 1 },
        { sys: 'LEGACY', p: 'Y', amt: 1 },
        { sys: null, p: 'Z' },
        { sys: 'SAP', p: '', amt: 1 },
      ],
      { ...base, processField: 'p', valueField: 'amt', casesField: 'n', currency: 'JPY', period: '2026-10' },
    );
    expect(table.rows).toEqual([
      { node: 'C1', process: 'Order-to-Cash', value: 1500.5, cases: 10, currency: 'JPY', period: '2026-10' },
      { node: 'ncl_crm', process: 'Lead-to-Order', currency: 'JPY', period: '2026-10' },
    ]);
    expect(summary).toEqual({ rows: 6, used: 2, unmapped: { LEGACY: 2, '（空）': 1 }, missingProcess: 1, nonNumeric: 2 });
    expect(table.source).toEqual({ product: 'Celonis', ref: 'km:km1/record:rec1' });
    const reread = parseBusinessContextTable(JSON.stringify(table), 'celonis.json');
    expect(reread).toMatchObject({ ok: true, source: table.source });
  });

  it('--process の固定値で全行のプロセス名を決める。どちらも無ければエラー', () => {
    const { table } = celonisRowsToTable([{ sys: 'SAP' }], { ...base, process: 'P2P' });
    expect(table.rows).toEqual([{ node: 'C1', process: 'P2P' }]);
    expect(() => celonisRowsToTable([], base)).toThrow('--process');
  });
});
