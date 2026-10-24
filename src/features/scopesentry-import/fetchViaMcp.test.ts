import { describe, expect, it } from 'vitest';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { ALLOWED_TOOLS, MAX_RECORDS, PAGE_SIZE, apiKeyFromEnv, fetchRecords, fetchViaMcp, type McpToolClient } from './fetchViaMcp';
import { scopesentryRecordsToLayer } from './scopesentryToLayer';

const KEY = 'ssk_TEST-KEY-SHOULD-NOT-LEAK';
const textResult = (body: unknown, isError = false) => ({ isError, content: [{ type: 'text', text: typeof body === 'string' ? body : JSON.stringify(body) }] });

/** list_assets だけを持つモック。呼び出しを記録し、種別ごとに用意したレコードをページ分割して返す。 */
function mockClient(data: Record<string, unknown[]>) {
  const calls: { name: string; arguments?: Record<string, unknown> }[] = [];
  const client: McpToolClient = {
    async callTool(params) {
      calls.push(params);
      const a = params.arguments ?? {};
      const all = data[a.asset_type as string] ?? [];
      const i = (a.pageIndex as number) - 1;
      return textResult({ list: all.slice(i * PAGE_SIZE, (i + 1) * PAGE_SIZE), total: all.length });
    },
  };
  return { client, calls };
}
const asset = (i: number) => ({ host: `h${i}.example.com`, ip: `203.0.113.${(i % 250) + 1}`, port: String(1000 + i) });

describe('fetchRecords', () => {
  it('list_assets だけを、asset / vulnerability / SubdomainTakerResult の 3 種別で呼ぶ', async () => {
    const { client, calls } = mockClient({ asset: [asset(1)], vulnerability: [{ vulnid: 'X' }], SubdomainTakerResult: [{ input: 'a.example.com' }] });
    const { records, capped } = await fetchRecords(client);
    expect(records).toHaveLength(3);
    expect(capped).toBe(false);
    expect(ALLOWED_TOOLS).toEqual(['list_assets']);
    expect(calls.every((c) => c.name === 'list_assets')).toBe(true);
    expect(calls.map((c) => c.arguments?.asset_type)).toEqual(['asset', 'vulnerability', 'SubdomainTakerResult']);
  });

  it('ページ送りして、短いページで止まる。project は filter.project、search はそのまま渡す', async () => {
    const { client, calls } = mockClient({ asset: Array.from({ length: PAGE_SIZE + 5 }, (_, i) => asset(i)) });
    const { records } = await fetchRecords(client, { project: 'abc123', search: 'port==443' });
    expect(records).toHaveLength(PAGE_SIZE + 5);
    const assetCalls = calls.filter((c) => c.arguments?.asset_type === 'asset');
    expect(assetCalls.map((c) => c.arguments?.pageIndex)).toEqual([1, 2]);
    expect(assetCalls[0].arguments).toMatchObject({ pageSize: PAGE_SIZE, search: 'port==443', filter: { project: ['abc123'] } });
  });

  it('合計 MAX_RECORDS 件で打ち切り、capped を立てる', async () => {
    const { client } = mockClient({ asset: Array.from({ length: MAX_RECORDS + 200 }, (_, i) => asset(i)) });
    const { records, capped } = await fetchRecords(client);
    expect(records).toHaveLength(MAX_RECORDS);
    expect(capped).toBe(true);
  });

  it('isError の応答は本文つきの例外にする。list の無い応答も例外', async () => {
    await expect(fetchRecords({ callTool: async () => textResult('permission denied', true) })).rejects.toThrow('permission denied');
    await expect(fetchRecords({ callTool: async () => textResult({ nope: 1 }) })).rejects.toThrow('list');
    await expect(fetchRecords({ callTool: async () => textResult('not json') })).rejects.toThrow('JSON');
  });

  it('取得したレコードはファイル取り込みと同じ純粋関数で図になる', async () => {
    const { client } = mockClient({
      asset: [{ ...asset(1), type: 'http', url: 'https://h1.example.com/' }],
      vulnerability: [{ url: 'https://h1.example.com:1001/', vulnid: 'V-1' }],
    });
    const { records } = await fetchRecords(client);
    expect(scopesentryRecordsToLayer(records).ok).toBe(true);
  });
});

describe('apiKeyFromEnv', () => {
  it('未設定・空ならキー名を示すエラー（値は含まない）。設定されていれば返す', () => {
    expect(() => apiKeyFromEnv({})).toThrow('SCOPESENTRY_API_KEY');
    expect(() => apiKeyFromEnv({ SCOPESENTRY_API_KEY: '  ' })).toThrow('SCOPESENTRY_API_KEY');
    expect(apiKeyFromEnv({ SCOPESENTRY_API_KEY: KEY })).toBe(KEY);
  });
});

describe('fetchViaMcp（メモリ上の MCP サーバーとの結合）', () => {
  it('実際の MCP クライアントで接続し、list_assets の結果を返す。キーは結果に含まれない', async () => {
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    const server = new McpServer({ name: 'mock-scopesentry', version: '0.0.0' });
    const seen: string[] = [];
    server.registerTool(
      'list_assets',
      { inputSchema: { asset_type: z.string(), pageIndex: z.number().optional(), pageSize: z.number().optional() } },
      async (args) => {
        seen.push(args.asset_type);
        return { content: [{ type: 'text' as const, text: JSON.stringify({ list: args.asset_type === 'asset' ? [asset(1)] : [] }) }] };
      },
    );
    await server.connect(serverSide);
    const result = await fetchViaMcp('http://127.0.0.1:9', KEY, {}, clientSide);
    expect(seen).toEqual(['asset', 'vulnerability', 'SubdomainTakerResult']);
    expect(JSON.stringify(result)).not.toContain(KEY);
  });
});
