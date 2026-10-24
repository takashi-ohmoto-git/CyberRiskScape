import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { BRANDING } from '../../core/branding';

/**
 * ScopeSentry の公式 MCP（`<base-url>/mcp`、Streamable HTTP）から、読み取り専用の `list_assets` だけで
 * 取り込み用のレコードを集める（CLI 専用）。取得結果は `scopesentryRecordsToLayer` に渡す＝ファイル取り込みと同じ関数。
 *
 * - 呼べるツールは `ALLOWED_TOOLS` に固定する（create_* / add_asset_tag 等の書き込み系は呼べない）。
 * - API キーは環境変数から受け取り、ヘッダにだけ載せる。ログ・エラー文言・保存物には出さない。
 * - REST は JWT が必要でキー（ssk_...）が通るのは /mcp だけなので、MCP クライアントとして接続する。
 */

/** 呼んでよい MCP ツール。ここに無い名前は呼ばない。 */
export const ALLOWED_TOOLS = ['list_assets'] as const;
/** 取得する資産種別（ScopeSentry の asset_type）。 */
export const ASSET_TYPES = ['asset', 'vulnerability', 'SubdomainTakerResult'] as const;
export const PAGE_SIZE = 100;
/** 取得するレコード数の上限（全種別の合計）。 */
export const MAX_RECORDS = 3000;

/** `callTool` だけを使う最小のクライアント（テストでモックに差し替える）。 */
export interface McpToolClient {
  callTool(params: { name: string; arguments?: Record<string, unknown> }): Promise<unknown>;
}

export interface FetchOptions {
  /** プロジェクトの ObjectID（`filter.project` に入る）。 */
  project?: string;
  /** ScopeSentry の検索式。 */
  search?: string;
}

export interface FetchResult {
  records: unknown[];
  /** 上限に達して打ち切った種別があるか。 */
  capped: boolean;
}

/** 許可リストにあるツールだけ呼ぶ。 */
async function callAllowed(client: McpToolClient, name: string, args: Record<string, unknown>): Promise<unknown> {
  if (!(ALLOWED_TOOLS as readonly string[]).includes(name)) throw new Error(`許可されていない MCP ツールです: ${name}`);
  return client.callTool({ name, arguments: args });
}

/** CallToolResult から `list` 配列を取り出す。isError なら本文を添えて例外にする。 */
function listOf(result: unknown): unknown[] {
  const r = (result ?? {}) as { isError?: boolean; content?: { type?: string; text?: string }[]; structuredContent?: unknown };
  const text = r.content?.find((c) => c.type === 'text')?.text;
  if (r.isError) throw new Error(`ScopeSentry がエラーを返しました: ${text ?? '(本文なし)'}`);
  let body: unknown = r.structuredContent;
  if (text !== undefined) {
    try {
      body = JSON.parse(text);
    } catch {
      throw new Error('ScopeSentry の応答を JSON として読めません。');
    }
  }
  const list = (body as { list?: unknown } | undefined)?.list;
  if (!Array.isArray(list)) throw new Error('ScopeSentry の応答に list がありません。');
  return list;
}

/** `list_assets` を種別ごとにページ送りして集める。短いページで終了し、合計 MAX_RECORDS で打ち切る。 */
export async function fetchRecords(client: McpToolClient, options: FetchOptions = {}): Promise<FetchResult> {
  const records: unknown[] = [];
  let capped = false;
  for (const assetType of ASSET_TYPES) {
    for (let pageIndex = 1; ; pageIndex++) {
      if (records.length >= MAX_RECORDS) {
        capped = true;
        break;
      }
      const list = listOf(
        await callAllowed(client, 'list_assets', {
          asset_type: assetType,
          pageIndex,
          pageSize: PAGE_SIZE,
          ...(options.search ? { search: options.search } : {}),
          ...(options.project ? { filter: { project: [options.project] } } : {}),
        }),
      );
      records.push(...list.slice(0, MAX_RECORDS - records.length));
      if (list.length < PAGE_SIZE) break;
    }
  }
  return { records, capped };
}

/** 環境変数から API キーを取り出す。無ければ例外（値は出さない）。 */
export function apiKeyFromEnv(env: Record<string, string | undefined>): string {
  const key = env.SCOPESENTRY_API_KEY?.trim();
  if (!key) throw new Error('環境変数 SCOPESENTRY_API_KEY に ScopeSentry の API キー（ssk_...）を設定してください。');
  return key;
}

/** 接続して取得し、必ず切断する。transport を渡せばネットワークなしでテストできる。 */
export async function fetchViaMcp(
  baseUrl: string,
  apiKey: string,
  options: FetchOptions = {},
  transport?: Transport,
): Promise<FetchResult> {
  const t =
    transport ??
    new StreamableHTTPClientTransport(new URL(`${baseUrl.replace(/\/+$/, '')}/mcp`), {
      requestInit: { headers: { 'X-API-Key': apiKey } },
    });
  const client = new Client({ name: `${BRANDING.name}-import`, version: '1.0.0' });
  try {
    await client.connect(t);
    return await fetchRecords(client, options);
  } finally {
    await client.close().catch(() => undefined);
  }
}
