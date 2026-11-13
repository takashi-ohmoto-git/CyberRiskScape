import { z } from 'zod';
import { BUSINESS_CONTEXT_KIND, BUSINESS_CONTEXT_MAX_ROWS, type BusinessContextRow } from './parseBusinessContextTable';

/**
 * Celonis（プロセスマイニング）の Knowledge Model の API から業務の文脈の表（ベンダー非依存の JSON）を作る（CLI 専用）。
 * 取得部分（`fetchCelonisRecordRows`）と変換部分（`celonisRowsToTable`）に分け、変換は純粋関数。
 * - GET（Record のデータ）と、トークンの取得の POST（client_credentials）だけを呼ぶ。対象環境は変更しない。
 * - 資格情報は環境変数だけから受け取り、Authorization ヘッダ・トークン取得のフォームにだけ載せる。
 *   出力・エラー文言には出さない（応答の本文も文言に含めない）。redirect は error（別ホストへ転送しない）。
 * - API の仕様（公式ドキュメント、2026-11-13 確認）：Knowledge Model の Record の data は pageSize 1〜50・page 0〜19
 *   （最大 1,000 行）。fields は 1〜200。
 */

export const CELONIS_CLIENT_ID_ENV = 'CELONIS_CLIENT_ID';
export const CELONIS_CLIENT_SECRET_ENV = 'CELONIS_CLIENT_SECRET';
export const CELONIS_TOKEN_ENV = 'CELONIS_TOKEN';
export const CELONIS_PRODUCT = 'Celonis';
const SCOPE = 'intelligence.knowledge-models:read';
const PAGE_SIZE = 50;
const MAX_PAGES = 20;
export const CELONIS_MAX_ROWS = PAGE_SIZE * MAX_PAGES;
const TIMEOUT_MS = 30_000;

export type CelonisCredentials = { token: string } | { clientId: string; clientSecret: string };

/** 環境変数から資格情報を決める。CELONIS_TOKEN があればそれを使う。 */
export function credentialsFromEnv(env: Record<string, string | undefined>): CelonisCredentials {
  const token = env[CELONIS_TOKEN_ENV]?.trim();
  if (token) return { token };
  const clientId = env[CELONIS_CLIENT_ID_ENV]?.trim();
  const clientSecret = env[CELONIS_CLIENT_SECRET_ENV]?.trim();
  if (clientId && clientSecret) return { clientId, clientSecret };
  throw new Error(`環境変数 ${CELONIS_CLIENT_ID_ENV} と ${CELONIS_CLIENT_SECRET_ENV}（または ${CELONIS_TOKEN_ENV}）を設定してください。`);
}

function secretsOf(c: CelonisCredentials): string[] {
  return ('token' in c ? [c.token] : [c.clientId, c.clientSecret]).filter((s) => s.length > 0);
}

/** --api の検査：https・userinfo なし・クエリ/フラグメントなし。末尾の / は除く。 */
export function checkApiBase(api: string): { base: string; origin: string } {
  let u: URL;
  try {
    u = new URL(api);
  } catch {
    throw new Error('--api の URL を解釈できません。');
  }
  if (u.protocol !== 'https:') throw new Error('--api は https の URL を指定してください。');
  if (u.username || u.password) throw new Error('--api に認証情報（userinfo）を含めないでください。');
  if (u.search || u.hash) throw new Error('--api にクエリ・フラグメントを含めないでください。');
  return { base: `${u.origin}${u.pathname.replace(/\/+$/, '')}`, origin: u.origin };
}

const TokenSchema = z.object({ access_token: z.string().min(1) });

const DataSchema = z.object({
  total: z.number().int().nonnegative().optional(),
  content: z.object({ data: z.array(z.record(z.string(), z.unknown())) }),
});

async function readJson(res: Response, what: string): Promise<unknown> {
  const type = res.headers?.get?.('content-type') ?? 'application/json';
  if (!/json/i.test(type)) throw new Error(`${what} の応答が JSON ではありません。`);
  try {
    return await res.json();
  } catch {
    throw new Error(`${what} の応答が JSON として読めません。`);
  }
}

/** client_credentials でアクセストークンを取る（POST・scope は読み取りのみ）。 */
export async function fetchAccessToken(origin: string, creds: CelonisCredentials, fetchImpl: typeof fetch): Promise<string> {
  if ('token' in creds) return creds.token;
  const res = await fetchImpl(`${origin}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: creds.clientId,
      client_secret: creds.clientSecret,
      scope: SCOPE,
    }).toString(),
    redirect: 'error',
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`Celonis のトークン取得が HTTP ${res.status} を返しました。`);
  const parsed = TokenSchema.safeParse(await readJson(res, 'トークン取得'));
  if (!parsed.success) throw new Error('Celonis のトークン取得の応答にアクセストークンがありません。');
  return parsed.data.access_token;
}

export interface FetchCelonisOptions {
  km: string;
  record: string;
  fields: readonly string[];
}

export interface FetchCelonisResult {
  rows: Record<string, unknown>[];
  /** API が返した総件数（無ければ undefined）。 */
  total?: number;
  /** 取得できる上限（1,000 行）で打ち切った。 */
  truncated: boolean;
}

/** Record のデータをページごとに GET して集める。資格情報は出力・エラーに含めない。 */
export async function fetchCelonisRecordRows(
  api: string,
  creds: CelonisCredentials,
  opts: FetchCelonisOptions,
  fetchImpl: typeof fetch = fetch,
): Promise<FetchCelonisResult> {
  const { base, origin } = checkApiBase(api);
  if (opts.fields.length < 1 || opts.fields.length > 200) throw new Error('取得する項目は 1〜200 個にしてください。');
  const secrets = secretsOf(creds);
  const mask = (m: string): string => secrets.reduce((s, secret) => s.split(secret).join('***'), m);
  try {
    const token = await fetchAccessToken(origin, creds, fetchImpl);
    if (token) secrets.push(token);
    const rows: Record<string, unknown>[] = [];
    let total: number | undefined;
    for (let page = 0; page < MAX_PAGES; page += 1) {
      const q = new URLSearchParams({ fields: opts.fields.join(','), pageSize: String(PAGE_SIZE), page: String(page) });
      const url = `${base}/knowledge-models/${encodeURIComponent(opts.km)}/records/${encodeURIComponent(opts.record)}/data?${q.toString()}`;
      const res = await fetchImpl(url, {
        method: 'GET',
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
        redirect: 'error',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`Celonis が HTTP ${res.status} を返しました。`);
      const parsed = DataSchema.safeParse(await readJson(res, 'データ取得'));
      if (!parsed.success) throw new Error('Celonis のデータ取得の応答の形が想定と違います。');
      total = parsed.data.total ?? total;
      const data = parsed.data.content.data;
      rows.push(...data);
      if (data.length < PAGE_SIZE || (total !== undefined && rows.length >= total)) return { rows, total, truncated: false };
    }
    return { rows, total, truncated: total === undefined || total > rows.length };
  } catch (e) {
    throw new Error(mask(e instanceof Error ? e.message : String(e)), { cause: e });
  }
}

export interface CelonisTableOptions {
  km: string;
  record: string;
  systemField: string;
  /** システムの値 → ノードの参照（C 番号または ID）。 */
  map: ReadonlyMap<string, string>;
  process?: string;
  processField?: string;
  valueField?: string;
  casesField?: string;
  currency?: string;
  period?: string;
}

export interface CelonisTableSummary {
  rows: number;
  used: number;
  /** 対応づけがなく除外した、システムの値ごとの行数。 */
  unmapped: Record<string, number>;
  /** プロセス名が取れず除外した行数。 */
  missingProcess: number;
  /** 数値として読めず無視した値の数。 */
  nonNumeric: number;
}

export interface CelonisTable {
  kind: typeof BUSINESS_CONTEXT_KIND;
  schemaVersion: 1;
  source: { product: string; ref: string };
  rows: BusinessContextRow[];
}

const asText = (v: unknown): string | undefined => {
  if (typeof v === 'string') return v.trim() || undefined;
  if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  return undefined;
};

/** 非負の有限な数だけ（数値文字列も可）。 */
const asAmount = (v: unknown): number | undefined => {
  const n = typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' ? Number(v) : Number.NaN;
  return Number.isFinite(n) && n >= 0 ? n : undefined;
};

/** 取得した行を、業務の文脈の表（JSON）に変換する純粋関数。 */
export function celonisRowsToTable(
  data: readonly Record<string, unknown>[],
  o: CelonisTableOptions,
): { table: CelonisTable; summary: CelonisTableSummary } {
  if (!o.process && !o.processField) throw new Error('--process か --process-field のどちらかを指定してください。');
  const summary: CelonisTableSummary = { rows: data.length, used: 0, unmapped: {}, missingProcess: 0, nonNumeric: 0 };
  const rows: BusinessContextRow[] = [];
  const unmapped = new Map<string, number>();
  for (const d of data) {
    const sys = asText(d[o.systemField]);
    const node = sys === undefined ? undefined : o.map.get(sys);
    if (node === undefined) {
      const k = sys ?? '（空）';
      unmapped.set(k, (unmapped.get(k) ?? 0) + 1);
      continue;
    }
    const process = o.process ?? asText(d[o.processField as string]);
    if (!process) {
      summary.missingProcess += 1;
      continue;
    }
    const row: BusinessContextRow = { node, process: process.slice(0, 200) };
    for (const [field, key] of [
      [o.valueField, 'value'],
      [o.casesField, 'cases'],
    ] as const) {
      if (!field || d[field] === undefined || d[field] === null) continue;
      const n = asAmount(d[field]);
      if (n === undefined) summary.nonNumeric += 1;
      else row[key] = n;
    }
    if (o.currency) row.currency = o.currency;
    if (o.period) row.period = o.period;
    rows.push(row);
  }
  if (rows.length > BUSINESS_CONTEXT_MAX_ROWS) throw new Error(`行が多すぎます（上限 ${BUSINESS_CONTEXT_MAX_ROWS} 行）。`);
  summary.used = rows.length;
  summary.unmapped = Object.fromEntries(unmapped);
  return {
    table: {
      kind: BUSINESS_CONTEXT_KIND,
      schemaVersion: 1,
      source: { product: CELONIS_PRODUCT, ref: `km:${o.km}/record:${o.record}`.slice(0, 200) },
      rows,
    },
    summary,
  };
}

/** `--map <値>=<ノード>` の繰り返しを Map にする。同じ値の重複はエラー。 */
export function parseValueMaps(args: readonly string[]): Map<string, string> {
  const m = new Map<string, string>();
  for (const a of args) {
    const i = a.indexOf('=');
    const key = i > 0 ? a.slice(0, i).trim() : '';
    const node = i > 0 ? a.slice(i + 1).trim() : '';
    if (!key || !node) throw new Error(`--map は <値>=<C番号|ID> の形で指定してください: "${a}"`);
    if (m.has(key)) throw new Error(`--map の値が重複しています: "${key}"`);
    m.set(key, node);
  }
  if (m.size === 0) throw new Error('--map を 1 つ以上指定してください。');
  return m;
}
