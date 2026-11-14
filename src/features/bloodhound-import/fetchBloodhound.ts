import type { BloodhoundQuery } from './bloodhoundQueries';
import { parseCypherResponse } from './parseCypherResponse';

/**
 * BloodHound CE の API に、同梱の問い合わせ（読み取りだけの Cypher）を送る（CLI 専用）。
 * 取得した応答は `parseCypherResponse` に渡す＝ファイル取り込みと同じ関数。
 * - 呼ぶのは `POST /api/v2/graphs/cypher` だけ。問い合わせは同梱の対応表のものだけ（任意の Cypher は送らない）
 * - 認証は署名付きリクエスト（公式の API 仕様の HMAC-SHA256 の連鎖）。トークン ID・鍵は環境変数から受け取り、
 *   ヘッダの計算にだけ使う（出力・エラー文言に出さない）
 * - redirect は error（別のホストへ署名付きの要求を転送しない）
 * Web Crypto（globalThis.crypto.subtle）を使い、Node 固有の API に依存しない。
 */

export const BLOODHOUND_TOKEN_ID_ENV = 'BLOODHOUND_TOKEN_ID';
export const BLOODHOUND_TOKEN_KEY_ENV = 'BLOODHOUND_TOKEN_KEY';
export const CYPHER_PATH = '/api/v2/graphs/cypher';
const TIMEOUT_MS = 60_000;
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

export interface BloodhoundCredentials {
  tokenId: string;
  tokenKey: string;
}

export function credentialsFromEnv(env: Record<string, string | undefined>): BloodhoundCredentials {
  const tokenId = env[BLOODHOUND_TOKEN_ID_ENV]?.trim();
  const tokenKey = env[BLOODHOUND_TOKEN_KEY_ENV]?.trim();
  if (!tokenId || !tokenKey) {
    throw new Error(`環境変数 ${BLOODHOUND_TOKEN_ID_ENV} と ${BLOODHOUND_TOKEN_KEY_ENV} に API トークンを設定してください。`);
  }
  return { tokenId, tokenKey };
}

export function checkBaseUrl(baseUrl: string): string {
  let u: URL;
  try {
    u = new URL(baseUrl);
  } catch {
    throw new Error('--api の URL を解釈できません。');
  }
  if (u.username || u.password || u.search || u.hash) {
    throw new Error('--api の URL に利用者名・パスワード・クエリ・フラグメントを含めないでください。');
  }
  if (u.protocol === 'http:') {
    if (!LOCAL_HOSTS.has(u.hostname)) throw new Error('--api は https の URL を指定してください（http は localhost・127.0.0.1・[::1] のみ可）。');
  } else if (u.protocol !== 'https:') {
    throw new Error('--api は https の URL を指定してください。');
  }
  return `${u.origin}${u.pathname.replace(/\/+$/, '')}`;
}

const encoder = new TextEncoder();

async function hmac(key: Uint8Array, data: string): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, encoder.encode(data)));
}

function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

/** RFC3339（秒まで・UTC）。 */
export function rfc3339(now: Date): string {
  return now.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * 署名付きリクエストのヘッダ。公式の API 仕様の手順：
 * ① 鍵で「メソッド＋URI」の HMAC → ② その値を鍵に日時（時まで＝先頭 13 文字）の HMAC → ③ その値を鍵に本文の HMAC → base64。
 */
export async function signRequest(
  creds: BloodhoundCredentials,
  method: string,
  uri: string,
  body: string,
  now: Date,
): Promise<Record<string, string>> {
  const date = rfc3339(now);
  const k1 = await hmac(encoder.encode(creds.tokenKey), `${method}${uri}`);
  const k2 = await hmac(k1, date.slice(0, 13));
  const sig = await hmac(k2, body);
  return { Authorization: `bhesignature ${creds.tokenId}`, RequestDate: date, Signature: toBase64(sig) };
}

export interface FetchBloodhoundResult {
  /** 問い合わせ ID → 応答の JSON。 */
  responses: Map<string, unknown>;
  /** 失敗した問い合わせ（ID と理由）。 */
  failed: { queryId: string; reason: string }[];
}

export async function fetchBloodhoundQueries(
  baseUrl: string,
  creds: BloodhoundCredentials,
  queries: readonly BloodhoundQuery[],
  fetchImpl: typeof fetch = fetch,
  now: () => Date = () => new Date(),
): Promise<FetchBloodhoundResult> {
  const base = checkBaseUrl(baseUrl);
  const uriPath = `${new URL(base).pathname.replace(/\/+$/, '')}${CYPHER_PATH}`;
  const mask = (m: string): string => [creds.tokenKey, creds.tokenId].reduce((s, t) => (t ? s.split(t).join('***') : s), m);
  const responses = new Map<string, unknown>();
  const failed: FetchBloodhoundResult['failed'] = [];
  for (const q of queries) {
    const body = JSON.stringify({ query: q.cypher, include_properties: false });
    try {
      const headers = await signRequest(creds, 'POST', uriPath, body, now());
      const res = await fetchImpl(`${base}${CYPHER_PATH}`, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json', Accept: 'application/json' },
        body,
        redirect: 'error',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      // 該当 0 件は HTTP 404（本文 "resource not found"）で返る。本文を渡し、parseCypherResponse が 0 件として読む
      if (res.status === 404) {
        const notFound = (await res.json().catch(() => null)) as unknown;
        if (parseCypherResponse(notFound).ok) {
          responses.set(q.id, notFound);
          continue;
        }
      }
      if (!res.ok) {
        failed.push({ queryId: q.id, reason: `HTTP ${res.status}` });
        continue;
      }
      responses.set(q.id, await res.json());
    } catch (e) {
      failed.push({ queryId: q.id, reason: mask(e instanceof Error ? e.message : String(e)) });
    }
  }
  return { responses, failed };
}
