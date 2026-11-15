/**
 * Microsoft Graph（v1.0）から外部アプリ・同意の在庫を読む（CLI 専用）。取得した生のページは parseGraph の関数に渡す
 * ＝ファイル取り込みと同じ関数。
 * - トークンはクライアント資格情報フロー（公式の Microsoft identity platform の手順）。テナント ID・クライアント ID・
 *   クライアントシークレットは環境変数から受け取り、トークンの要求にだけ使う（出力・エラー文言に出さない）
 * - 呼ぶのは読み取りの GET だけ（4 つの一覧）。次のページの URL は graph.microsoft.com のものだけを辿る
 * - redirect は error（別のホストへトークンを転送しない）
 * 要る権限（アプリケーションの権限）：Application.Read.All・Directory.Read.All（委任の同意の一覧）。
 */

export const MSGRAPH_TENANT_ENV = 'MSGRAPH_TENANT_ID';
export const MSGRAPH_CLIENT_ID_ENV = 'MSGRAPH_CLIENT_ID';
export const MSGRAPH_CLIENT_SECRET_ENV = 'MSGRAPH_CLIENT_SECRET';

const GRAPH_ORIGIN = 'https://graph.microsoft.com';
const TIMEOUT_MS = 60_000;
/** 1 つの一覧で辿るページの上限（1 ページ最大 999 件）。 */
const MAX_PAGES = 200;

export interface GraphCredentials {
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function graphCredentialsFromEnv(env: Record<string, string | undefined>): GraphCredentials {
  const tenantId = env[MSGRAPH_TENANT_ENV]?.trim();
  const clientId = env[MSGRAPH_CLIENT_ID_ENV]?.trim();
  const clientSecret = env[MSGRAPH_CLIENT_SECRET_ENV]?.trim();
  if (!tenantId || !clientId || !clientSecret) {
    throw new Error(`環境変数 ${MSGRAPH_TENANT_ENV}・${MSGRAPH_CLIENT_ID_ENV}・${MSGRAPH_CLIENT_SECRET_ENV} を設定してください。`);
  }
  if (!GUID_RE.test(tenantId)) throw new Error(`${MSGRAPH_TENANT_ENV} はテナント ID（GUID）にしてください。`);
  return { tenantId, clientId, clientSecret };
}

export interface GraphFetchResult {
  servicePrincipals: unknown[];
  graphServicePrincipal: unknown;
  graphAppRoleAssignedTo: unknown[];
  oauth2PermissionGrants: unknown[];
  /** ページの上限で打ち切った一覧。 */
  truncated: string[];
}

export async function fetchGraphInventory(
  creds: GraphCredentials,
  graphAppId: string,
  fetchImpl: typeof fetch = fetch,
): Promise<GraphFetchResult> {
  const mask = (m: string): string => [creds.clientSecret].reduce((s, t) => (t ? s.split(t).join('***') : s), m);
  try {
    const tokenRes = await fetchImpl(`https://login.microsoftonline.com/${creds.tenantId}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: creds.clientId,
        client_secret: creds.clientSecret,
        scope: `${GRAPH_ORIGIN}/.default`,
        grant_type: 'client_credentials',
      }).toString(),
      redirect: 'error',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!tokenRes.ok) throw new Error(`トークンを取得できません（HTTP ${tokenRes.status}）。`);
    const token = ((await tokenRes.json()) as { access_token?: unknown }).access_token;
    if (typeof token !== 'string' || token === '') throw new Error('トークンの応答に access_token がありません。');

    const get = async (url: string): Promise<unknown> => {
      const res = await fetchImpl(url, {
        method: 'GET',
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
        redirect: 'error',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`Microsoft Graph が HTTP ${res.status} を返しました（${new URL(url).pathname}）。`);
      return res.json();
    };
    const truncated: string[] = [];
    const list = async (path: string, name: string): Promise<unknown[]> => {
      const pages: unknown[] = [];
      let url: string | undefined = `${GRAPH_ORIGIN}${path}`;
      while (url) {
        if (pages.length >= MAX_PAGES) {
          truncated.push(name);
          break;
        }
        const page = (await get(url)) as { '@odata.nextLink'?: unknown };
        pages.push(page);
        const next = page['@odata.nextLink'];
        url = typeof next === 'string' && next.startsWith(`${GRAPH_ORIGIN}/`) ? next : undefined;
      }
      return pages;
    };
    const app = encodeURIComponent(graphAppId);
    return {
      servicePrincipals: await list(
        '/v1.0/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled,verifiedPublisher,passwordCredentials,keyCredentials&$top=999',
        'servicePrincipals',
      ),
      graphServicePrincipal: await get(`${GRAPH_ORIGIN}/v1.0/servicePrincipals(appId='${app}')?$select=id,appId,displayName,appRoles`),
      graphAppRoleAssignedTo: await list(`/v1.0/servicePrincipals(appId='${app}')/appRoleAssignedTo?$top=999`, 'appRoleAssignedTo'),
      oauth2PermissionGrants: await list('/v1.0/oauth2PermissionGrants', 'oauth2PermissionGrants'),
      truncated,
    };
  } catch (e) {
    throw new Error(mask(e instanceof Error ? e.message : String(e)), { cause: e });
  }
}
