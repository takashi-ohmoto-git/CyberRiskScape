import { describe, expect, it } from 'vitest';
import { BUNDLED_GRAPH_PERMISSIONS, loadGraphPermissions } from './graphPermissions';
import { parseAssignments, parseGrants, parseServicePrincipals, type ParseGraphResult } from './parseGraph';
import { entraAppsToFindings } from './entraAppsToFindings';
import { fetchGraphInventory, graphCredentialsFromEnv } from './fetchGraph';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';

/** 架空のテナント・アプリ。 */
const TENANT = '11111111-1111-4111-8111-111111111111';
const PARTNER = '22222222-2222-4222-8222-222222222222';
const MS = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a';
const GRAPH_APP = '00000003-0000-0000-c000-000000000000';
const ROLE_MAIL = 'aaaaaaaa-0000-4000-8000-000000000001';
const ROLE_USERREAD = 'aaaaaaaa-0000-4000-8000-000000000002';

const page = (value: object[], next?: string) => ({ value, ...(next ? { '@odata.nextLink': next } : {}) });

const sps = page([
  { id: 'sp-own', appId: 'own', displayName: 'Own App', appOwnerOrganizationId: TENANT, servicePrincipalType: 'Application' },
  {
    id: 'sp-partner',
    appId: 'p1',
    displayName: 'Partner Sync',
    appOwnerOrganizationId: PARTNER,
    servicePrincipalType: 'Application',
    passwordCredentials: [{ endDateTime: '2099-01-01T00:00:00Z', hint: 'abc', secretText: 'TOP-SECRET-VALUE' }],
  },
  {
    id: 'sp-verified',
    appId: 'p2',
    displayName: 'Verified Mailer',
    appOwnerOrganizationId: PARTNER,
    servicePrincipalType: 'Application',
    verifiedPublisher: { displayName: 'Example Publisher', verifiedPublisherId: '123' },
  },
  { id: 'sp-ms', appId: 'm1', displayName: 'Microsoft Service X', appOwnerOrganizationId: MS, servicePrincipalType: 'Application', keyCredentials: [{ endDateTime: '2030-01-01T00:00:00Z' }] },
  { id: 'sp-mi', appId: 'mi', displayName: 'build-identity', appOwnerOrganizationId: null, servicePrincipalType: 'ManagedIdentity' },
]);
const graphSp = { id: 'sp-graph', appId: GRAPH_APP, displayName: 'Microsoft Graph', appRoles: [{ id: ROLE_MAIL, value: 'Mail.Read' }, { id: ROLE_USERREAD, value: 'User.Read.All' }] };
const assignments = page([
  { principalId: 'sp-partner', principalType: 'ServicePrincipal', appRoleId: ROLE_MAIL },
  { principalId: 'sp-verified', principalType: 'ServicePrincipal', appRoleId: ROLE_USERREAD },
  { principalId: 'sp-own', principalType: 'ServicePrincipal', appRoleId: ROLE_MAIL },
]);
const grants = page([
  { clientId: 'sp-verified', consentType: 'AllPrincipals', resourceId: 'sp-graph', scope: 'openid Files.ReadWrite.All' },
  { clientId: 'sp-partner', consentType: 'Principal', principalId: 'user-carol', resourceId: 'sp-graph', scope: 'Mail.Read' },
  { clientId: 'sp-partner', consentType: 'Principal', principalId: 'user-dave', resourceId: 'sp-graph', scope: 'User.Read' },
  { clientId: 'sp-partner', consentType: 'AllPrincipals', resourceId: 'sp-other-api', scope: 'Mail.Read' },
]);

const items = <T>(r: ParseGraphResult<T>): T[] => {
  if (!r.ok) throw new Error(r.error);
  return r.items;
};

function convert(diagramApps: { label: string; name: string }[] = []) {
  return entraAppsToFindings({
    servicePrincipals: [...items(parseServicePrincipals(sps)), ...items(parseServicePrincipals(graphSp))],
    grants: items(parseGrants(grants)),
    graphAssignments: items(parseAssignments(assignments)),
    tenantId: TENANT,
    perms: BUNDLED_GRAPH_PERMISSIONS,
    subject: { layer: 'L1', nodeId: 'entra' },
    diagramApps,
    scope: 'contoso',
    importedAt: '2026-11-15T00:00:00Z',
  });
}

describe('graphPermissions', () => {
  it('同梱の一覧を読め、Microsoft のテナント ID と Graph のアプリ ID を持つ', () => {
    expect(BUNDLED_GRAPH_PERMISSIONS.microsoftTenantIds.has(MS)).toBe(true);
    expect(BUNDLED_GRAPH_PERMISSIONS.graphAppId).toBe(GRAPH_APP);
    expect(BUNDLED_GRAPH_PERMISSIONS.powerful.get('Mail.Read')).toBeDefined();
    expect(BUNDLED_GRAPH_PERMISSIONS.powerful.has('User.Read')).toBe(false);
  });

  it('名前の重複は読み込みでエラー', () => {
    const yaml = `schemaVersion: 1\nmicrosoftTenantIds: []\ngraphAppId: ${GRAPH_APP}\npowerfulPermissions:\n  - group: a\n    names: [X]\n  - group: b\n    names: [X]\n`;
    expect(() => loadGraphPermissions(yaml)).toThrow();
  });
});

describe('parseGraph', () => {
  it('資格情報は件数だけを読み、ヒント・値は持たない。同意の利用者は持たない', () => {
    const r = parseServicePrincipals(sps);
    expect(r.ok && r.items.find((s) => s.id === 'sp-partner')?.credentialCount).toBe(1);
    const all = JSON.stringify([r, parseGrants(grants)]);
    expect(all).not.toContain('TOP-SECRET-VALUE');
    expect(all).not.toContain('"abc"');
    expect(all).not.toContain('user-carol');
  });

  it('ページの配列も受け、形が違えばエラー', () => {
    const r = parseGrants([page([grants.value[0]]), page([grants.value[1]])]);
    expect(r.ok && r.items).toHaveLength(2);
    expect(parseServicePrincipals({ nope: 1 }).ok).toBe(false);
  });
});

describe('entraAppsToFindings', () => {
  it('外部アプリの強いアプリ単独の権限・テナント全体の同意・利用者ごとの同意・Microsoft のアプリの資格情報を指摘にする', () => {
    const { findings, externalCount, externalApps } = convert();
    expect(externalCount).toBe(2);
    const byId = Object.fromEntries(findings.map((f) => [f.externalId, f]));
    // 自組織のアプリ（Own App）の Mail.Read は外部アプリではないので数えない。User.Read.All は一覧に無い
    expect(byId['external-app-powerful-app-permissions']).toMatchObject({ severity: 'Critical', canonicalIds: ['idp-app-only-privilege'], subject: { nodeId: 'entra' } });
    expect(byId['external-app-powerful-app-permissions'].resource?.label).toContain('Partner Sync');
    expect(byId['external-app-powerful-app-permissions'].resource?.label).toContain('発行元未確認 1');
    expect(byId['external-app-tenant-wide-consent'].resource?.label).toContain('Verified Mailer');
    // Graph 以外の API への同意は数えない。利用者の User.Read は強い権限ではない
    expect(byId['external-app-user-consent']).toMatchObject({ severity: 'Medium', canonicalIds: ['idp-external-app-consent'] });
    expect(externalApps.find((a) => a.name === 'Partner Sync')).toMatchObject({ appPermissions: ['Mail.Read'], tenantWideScopes: [], userConsentCount: 1 });
    expect(byId['microsoft-app-credentials'].resource?.label).toContain('Microsoft Service X');
    expect(JSON.stringify(findings)).not.toMatch(/user-carol|user-dave/);
  });

  it('外部アプリを図のアプリ系のノードとラベルで突き合わせる（大文字小文字・前後の空白を無視）', () => {
    const { externalApps } = convert([{ label: 'C7 partner sync', name: ' partner SYNC ' }]);
    expect(externalApps.find((a) => a.name === 'Partner Sync')?.diagramNode).toBe('C7 partner sync');
    expect(externalApps.find((a) => a.name === 'Verified Mailer')?.diagramNode).toBeUndefined();
  });

  it('対応表の canonicalId はすべて脅威ライブラリに実在する', () => {
    const known = new Set(BUNDLED_THREAT_LIBRARY.rules.map((r) => r.canonicalId));
    for (const f of convert().findings) for (const c of f.canonicalIds) expect(known.has(c), c).toBe(true);
  });
});

describe('fetchGraph', () => {
  const creds = { tenantId: TENANT, clientId: 'client-1', clientSecret: 'very-secret' };

  it('環境変数が無い・テナント ID が GUID でなければエラー', () => {
    expect(() => graphCredentialsFromEnv({})).toThrow(/MSGRAPH_TENANT_ID/);
    expect(() => graphCredentialsFromEnv({ MSGRAPH_TENANT_ID: 'x', MSGRAPH_CLIENT_ID: 'a', MSGRAPH_CLIENT_SECRET: 'b' })).toThrow(/GUID/);
  });

  it('クライアント資格情報でトークンを取り、GET だけで 4 つの一覧を読む。次のページは graph.microsoft.com だけ辿る', async () => {
    const calls: { url: string; method?: string }[] = [];
    const fake = (async (url: string, init: RequestInit) => {
      calls.push({ url, method: init.method });
      if (url.startsWith('https://login.microsoftonline.com/')) {
        expect(String(init.body)).toContain('grant_type=client_credentials');
        expect(String(init.body)).toContain('scope=https%3A%2F%2Fgraph.microsoft.com%2F.default');
        return new Response(JSON.stringify({ access_token: 'tok' }), { status: 200 });
      }
      expect((init.headers as Record<string, string>).Authorization).toBe('Bearer tok');
      if (url.includes('/servicePrincipals?') && !url.includes('skiptoken')) {
        return new Response(JSON.stringify(page([], 'https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=x')), { status: 200 });
      }
      if (url.includes('/oauth2PermissionGrants')) {
        return new Response(JSON.stringify(page([], 'https://evil.example.com/next')), { status: 200 });
      }
      return new Response(JSON.stringify(url.endsWith('appRoles') ? graphSp : page([])), { status: 200 });
    }) as unknown as typeof fetch;
    const r = await fetchGraphInventory(creds, GRAPH_APP, fake);
    expect(calls[0]).toMatchObject({ method: 'POST', url: `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token` });
    expect(calls.slice(1).every((c) => c.method === 'GET' && c.url.startsWith('https://graph.microsoft.com/v1.0/'))).toBe(true);
    expect(r.servicePrincipals).toHaveLength(2);
    expect(r.oauth2PermissionGrants).toHaveLength(1);
    expect(calls.some((c) => c.url.includes('evil.example.com'))).toBe(false);
  });

  it('エラー文言にクライアントシークレットを出さない', async () => {
    const fake = (async () => {
      throw new Error(`boom ${creds.clientSecret}`);
    }) as unknown as typeof fetch;
    await expect(fetchGraphInventory(creds, GRAPH_APP, fake)).rejects.toThrow('boom ***');
  });
});
