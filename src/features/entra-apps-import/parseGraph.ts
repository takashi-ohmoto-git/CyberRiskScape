import { z } from 'zod';

/**
 * Microsoft Graph（v1.0）の応答から、外部アプリ・同意の在庫に要る項目だけを取り出す。
 * 応答は 1 ページ（`{ value: [...] }`）でも、ページの配列でもよい。項目は公式の資源の定義
 * （servicePrincipal・oAuth2PermissionGrant・appRoleAssignment）による。
 * - 資格情報は有効期限（endDateTime）だけを読む（hint・secretText 等は捨てる）
 * - 利用者の ID・名前（同意の principalId 等）は読まない
 * DOM にも Node にも依存しない。
 */

const Credential = z.object({ endDateTime: z.string().nullish() });

const ServicePrincipalSchema = z.object({
  id: z.string().min(1),
  appId: z.string().nullish(),
  displayName: z.string().nullish(),
  appOwnerOrganizationId: z.string().nullish(),
  servicePrincipalType: z.string().nullish(),
  accountEnabled: z.boolean().nullish(),
  verifiedPublisher: z.object({ displayName: z.string().nullish(), verifiedPublisherId: z.string().nullish() }).nullish(),
  passwordCredentials: z.array(Credential).nullish(),
  keyCredentials: z.array(Credential).nullish(),
  appRoles: z.array(z.object({ id: z.string(), value: z.string().nullish() })).nullish(),
});

const GrantSchema = z.object({
  clientId: z.string().min(1),
  consentType: z.string().nullish(),
  resourceId: z.string().nullish(),
  scope: z.string().nullish(),
});

const AssignmentSchema = z.object({
  principalId: z.string().min(1),
  principalType: z.string().nullish(),
  appRoleId: z.string().min(1),
  resourceId: z.string().nullish(),
});

export interface GraphServicePrincipal {
  id: string;
  appId?: string;
  displayName: string;
  appOwnerOrganizationId?: string;
  servicePrincipalType?: string;
  accountEnabled: boolean;
  verifiedPublisher?: string;
  credentialCount: number;
  appRoles: { id: string; value?: string }[];
}

export interface GraphGrant {
  clientId: string;
  consentType: 'AllPrincipals' | 'Principal' | 'Other';
  resourceId?: string;
  scopes: string[];
}

export interface GraphAssignment {
  principalId: string;
  principalType?: string;
  appRoleId: string;
}

export type ParseGraphResult<T> = { ok: true; items: T[]; invalid: number } | { ok: false; error: string };

const PageSchema = z.object({ value: z.array(z.unknown()) });

/** 1 ページ・ページの配列・資源 1 件（value を持たない）のどれでも受け、要素を並べる。 */
function itemsOf(raw: unknown): unknown[] | undefined {
  const pages = Array.isArray(raw) ? raw : [raw];
  const out: unknown[] = [];
  for (const p of pages) {
    const page = PageSchema.safeParse(p);
    if (page.success) out.push(...page.data.value);
    else if (p && typeof p === 'object' && 'id' in p) out.push(p);
    else return undefined;
  }
  return out;
}

function parseItems<S extends z.ZodTypeAny, T>(raw: unknown, schema: S, map: (v: z.infer<S>) => T, what: string): ParseGraphResult<T> {
  const items = itemsOf(raw);
  if (!items) return { ok: false, error: `Microsoft Graph の ${what} の応答の形ではありません（value の配列が必要です）。` };
  const out: T[] = [];
  let invalid = 0;
  for (const i of items) {
    const r = schema.safeParse(i);
    if (r.success) out.push(map(r.data));
    else invalid += 1;
  }
  return { ok: true, items: out, invalid };
}

export function parseServicePrincipals(raw: unknown): ParseGraphResult<GraphServicePrincipal> {
  return parseItems(
    raw,
    ServicePrincipalSchema,
    (v) => ({
      id: v.id,
      ...(v.appId ? { appId: v.appId.toLowerCase() } : {}),
      displayName: (v.displayName ?? v.appId ?? v.id).slice(0, 200),
      ...(v.appOwnerOrganizationId ? { appOwnerOrganizationId: v.appOwnerOrganizationId.toLowerCase() } : {}),
      ...(v.servicePrincipalType ? { servicePrincipalType: v.servicePrincipalType } : {}),
      accountEnabled: v.accountEnabled !== false,
      ...(v.verifiedPublisher?.verifiedPublisherId ? { verifiedPublisher: (v.verifiedPublisher.displayName ?? v.verifiedPublisher.verifiedPublisherId).slice(0, 200) } : {}),
      credentialCount: (v.passwordCredentials?.length ?? 0) + (v.keyCredentials?.length ?? 0),
      appRoles: (v.appRoles ?? []).map((r) => ({ id: r.id.toLowerCase(), ...(r.value ? { value: r.value } : {}) })),
    }),
    'servicePrincipals',
  );
}

export function parseGrants(raw: unknown): ParseGraphResult<GraphGrant> {
  return parseItems(
    raw,
    GrantSchema,
    (v) => ({
      clientId: v.clientId,
      consentType: v.consentType === 'AllPrincipals' || v.consentType === 'Principal' ? v.consentType : ('Other' as const),
      ...(v.resourceId ? { resourceId: v.resourceId } : {}),
      scopes: (v.scope ?? '').split(/\s+/).filter(Boolean),
    }),
    'oauth2PermissionGrants',
  );
}

export function parseAssignments(raw: unknown): ParseGraphResult<GraphAssignment> {
  return parseItems(
    raw,
    AssignmentSchema,
    (v) => ({ principalId: v.principalId, ...(v.principalType ? { principalType: v.principalType } : {}), appRoleId: v.appRoleId.toLowerCase() }),
    'appRoleAssignedTo',
  );
}
