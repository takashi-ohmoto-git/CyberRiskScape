import type { Finding, LayerKey, Severity } from '../../core/model/types';
import type { GraphPermissionMap } from './graphPermissions';
import type { GraphAssignment, GraphGrant, GraphServicePrincipal } from './parseGraph';

/**
 * Microsoft Graph の在庫（サービスプリンシパル・委任の同意・Graph のアプリ単独の権限）を、指摘と外部アプリの一覧にする。
 * - 外部アプリ：所有テナントが自組織でも Microsoft のサービスでもない、アプリのサービスプリンシパル
 * - 指摘は観測ごとに 1 件で IdP に載せる（無ければ未結合）。名前はアプリの表示名だけ（利用者の名前は扱わない）
 * - 図との突き合わせは、外部アプリの表示名と図のアプリ系のノードのラベルの完全一致（大文字小文字・前後の空白を無視）
 * DOM にも Node にも依存しない純粋関数。
 */

export const ENTRA_APPS_PRODUCT = 'Microsoft Graph';

const MAX_NAMES = 20;
const TEXT_MAX = 200;

export interface ExternalApp {
  name: string;
  /** 確認済みの発行元（無ければ未確認）。 */
  verifiedPublisher?: string;
  /** 強いアプリ単独の Graph の権限。 */
  appPermissions: string[];
  /** 強い委任の権限（テナント全体の同意）。 */
  tenantWideScopes: string[];
  /** 強い委任の権限について、利用者ごとの同意の件数（利用者は特定しない）。 */
  userConsentCount: number;
  /** 図で一致したノード（C 番号とラベル）。 */
  diagramNode?: string;
}

export interface EntraAppsCheck {
  id: string;
  title: string;
  count: number;
}

export interface EntraAppsInput {
  servicePrincipals: readonly GraphServicePrincipal[];
  grants: readonly GraphGrant[];
  /** Microsoft Graph のサービスプリンシパルに対するアプリ単独の権限（appRoleAssignedTo）。 */
  graphAssignments: readonly GraphAssignment[];
  tenantId: string;
  perms: GraphPermissionMap;
  subject?: { layer: LayerKey; nodeId: string };
  /** 図のアプリ系のノード（突き合わせ用）。 */
  diagramApps: readonly { label: string; name: string }[];
  scope: string;
  importedAt: string;
}

interface Check {
  id: string;
  title: string;
  severity: Severity;
  canonicalIds: string[];
}

const CHECKS = {
  appPerms: {
    id: 'external-app-powerful-app-permissions',
    title: '強いアプリ単独の権限（Microsoft Graph）を持つ外部アプリ',
    severity: 'Critical',
    canonicalIds: ['idp-app-only-privilege'],
  },
  tenantWide: {
    id: 'external-app-tenant-wide-consent',
    title: '強い権限をテナント全体で同意した外部アプリ',
    severity: 'High',
    canonicalIds: ['idp-external-app-consent'],
  },
  userConsent: {
    id: 'external-app-user-consent',
    title: '強い権限を利用者が個別に同意した外部アプリ',
    severity: 'Medium',
    canonicalIds: ['idp-external-app-consent'],
  },
  msCredentials: {
    id: 'microsoft-app-credentials',
    title: '資格情報が設定された Microsoft のサービスのアプリ',
    severity: 'High',
    canonicalIds: ['idp-app-credential-addition'],
  },
} satisfies Record<string, Check>;

const norm = (s: string) => s.trim().toLowerCase();

function label(names: readonly string[], unverified: number): string {
  const head = `${names.length} 件${unverified > 0 ? `（発行元未確認 ${unverified}）` : ''}`;
  const text = `${head}：${names.slice(0, MAX_NAMES).join(', ')}${names.length > MAX_NAMES ? ` ほか ${names.length - MAX_NAMES} 件` : ''}`;
  return text.length > TEXT_MAX ? `${text.slice(0, TEXT_MAX - 1)}…` : text;
}

export function entraAppsToFindings(input: EntraAppsInput): {
  findings: Finding[];
  externalApps: ExternalApp[];
  checks: EntraAppsCheck[];
  externalCount: number;
} {
  const tenant = input.tenantId.toLowerCase();
  const isExternal = (sp: GraphServicePrincipal) =>
    sp.servicePrincipalType === 'Application' &&
    sp.appOwnerOrganizationId !== undefined &&
    sp.appOwnerOrganizationId !== tenant &&
    !input.perms.microsoftTenantIds.has(sp.appOwnerOrganizationId);
  const byId = new Map(input.servicePrincipals.map((sp) => [sp.id, sp]));
  const graphSp = input.servicePrincipals.find((sp) => sp.appId === input.perms.graphAppId);
  const roleName = new Map((graphSp?.appRoles ?? []).map((r) => [r.id, r.value]));
  const powerful = (name: string | undefined) => name !== undefined && input.perms.powerful.has(name);

  const apps = new Map<string, ExternalApp>();
  const appOf = (sp: GraphServicePrincipal): ExternalApp => {
    let a = apps.get(sp.id);
    if (!a) {
      a = {
        name: sp.displayName,
        ...(sp.verifiedPublisher ? { verifiedPublisher: sp.verifiedPublisher } : {}),
        appPermissions: [],
        tenantWideScopes: [],
        userConsentCount: 0,
      };
      apps.set(sp.id, a);
    }
    return a;
  };
  const externals = input.servicePrincipals.filter(isExternal);
  for (const sp of externals) appOf(sp);

  for (const as of input.graphAssignments) {
    const sp = byId.get(as.principalId);
    const name = roleName.get(as.appRoleId);
    if (!sp || !isExternal(sp) || !powerful(name)) continue;
    const a = appOf(sp);
    if (!a.appPermissions.includes(name!)) a.appPermissions.push(name!);
  }
  for (const g of input.grants) {
    const sp = byId.get(g.clientId);
    if (!sp || !isExternal(sp)) continue;
    // 委任の権限は Microsoft Graph への同意だけを判定する（他の API のスコープ名は意味が違う）
    if (graphSp && g.resourceId !== undefined && g.resourceId !== graphSp.id) continue;
    const strong = g.scopes.filter((s) => powerful(s));
    if (strong.length === 0) continue;
    const a = appOf(sp);
    if (g.consentType === 'AllPrincipals') {
      for (const s of strong) if (!a.tenantWideScopes.includes(s)) a.tenantWideScopes.push(s);
    } else if (g.consentType === 'Principal') {
      a.userConsentCount += 1;
    }
  }

  const diagram = new Map(input.diagramApps.map((d) => [norm(d.name), d.label]));
  const externalApps = [...apps.values()]
    .map((a) => {
      const node = diagram.get(norm(a.name));
      return node ? { ...a, diagramNode: node } : a;
    })
    .sort((x, y) => x.name.localeCompare(y.name));

  const msWithCreds = input.servicePrincipals.filter(
    (sp) => sp.appOwnerOrganizationId !== undefined && input.perms.microsoftTenantIds.has(sp.appOwnerOrganizationId) && sp.credentialCount > 0,
  );

  const groups: [Check, ExternalApp[] | GraphServicePrincipal[]][] = [
    [CHECKS.appPerms, externalApps.filter((a) => a.appPermissions.length > 0)],
    [CHECKS.tenantWide, externalApps.filter((a) => a.tenantWideScopes.length > 0)],
    [CHECKS.userConsent, externalApps.filter((a) => a.userConsentCount > 0)],
    [CHECKS.msCredentials, msWithCreds],
  ];
  const findings: Finding[] = [];
  const checks: EntraAppsCheck[] = [];
  for (const [c, hits] of groups) {
    checks.push({ id: c.id, title: c.title, count: hits.length });
    if (hits.length === 0) continue;
    const names = [...new Set(hits.map((h) => ('name' in h ? h.name : h.displayName)))].sort();
    const unverified = hits.filter((h) => 'appPermissions' in h && !h.verifiedPublisher).length;
    findings.push({
      id: `${ENTRA_APPS_PRODUCT}:${input.scope}:${c.id}`,
      source: { format: 'msgraph', product: ENTRA_APPS_PRODUCT, scope: input.scope, importedAt: input.importedAt },
      externalId: c.id,
      identifiers: [{ scheme: 'msgraph-check', value: c.id }],
      title: `${c.title}：${hits.length} 件`.slice(0, TEXT_MAX),
      severity: c.severity,
      canonicalIds: [...c.canonicalIds],
      ...(input.subject ? { subject: input.subject } : {}),
      resource: { label: label(names, unverified), type: 'Entra ID' },
      observedAt: input.importedAt,
    });
  }
  return { findings, externalApps, checks, externalCount: externals.length };
}
