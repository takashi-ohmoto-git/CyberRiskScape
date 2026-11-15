import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { entraAppsReportToMarkdown, importEntraApps } from './importEntraApps';

const FIXTURE_PATH = new URL('./__fixtures__/sample-project.json', import.meta.url);
const TENANT = '11111111-1111-4111-8111-111111111111';
const PARTNER = '22222222-2222-4222-8222-222222222222';
const GRAPH_APP = '00000003-0000-0000-c000-000000000000';
const ROLE_FILES = 'bbbbbbbb-0000-4000-8000-000000000001';

/** 架空のテナント。IdP（C1）と、外部アプリの 1 つを描いた SaaS（C2）。 */
function project(extra: object[] = []) {
  const base = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as Record<string, unknown>;
  return {
    ...base,
    layers: {
      ...(base.layers as object),
      L1: {
        nodes: [
          { id: 'entra', seq: 1, type: 'IDENTITY_PROVIDER', x: 0, y: 0, label: 'Entra ID' },
          { id: 'crm', seq: 2, type: 'SAAS', x: 200, y: 0, label: 'Partner CRM' },
          ...extra,
        ],
        edges: [],
        boundaries: [],
        annotations: [],
      },
    },
    idCounters: { ...(base.idCounters as object), L1: { node: 3, edge: 0, boundary: 0 } },
  };
}

const raw = {
  servicePrincipals: {
    value: [
      { id: 'a', appId: 'x1', displayName: 'Partner CRM', appOwnerOrganizationId: PARTNER, servicePrincipalType: 'Application' },
      { id: 'b', appId: 'x2', displayName: 'Shadow Exporter', appOwnerOrganizationId: PARTNER, servicePrincipalType: 'Application' },
    ],
  },
  graphServicePrincipal: { id: 'g', appId: GRAPH_APP, displayName: 'Microsoft Graph', appRoles: [{ id: ROLE_FILES, value: 'Files.Read.All' }] },
  graphAppRoleAssignedTo: { value: [{ principalId: 'b', principalType: 'ServicePrincipal', appRoleId: ROLE_FILES }] },
  oauth2PermissionGrants: { value: [{ clientId: 'a', consentType: 'AllPrincipals', resourceId: 'g', scope: 'Sites.ReadWrite.All' }] },
};

describe('importEntraApps', () => {
  it('指摘を図の IdP に載せ、外部アプリを図の SaaS と突き合わせる（図に無いものに印）', () => {
    const out = importEntraApps(project(), raw, { tenantId: TENANT, scope: 'contoso', importedAt: '2026-11-15T00:00:00Z' });
    expect(out.idp).toEqual({ kind: 'found', node: 'C1 Entra ID' });
    expect(out.externalCount).toBe(2);
    expect(out.stored).toBe(2);
    expect(out.project.findings?.every((f) => f.subject?.nodeId === 'entra')).toBe(true);
    expect(out.externalApps.find((a) => a.name === 'Partner CRM')?.diagramNode).toBe('C2 Partner CRM');
    const md = entraAppsReportToMarkdown(out);
    expect(md).toContain('Shadow Exporter');
    expect(md).toContain('**図に無い**');
    expect(out.graphRolesMissing).toBe(false);
  });

  it('Graph のサービスプリンシパルが無ければアプリ単独の権限は判定できないと報告する', () => {
    const { graphServicePrincipal: _g, ...noGraph } = raw;
    const out = importEntraApps(project(), noGraph, { tenantId: TENANT });
    expect(out.graphRolesMissing).toBe(true);
    expect(out.checks.find((c) => c.id === 'external-app-powerful-app-permissions')?.count).toBe(0);
    expect(entraAppsReportToMarkdown(out)).toContain('判定していない');
  });

  it('IdP が複数なら --idp-node が要り、無ければ未結合', () => {
    const many = project([{ id: 'okta', seq: 3, type: 'IDENTITY_PROVIDER', x: 0, y: 200, label: 'Okta' }]);
    expect(importEntraApps(many, raw, { tenantId: TENANT }).idp.kind).toBe('many');
    expect(importEntraApps(many, raw, { tenantId: TENANT, idpNode: 'C1' }).idp.kind).toBe('found');
    expect(importEntraApps(many, raw, { tenantId: TENANT, idpNode: 'C2' }).idp.kind).toBe('wrongType');
  });

  it('servicePrincipals の形が違えばエラー', () => {
    expect(() => importEntraApps(project(), { servicePrincipals: { nope: 1 } }, { tenantId: TENANT })).toThrow();
  });
});
