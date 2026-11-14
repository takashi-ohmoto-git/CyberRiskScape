import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bloodhoundReportToMarkdown, importBloodhound } from './importBloodhound';

const FIXTURE_PATH = new URL('./__fixtures__/sample-project.json', import.meta.url);

/** AD（C1）・認証局（C2）・端末（C3）の図。架空のデータ。 */
function project(extraNodes: object[] = []) {
  const base = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as Record<string, unknown>;
  const layers = base.layers as Record<string, Record<string, unknown>>;
  return {
    ...base,
    layers: {
      ...layers,
      L1: {
        nodes: [
          { id: 'ad', seq: 1, type: 'DIRECTORY', x: 0, y: 0, label: 'AD' },
          { id: 'ca', seq: 2, type: 'CERTIFICATE_AUTHORITY', x: 200, y: 0, label: 'CA' },
          { id: 'pc', seq: 3, type: 'PC', x: 400, y: 0, label: 'PC' },
          ...extraNodes,
        ],
        edges: [],
        boundaries: [],
        annotations: [],
      },
    },
    idCounters: { ...(base.idCounters as object), L1: { node: 4, edge: 0, boundary: 0 } },
  };
}

const response = (nodes: Record<string, object>) => ({ data: { nodes, edges: [] } });

const responses = new Map<string, unknown>([
  ['kerberoastable-users', response({ u1: { label: 'SVC_SQL@CORP.EXAMPLE', kind: 'User', isTierZero: false } })],
  ['adcs-esc-paths', response({ g1: { label: 'DOMAIN USERS@CORP.EXAMPLE', kind: 'Group', isTierZero: false } })],
  ['dcsync-non-tier-zero', response({})],
]);

describe('importBloodhound', () => {
  it('図にちょうど 1 つあるディレクトリ・認証局に載せ、AD CS は認証局へ', () => {
    const out = importBloodhound(project(), responses, { scope: 'corp', importedAt: '2026-11-15T00:00:00Z' });
    expect(out.directory.kind).toBe('found');
    expect(out.ca.kind).toBe('found');
    expect(out.stored).toBe(2);
    const findings = out.project.findings ?? [];
    expect(findings.find((f) => f.externalId === 'kerberoastable-users')?.subject).toEqual({ layer: 'L1', nodeId: 'ad' });
    expect(findings.find((f) => f.externalId === 'adcs-esc-paths')?.subject).toEqual({ layer: 'L1', nodeId: 'ca' });
    expect(JSON.stringify(out.project)).not.toContain('SVC_SQL');
    const md = bloodhoundReportToMarkdown(out);
    expect(md).toContain('C1 AD');
    expect(md).toContain('未評価');
  });

  it('ディレクトリが複数なら --node が要り、指定すればそこに載せる。型が違えば未結合', () => {
    const p = project([{ id: 'ad2', seq: 4, type: 'DIRECTORY', x: 0, y: 200, label: 'AD2' }]);
    expect(importBloodhound(p, responses).directory.kind).toBe('many');
    expect(importBloodhound(p, responses, { node: 'C4' }).directory).toMatchObject({ kind: 'found', node: { id: 'ad2' } });
    expect(importBloodhound(p, responses, { node: 'C3' }).directory.kind).toBe('wrongType');
  });

  it('取り込み直しは同じ scope の指摘を置き換え、別の scope は残す', () => {
    const first = importBloodhound(project(), responses, { scope: 'corp' });
    const again = importBloodhound(first.project, new Map([['dcsync-non-tier-zero', response({})]]), { scope: 'corp' });
    expect(again.diff.resolved).toBe(2);
    expect(again.project.findings).toBeUndefined();
    const other = importBloodhound(first.project, new Map([['dcsync-non-tier-zero', response({})]]), { scope: 'other' });
    expect(other.project.findings).toHaveLength(2);
  });

  it('Entra ID の指摘は図の IdP に載せる（--idp-node でも指定できる）', () => {
    const p = project([{ id: 'entra', seq: 4, type: 'IDENTITY_PROVIDER', x: 0, y: 200, label: 'Entra ID' }]);
    const entra = new Map<string, unknown>([
      ['entra-privilege-granting-apps', response({ sp: { label: 'GRAPH-ADMIN-APP', kind: 'AZServicePrincipal', isTierZero: true } })],
    ]);
    const out = importBloodhound(p, entra);
    expect(out.idp).toMatchObject({ kind: 'found', node: { id: 'entra' } });
    expect(out.project.findings?.[0].subject).toEqual({ layer: 'L1', nodeId: 'entra' });
    expect(importBloodhound(p, entra, { idpNode: 'C1' }).idp.kind).toBe('wrongType');
    expect(importBloodhound(project(), entra).idp.kind).toBe('none');
  });

  it('Azure の指摘は IaaS / PaaS とシークレット管理に載せ、ユーザーの名前は残さない', () => {
    const p = project([
      { id: 'azure', seq: 4, type: 'IAAS', x: 0, y: 200, label: 'Azure（本番サブスクリプション）' },
      { id: 'kv', seq: 5, type: 'SECRETS_VAULT', x: 200, y: 200, label: 'Key Vault' },
    ]);
    const azure = new Map<string, unknown>([
      [
        'azure-scope-controllers',
        response({
          mi: { label: 'BUILD-AGENT-IDENTITY', kind: 'AZManagedIdentity', isTierZero: false },
          u: { label: 'CAROL@CONTOSO.EXAMPLE', kind: 'AZUser', isTierZero: false },
        }),
      ],
      ['azure-key-vault-readers', response({ g: { label: 'APP-OPERATORS', kind: 'AZGroup', isTierZero: false } })],
    ]);
    const out = importBloodhound(p, azure);
    expect(out.cloud).toMatchObject({ kind: 'found', node: { id: 'azure' } });
    expect(out.vault).toMatchObject({ kind: 'found', node: { id: 'kv' } });
    const f = out.project.findings ?? [];
    expect(f.find((x) => x.externalId === 'azure-scope-controllers')).toMatchObject({
      subject: { layer: 'L1', nodeId: 'azure' },
      severity: 'Critical',
      canonicalIds: ['cloud-management-role-overgrant'],
      resource: { type: 'Azure' },
    });
    expect(f.find((x) => x.externalId === 'azure-key-vault-readers')?.subject).toEqual({ layer: 'L1', nodeId: 'kv' });
    expect(JSON.stringify(out.project)).toContain('BUILD-AGENT-IDENTITY');
    expect(JSON.stringify(out.project)).not.toContain('CAROL');
  });

  it('IaaS と PaaS の両方があれば --cloud-node が要り、型が違えば未結合', () => {
    const p = project([
      { id: 'iaas', seq: 4, type: 'IAAS', x: 0, y: 200, label: 'IaaS' },
      { id: 'paas', seq: 5, type: 'PAAS', x: 200, y: 200, label: 'PaaS' },
    ]);
    const azure = new Map<string, unknown>([['azure-code-executors', response({ g: { label: 'DEVS', kind: 'AZGroup', isTierZero: false } })]]);
    expect(importBloodhound(p, azure).cloud.kind).toBe('many');
    expect(importBloodhound(p, azure, { cloudNode: 'C5' }).cloud).toMatchObject({ kind: 'found', node: { id: 'paas' } });
    expect(importBloodhound(p, azure, { cloudNode: 'C1' }).cloud.kind).toBe('wrongType');
    expect(importBloodhound(project(), azure).project.findings?.[0].subject).toBeUndefined();
  });

  it('応答の形が違う問い合わせは invalid に並べる', () => {
    const out = importBloodhound(project(), new Map([['kerberoastable-users', { nope: 1 }]]));
    expect(out.invalid.map((i) => i.queryId)).toEqual(['kerberoastable-users']);
  });
});
