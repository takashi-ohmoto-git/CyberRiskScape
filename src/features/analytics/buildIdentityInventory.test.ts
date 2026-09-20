import { describe, expect, it } from 'vitest';
import { buildIdentityInventory } from './buildIdentityInventory';
import type { DiagramEdge, DiagramNode } from '../../core/model/types';

const idp: DiagramNode = {
  id: 'idp',
  type: 'IDENTITY_PROVIDER',
  x: 0,
  y: 0,
  label: 'Entra ID',
  identityProviderKind: 'IDaaS',
};
const ad: DiagramNode = { id: 'ad', type: 'DIRECTORY', x: 0, y: 100, label: '社内 AD' };
const user: DiagramNode = { id: 'u', type: 'USER', x: 100, y: 0 };
const appA: DiagramNode = { id: 'a', type: 'PROCESS', x: 200, y: 0, label: '業務アプリ A' };
const appB: DiagramNode = { id: 'b', type: 'PROCESS', x: 300, y: 0, label: '業務アプリ B' };

function edge(id: string, source: string, target: string, authProviderId?: string): DiagramEdge {
  return {
    id,
    source,
    target,
    auth: 'MFA',
    network: 'VPC',
    encryption: 'TLS',
    ...(authProviderId ? { authProviderId } : {}),
  };
}

describe('buildIdentityInventory', () => {
  it('発行元になり得る型だけを行にする', () => {
    const rows = buildIdentityInventory([idp, ad, user, appA], []);
    expect(rows.map((r) => r.provider.id)).toEqual(['idp', 'ad']);
  });

  it('Tier 1 は authProviderId で宣言されたエッジの接続先', () => {
    const rows = buildIdentityInventory(
      [idp, user, appA, appB],
      [edge('e1', 'u', 'a', 'idp'), edge('e2', 'u', 'b', 'idp')],
    );
    expect(rows[0].dependents.map((n) => n.id)).toEqual(['a', 'b']);
  });

  it('Tier 2 は実エッジの相手で、Tier 1 と重複しない', () => {
    const rows = buildIdentityInventory(
      [idp, user, appA],
      [edge('e1', 'u', 'a', 'idp'), edge('e2', 'u', 'idp')],
    );
    expect(rows[0].dependents.map((n) => n.id)).toEqual(['a']);
    expect(rows[0].directPeers.map((n) => n.id)).toEqual(['u']);
  });

  it('Tier 1 に居る相手は Tier 2 に重複表示しない', () => {
    const rows = buildIdentityInventory(
      [idp, user, appA],
      [edge('e1', 'u', 'a', 'idp'), edge('e2', 'a', 'idp')],
    );
    expect(rows[0].dependents.map((n) => n.id)).toEqual(['a']);
    expect(rows[0].directPeers).toEqual([]);
  });

  it('参照されていない発行元でも実エッジがあれば Tier 2 に出る（エンジン閉包に載らないケース）', () => {
    const rows = buildIdentityInventory([idp, ad], [edge('e1', 'ad', 'idp')]);
    const adRow = rows.find((r) => r.provider.id === 'ad');
    expect(adRow?.directPeers.map((n) => n.id)).toEqual(['idp']);
  });

  it('一度も参照されていない発行元も行に残す（未使用に気づけるように）', () => {
    const rows = buildIdentityInventory([idp], []);
    expect(rows).toHaveLength(1);
    expect(rows[0].dependents).toEqual([]);
    expect(rows[0].directPeers).toEqual([]);
  });

  it('IdP 種別を行に持つ（DIRECTORY は種別を持たないので undefined）', () => {
    const rows = buildIdentityInventory([idp, ad], []);
    expect(rows[0].kind).toBe('IDaaS');
    expect(rows[1].kind).toBeUndefined();
  });

  it('発行元が図に無ければ空配列', () => {
    expect(buildIdentityInventory([user, appA], [edge('e1', 'u', 'a')])).toEqual([]);
  });
});
