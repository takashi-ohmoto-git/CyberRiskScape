import { describe, expect, it } from 'vitest';
import { buildAuthProviderClosure, dependentsOf } from './authProviderClosure';
import type { DiagramEdge, DiagramNode } from '../model/types';

const idp: DiagramNode = { id: 'idp', type: 'IDENTITY_PROVIDER', x: 0, y: 0, label: 'Entra ID' };
const ad: DiagramNode = { id: 'ad', type: 'DIRECTORY', x: 0, y: 200, label: '社内 AD' };
const user: DiagramNode = { id: 'user', type: 'USER', x: 200, y: 0 };
const appA: DiagramNode = { id: 'appA', type: 'PROCESS', x: 400, y: 0, label: '業務アプリ A' };
const appB: DiagramNode = { id: 'appB', type: 'PROCESS', x: 400, y: 200, label: '業務アプリ B' };

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

describe('buildAuthProviderClosure', () => {
  it('発行元ごとに依存コンポーネント（target 側）を集める', () => {
    const c = buildAuthProviderClosure(
      [idp, user, appA, appB],
      [edge('e1', 'user', 'appA', 'idp'), edge('e2', 'user', 'appB', 'idp')],
    );
    expect(dependentsOf(c, 'idp').map((n) => n.id)).toEqual(['appA', 'appB']);
  });

  it('同じコンポーネントへの複数エッジは重複排除する', () => {
    const c = buildAuthProviderClosure(
      [idp, user, appA],
      [edge('e1', 'user', 'appA', 'idp'), edge('e2', 'idp', 'appA', 'idp')],
    );
    expect(dependentsOf(c, 'idp').map((n) => n.id)).toEqual(['appA']);
  });

  it('発行元が複数あれば別々に集計する', () => {
    const c = buildAuthProviderClosure(
      [idp, ad, user, appA, appB],
      [edge('e1', 'user', 'appA', 'idp'), edge('e2', 'user', 'appB', 'ad')],
    );
    expect(dependentsOf(c, 'idp').map((n) => n.id)).toEqual(['appA']);
    expect(dependentsOf(c, 'ad').map((n) => n.id)).toEqual(['appB']);
  });

  it('authProviderId を持たないエッジは数えない', () => {
    const c = buildAuthProviderClosure([idp, user, appA], [edge('e1', 'user', 'appA')]);
    expect(dependentsOf(c, 'idp')).toEqual([]);
  });

  it('発行元自身が target のエッジ（自己参照）は数えない', () => {
    const c = buildAuthProviderClosure([idp, user], [edge('e1', 'user', 'idp', 'idp')]);
    expect(dependentsOf(c, 'idp')).toEqual([]);
  });

  it('参照先が削除済み（dangling）の authProviderId は数えない', () => {
    const c = buildAuthProviderClosure([user, appA], [edge('e1', 'user', 'appA', 'gone')]);
    expect(dependentsOf(c, 'gone')).toEqual([]);
  });

  it('登録の無い発行元は空配列を返す', () => {
    const c = buildAuthProviderClosure([idp], []);
    expect(dependentsOf(c, 'idp')).toEqual([]);
  });
});
