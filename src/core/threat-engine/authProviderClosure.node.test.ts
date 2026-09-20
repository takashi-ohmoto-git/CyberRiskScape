import { describe, expect, it } from 'vitest';
import {
  authProviderRoleOf,
  buildAuthProviderClosure,
  dependentsOf,
  directPeersOf,
} from './authProviderClosure';
import type { DiagramEdge, DiagramNode } from '../model/types';

/**
 * ノード側 `authProviderId`（[[plan]] §2.42）の閉包への合流。
 *
 * 「このコンポーネント自身の認証の預け先」はエッジ宣言（経路ごとの資格情報）と別の事実だが、
 * 「落ちると認証が壊れる」点は同じなので **Tier 1 に合流**させる。
 */

const ad: DiagramNode = { id: 'ad', type: 'DIRECTORY', x: 0, y: 0, label: '社内 AD' };
const entra: DiagramNode = { id: 'entra', type: 'IDENTITY_PROVIDER', x: 300, y: 0 };
const user: DiagramNode = { id: 'user', type: 'USER', x: 0, y: 200 };
const app: DiagramNode = { id: 'app', type: 'PROCESS', x: 200, y: 200 };

/** ドメイン参加サーバ（エッジを 1 本も持たない）。 */
const srv = (authProviderId?: string): DiagramNode => ({
  id: 'srv',
  type: 'FRONT_END_SERVER',
  x: 400,
  y: 200,
  ...(authProviderId ? { authProviderId } : {}),
});

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

describe('ノード宣言の Tier 1 合流（[[plan]] §2.42）', () => {
  it('エッジが 1 本も無くてもノード宣言だけで依存先に数える', () => {
    const c = buildAuthProviderClosure([ad, srv('ad')], []);
    expect(dependentsOf(c, 'ad').map((n) => n.id)).toEqual(['srv']);
  });

  it('エッジ宣言とノード宣言が混在すると両方が Tier 1 に入る（ノード宣言が先）', () => {
    const c = buildAuthProviderClosure(
      [ad, user, app, srv('ad')],
      [edge('e1', 'user', 'app', 'ad')],
    );
    expect(dependentsOf(c, 'ad').map((n) => n.id)).toEqual(['srv', 'app']);
  });

  it('同じコンポーネントが両方の経路で依存していても重複しない', () => {
    const c = buildAuthProviderClosure([ad, user, srv('ad')], [edge('e1', 'user', 'srv', 'ad')]);
    expect(dependentsOf(c, 'ad').map((n) => n.id)).toEqual(['srv']);
  });

  it('自己参照は数えないが、発行元として参照されている事実は立つ', () => {
    const selfRef: DiagramNode = { ...ad, authProviderId: 'ad' };
    const c = buildAuthProviderClosure([selfRef], []);
    expect(dependentsOf(c, 'ad')).toEqual([]);
    expect(authProviderRoleOf(c, 'ad')).toBe('Sole');
  });

  it('参照先が削除済み（dangling）のノード宣言は数えない', () => {
    const c = buildAuthProviderClosure([srv('gone')], []);
    expect(dependentsOf(c, 'gone')).toEqual([]);
    expect(authProviderRoleOf(c, 'gone')).toBe('Unused');
  });

  it('USER もノード宣言できる（利用者アカウントの発行元）', () => {
    const federated: DiagramNode = { ...user, authProviderId: 'entra' };
    const c = buildAuthProviderClosure([entra, federated], []);
    expect(dependentsOf(c, 'entra').map((n) => n.id)).toEqual(['user']);
  });

  it('ノード宣言だけの発行元も authProviderRole に反映される', () => {
    const sole = buildAuthProviderClosure([ad, srv('ad')], []);
    expect(authProviderRoleOf(sole, 'ad')).toBe('Sole');

    // ノード宣言が 2 つ目の発行元を参照すると Shared になる。
    const federatedUser: DiagramNode = { ...user, authProviderId: 'entra' };
    const shared = buildAuthProviderClosure([ad, entra, srv('ad'), federatedUser], []);
    expect(authProviderRoleOf(shared, 'ad')).toBe('Shared');
    expect(authProviderRoleOf(shared, 'entra')).toBe('Shared');
  });

  it('Tier 2（directPeersOf）はノード宣言では増えない', () => {
    // ノード宣言は実エッジではないので、直接接続の相手には数えない。
    const peers = directPeersOf([ad, srv('ad')], [], 'ad', new Set(['srv']));
    expect(peers).toEqual([]);
  });
});
