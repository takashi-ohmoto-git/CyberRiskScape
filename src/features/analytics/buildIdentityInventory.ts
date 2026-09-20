import type { DiagramEdge, DiagramNode, IdentityProviderKind } from '../../core/model/types';
import { AUTH_PROVIDER_APPLICABLE } from '../../core/model/types';
import {
  buildAuthProviderClosure,
  dependentsOf,
  directPeersOf,
} from '../../core/threat-engine/authProviderClosure';

/**
 * 認証基盤インベントリの構築（[[plan]] §2.40 ②）。
 *
 * **新しいデータは持たない。** インベントリは `edge.authProviderId` 参照からの派生ビューであり、
 * 図と独立したレジストリ（[[plan]] §2.39 B-1 の案 B-2）のような二重管理・ドリフトが起きない。
 *
 * 行に載せるのは「発行元になり得る型（`AUTH_PROVIDER_APPLICABLE`）のノード」全件。
 * 一度も参照されていない発行元も**あえて載せる**（未使用の IdP が図にあること自体が
 * レビューで気づきたい事実のため）。表示ラベルの解決は UI 層に委ねる。
 */
export interface IdentityInventoryRow {
  provider: DiagramNode;
  kind?: IdentityProviderKind;
  /** Tier 1：この発行元を `authProviderId` で宣言しているエッジの接続先。 */
  dependents: DiagramNode[];
  /** Tier 2：実エッジで直接接続する相手（Tier 1 と重複しない）。 */
  directPeers: DiagramNode[];
}

export function buildIdentityInventory(
  nodes: readonly DiagramNode[],
  edges: readonly DiagramEdge[],
): IdentityInventoryRow[] {
  const closure = buildAuthProviderClosure(nodes, edges);

  return nodes
    .filter((n) => AUTH_PROVIDER_APPLICABLE.has(n.type))
    .map((provider) => {
      const dependents = dependentsOf(closure, provider.id);
      const tier1 = new Set(dependents.map((n) => n.id));
      const directPeers = directPeersOf(nodes, edges, provider.id, tier1);
      return { provider, kind: provider.identityProviderKind, dependents, directPeers };
    });
}
