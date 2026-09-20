import type { DiagramEdge, DiagramNode } from '../model/types';

/**
 * IdP インベントリと影響範囲の閉包（[[plan]] §2.40）。
 *
 * `edge.authProviderId`（[[plan]] §2.39 B-1）を辺とする依存グラフを張り、
 * 「この発行元が落ちたら何が落ちるか」をノードごとの集合として導出する。
 *
 * 設計：
 * - **新しいデータは持たない。** インベントリは既存の `authProviderId` 参照からの派生ビューで、
 *   図と独立したレジストリ（[[plan]] §2.39 B-1 の案 B-2）のような二重管理・ドリフトが起きない。
 * - **依存先は target 側**を採る。エッジ `source → target` の認証が発行元 X に依っているとき、
 *   X の侵害で「なりすまされる／到達不能になる」のは資源側＝target であるため。
 * - **ノード側の宣言（`node.authProviderId`）も同じ Tier 1 に合流させる**（[[plan]] §2.42）。
 *   あちらは「このコンポーネント自身の認証の預け先」（ドメイン参加・SSO 連携）で、
 *   エッジ宣言（経路ごとの資格情報）とは別の事実だが、「落ちると認証が壊れる」点は同じ。
 *   由来を保存しないのは、表示時に `node.authProviderId === providerId` で判定できるため。
 * - スコープはアクティブ層（`detectThreats` が層単位の nodes / edges しか受け取らないため）。
 *
 * 閉包が求めるのは [[plan]] §2.40 の **Tier 1（宣言された依存）** と、論理接続の判定に使う
 * 「発行元として参照されているか」だけ。エンジンは Tier 2 を使わないため、閉包には含めない。
 * Tier 2（発行元ノードに実エッジで接続する相手）はビュー側（インベントリ・キャンバスの
 * ハイライト）の関心で、**閉包から導けない**ため独立した純関数 `directPeersOf` が持つ。
 */
export interface AuthProviderClosure {
  /** 発行元ノード id → 依存するコンポーネント（重複排除済み・エッジ出現順）。 */
  dependents: Map<string, DiagramNode[]>;
  /**
   * 1 本以上のエッジから発行元として参照されているノード id（[[plan]] §2.40）。
   *
   * `dependents` と別に持つのは、依存先が自己参照や削除済みで解決できない場合でも
   * 「発行元として使われている」事実は成立するため。**論理接続**の判定に使う。
   */
  referenced: Set<string>;
}

export function buildAuthProviderClosure(
  nodes: readonly DiagramNode[],
  edges: readonly DiagramEdge[],
): AuthProviderClosure {
  const nodeById = new Map(nodes.map((n) => [n.id, n] as const));
  const dependents = new Map<string, DiagramNode[]>();
  const referenced = new Set<string>();
  const seen = new Map<string, Set<string>>();

  /** 発行元 → 依存先を重複排除しつつ積む。 */
  const addDependent = (providerId: string, dependent: DiagramNode): void => {
    let list = dependents.get(providerId);
    let ids = seen.get(providerId);
    if (!list || !ids) {
      list = [];
      ids = new Set<string>();
      dependents.set(providerId, list);
      seen.set(providerId, ids);
    }
    if (ids.has(dependent.id)) return;
    ids.add(dependent.id);
    list.push(dependent);
  };

  // ノード自身の認証の預け先（[[plan]] §2.42）。エッジより先に走査して、
  // 「この機器は発行元 X に身元を預けている」を Tier 1 の先頭に置く。
  for (const node of nodes) {
    const providerId = node.authProviderId;
    if (!providerId) continue;
    // 参照先が削除済み（dangling）／自己参照は数えない。
    if (!nodeById.has(providerId)) continue;
    referenced.add(providerId);
    if (node.id === providerId) continue;
    addDependent(providerId, node);
  }

  for (const edge of edges) {
    const providerId = edge.authProviderId;
    if (!providerId) continue;
    // 参照先が削除済み（dangling）なら数えない。store 側で解除されるが、
    // 外部ファイル読込直後など解除前の状態も通り得るため防御的に見る。
    if (!nodeById.has(providerId)) continue;
    // 依存先が解決できなくても「発行元として参照されている」事実は立つ。
    referenced.add(providerId);
    const target = nodeById.get(edge.target);
    if (!target) continue;
    // 発行元自身への依存は数えない（自己参照）。
    if (target.id === providerId) continue;

    addDependent(providerId, target);
  }

  return { dependents, referenced };
}

/** 発行元 X に依存するコンポーネント。未登録なら空配列。 */
export function dependentsOf(closure: AuthProviderClosure, nodeId: string): DiagramNode[] {
  return closure.dependents.get(nodeId) ?? [];
}

/**
 * ノードが発行元として参照されている（＝**論理的に接続されている**）か。
 *
 * 全コンポーネントを IdP へ線で繋ぐのは実務上非現実的なので、`authProviderId` による参照を
 * 接続の一形態として扱う（[[plan]] §2.40、ユーザー判断 2026-09-20）。
 */
export function isReferencedProvider(closure: AuthProviderClosure, nodeId: string): boolean {
  return closure.referenced.has(nodeId);
}

/**
 * ノードが図の中で発行元として占める位置づけ（[[plan]] §2.41 案 A）。
 *
 * - `Sole`: 発行元として参照されており、かつ**参照されている発行元がこの 1 つだけ**
 * - `Shared`: 発行元として参照されているが、他にも参照されている発行元がある
 * - `Unused`: 一度も発行元として参照されていない
 *
 * しきい値は無く、参照の有無と発行元の個数だけで決まる。
 */
export type AuthProviderRole = 'Sole' | 'Shared' | 'Unused';

/**
 * 発行元としての位置づけを導出する（[[plan]] §2.41）。
 *
 * **ノード型で絞らない。** 発行元になり得ない型（DB 等）も誰からも参照されていないので
 * `Unused` になる。これは事実として正しく、エンジンに脅威知識を持ち込まないための選択。
 * 「IdP のうち単独依存のもの」を指したいルールは `nodeType` と併用すること。
 */
export function authProviderRoleOf(
  closure: AuthProviderClosure,
  nodeId: string,
): AuthProviderRole {
  if (!closure.referenced.has(nodeId)) return 'Unused';
  return closure.referenced.size === 1 ? 'Sole' : 'Shared';
}

/**
 * Tier 2：発行元ノードに**実エッジで直接接続する相手**（[[plan]] §2.40）。
 *
 * **閉包（`AuthProviderClosure`）からは導けない。** 閉包は `authProviderId` で参照されている
 * 発行元しか走査しないため、一度も参照されていない Directory の Tier 2 が 0 件になる
 * （[[plan]] §2.40 に記録した実バグ）。そのため `nodes` / `edges` を直接走査する。
 *
 * `excludeIds` には Tier 1 を渡す（Tier 1 と重複させない）。発行元自身は常に除く。
 */
export function directPeersOf(
  nodes: readonly DiagramNode[],
  edges: readonly DiagramEdge[],
  providerId: string,
  excludeIds: ReadonlySet<string>,
): DiagramNode[] {
  const nodeById = new Map(nodes.map((n) => [n.id, n] as const));
  const peers: DiagramNode[] = [];
  const seen = new Set<string>();

  for (const edge of edges) {
    const isSource = edge.source === providerId;
    const isTarget = edge.target === providerId;
    if (!isSource && !isTarget) continue;
    const peerId = isSource ? edge.target : edge.source;
    if (peerId === providerId || excludeIds.has(peerId) || seen.has(peerId)) continue;
    const peer = nodeById.get(peerId);
    if (!peer) continue;
    seen.add(peerId);
    peers.push(peer);
  }

  return peers;
}
