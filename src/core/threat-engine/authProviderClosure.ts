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
 * - スコープはアクティブ層（`detectThreats` が層単位の nodes / edges しか受け取らないため）。
 *
 * ここで求めるのは [[plan]] §2.40 の **Tier 1（宣言された依存）** のみ。
 * Tier 2（発行元ノードに直接接続するその他のエッジ）はインベントリビュー側の関心なので、
 * 必要になった時点で足す（先回りして計算しない）。
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

    let list = dependents.get(providerId);
    let ids = seen.get(providerId);
    if (!list || !ids) {
      list = [];
      ids = new Set<string>();
      dependents.set(providerId, list);
      seen.set(providerId, ids);
    }
    if (ids.has(target.id)) continue;
    ids.add(target.id);
    list.push(target);
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
