import type { LayerData, LayerKey } from '../../core/model/types';
import { resolveDrawableAncestor } from '../../core/model/parentChain';
import { getNodeCenter } from '../../core/canvas/nodeGeometry';
import type { TriggerHit } from '../../change-triggers/detectTriggers';

/**
 * 前回のモデルからの変更（実行トリガーの検出結果）を、再診断（再テスト）の範囲に変換する純粋関数。
 *
 * 範囲 = 発火したトリガーの対象要素（ノード）／エッジの両端ノード／境界の内側のノード
 *        ＋ 新しいモデルで追加されたノード。
 */

export interface RetestScope {
  /** 対象レイヤー。 */
  layer: LayerKey;
  /** 発火したトリガー（対象レイヤーの根拠だけ残す）。 */
  hits: TriggerHit[];
  /** 範囲に入るノード・エッジ・境界の内部 id。 */
  nodeIds: Set<string>;
  edgeIds: Set<string>;
  boundaryIds: Set<string>;
}

export function computeRetestScope(
  layer: LayerKey,
  base: LayerData,
  head: LayerData,
  allHits: readonly TriggerHit[],
): RetestScope {
  const nodeIds = new Set<string>();
  const edgeIds = new Set<string>();
  const boundaryIds = new Set<string>();
  const edgeById = new Map(head.edges.map((e) => [e.id, e]));
  const hits: TriggerHit[] = [];

  for (const hit of allHits) {
    const evidence = hit.evidence.filter((ev) => ev.layer === layer);
    if (evidence.length === 0) continue;
    hits.push({ ...hit, evidence });
    for (const ev of evidence) {
      const { kind, id } = ev.element;
      if (kind === 'node') nodeIds.add(id);
      else if (kind === 'edge') {
        edgeIds.add(id);
        const e = edgeById.get(id);
        if (e) {
          nodeIds.add(e.source);
          nodeIds.add(e.target);
        }
      } else {
        boundaryIds.add(id);
        const b = head.boundaries.find((x) => x.id === id);
        if (!b) continue;
        for (const n of head.nodes) {
          const c = getNodeCenter(resolveDrawableAncestor(n, head.nodes));
          if (c.x >= b.x && c.x <= b.x + b.width && c.y >= b.y && c.y <= b.y + b.height) nodeIds.add(n.id);
        }
      }
    }
  }

  // 追加されたノードは、トリガーが無くても新規なので再診断の対象にする。
  const baseNodeIds = new Set(base.nodes.map((n) => n.id));
  for (const n of head.nodes) if (!baseNodeIds.has(n.id)) nodeIds.add(n.id);

  return { layer, hits, nodeIds, edgeIds, boundaryIds };
}
