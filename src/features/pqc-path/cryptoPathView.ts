import type { CryptoFlow, DiagramNode } from '../../core/model/types';
import type { TerminationBehavior } from '../../crypto-behavior/schema';
import type { CryptoRoute, EffectiveTermination } from './types';

/** 同じ送信元・送信先の組が登録済みのフロー（無ければ undefined）。 */
export function findCryptoFlow(
  flows: readonly CryptoFlow[] | undefined,
  sourceId: string,
  targetId: string,
): CryptoFlow | undefined {
  return (flows ?? []).find((f) => f.sourceId === sourceId && f.targetId === targetId);
}

/** 経路図の 1 ノード分の役割。 */
export type RouteNodeRole = 'endpoint' | 'cut' | 'via';

/** 経路上の各ノードが、端点・区間の切れ目・経由のどれか。 */
export function routeNodeRoles(route: CryptoRoute): RouteNodeRole[] {
  const cuts = new Set(route.segments.slice(1).map((s) => s.fromNodeId));
  const last = route.nodeIds.length - 1;
  return route.nodeIds.map((id, i) =>
    i === 0 || i === last ? 'endpoint' : cuts.has(id) ? 'cut' : 'via',
  );
}

/** 各区間が経路のノード列で占める位置（from / to のインデックス）。 */
export function segmentSpans(route: CryptoRoute): { from: number; to: number }[] {
  return route.segments.map((s) => ({
    from: route.nodeIds.indexOf(s.fromNodeId),
    to: route.nodeIds.indexOf(s.toNodeId),
  }));
}

/** ノードの終端判定（個別設定 → 型の既定 → 不明）。analyzeCryptoPath と同じ優先順位。 */
export function nodeTermination(
  node: DiagramNode | undefined,
  behaviors: readonly TerminationBehavior[],
  isEndpoint: boolean,
): EffectiveTermination {
  if (isEndpoint) return { value: 'endpoint', confidence: 'endpoint' };
  if (node?.crypto?.termination) return { value: node.crypto.termination, confidence: 'confirmed' };
  const b = node ? behaviors.find((x) => x.componentType === node.type) : undefined;
  return b ? { value: b.default, confidence: 'default' } : { value: 'unknown', confidence: 'unknown' };
}
