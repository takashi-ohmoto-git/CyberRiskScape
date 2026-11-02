/**
 * 検知の空白：経路上で、ログが監視先（SIEM 等）に届かないノードの連続区間を求める純粋関数。
 * 経路のコスト・順位には影響しない表示専用の根拠。仕様は docs/attack-tree-analysis.md §11。
 */
import {
  ATTACK_SURFACE_APPLICABLE,
  ATTACK_SURFACE_KEYS_BY_TYPE,
  LOG_SINK_APPLICABLE,
  type DiagramNode,
} from '../../core/model/types';

export type DetectionState = 'forwarded' | 'localOnly' | 'none';

export interface RouteNodeDetection {
  nodeId: string;
  state: DetectionState;
  /** 何も入力されていないため、ログなしと仮定した */
  assumed: boolean;
}

export interface RouteDetection {
  /** 評価対象のノード（経路順） */
  nodes: RouteNodeDetection[];
  /** forwarded でないノード id の連続区間（経路順） */
  gaps: string[][];
  /** nodes が 1 件以上で forwarded が 0 件 */
  blind: boolean;
}

/** hasAccessLog をその型で入力できるか。 */
function canInputAccessLog(type: string): boolean {
  if (!ATTACK_SURFACE_APPLICABLE.has(type)) return false;
  const keys = ATTACK_SURFACE_KEYS_BY_TYPE[type];
  return keys === undefined || keys.includes('hasAccessLog');
}

export function assessRouteDetection(input: {
  routeNodeIds: readonly string[];
  nodes: readonly DiagramNode[];
  attackerId: string;
  /** ログの属性を入力できる型か（評価対象にするか） */
  isLogInputAvailable: (node: DiagramNode) => boolean;
}): RouteDetection {
  const byId = new Map(input.nodes.map((n) => [n.id, n] as const));
  const nodes: RouteNodeDetection[] = [];
  const gaps: string[][] = [];
  let current: string[] = [];

  for (const id of input.routeNodeIds) {
    const node = byId.get(id);
    if (!node || id === input.attackerId) continue;
    const isShadow = node.type === 'SHADOW' || node.type === 'SHADOW_APP';
    if (!isShadow && !input.isLogInputAvailable(node)) continue;

    const result = classify(node, byId, isShadow);
    nodes.push({ nodeId: id, ...result });
    if (result.state === 'forwarded') {
      if (current.length > 0) gaps.push(current);
      current = [];
    } else {
      current.push(id);
    }
  }
  if (current.length > 0) gaps.push(current);

  return { nodes, gaps, blind: nodes.length > 0 && nodes.every((n) => n.state !== 'forwarded') };
}

function classify(
  node: DiagramNode,
  byId: ReadonlyMap<string, DiagramNode>,
  isShadow: boolean,
): { state: DetectionState; assumed: boolean } {
  if (LOG_SINK_APPLICABLE.has(node.type)) return { state: 'forwarded', assumed: false };
  if (node.logSinkId && node.logSinkId !== node.id && byId.has(node.logSinkId)) {
    return { state: 'forwarded', assumed: false };
  }
  const accessLog = canInputAccessLog(node.type) ? node.attackSurface?.hasAccessLog : undefined;
  const collection = node.posture?.logCollection;
  if (accessLog === true || collection === 'Collected') return { state: 'localOnly', assumed: false };
  if (isShadow) return { state: 'none', assumed: false };
  if (accessLog === false || collection === 'NotCollected') return { state: 'none', assumed: false };
  return { state: 'none', assumed: true };
}
