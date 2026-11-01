import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import type { DiagramBoundary, DiagramEdge, DiagramNode, ThreatView } from '../../core/model/types';
import { isSuppressed } from '../../core/model/types';
import { resolveNodeBoundaries } from '../../core/canvas/boundaryCrossing';

/**
 * 手がかりの連鎖（docs/attack-tree-analysis.md §10）。
 *
 * 1 つずつは軽微な情報の漏れ（公開ディレクトリのファイル・画面の文章のヒント・エラー応答等）でも、
 * 攻撃者は拾った値を次のノードの鍵として使う。図の線ではつながらない「情報の受け渡し」なので、
 * 手がかりが開くノードは図から分からない。そこで「同じゾーン（最も内側の Internet 以外の信頼境界）の
 * ノードを弱める」と近似し、経路の根拠として表示する。経路のコストと順位は変えない。
 *
 * どの脅威が手がかりを渡すかは知識なので `data/attack-chain/footholds.yaml` に置く。
 */

const FootholdKindSchema = z.enum(['credential', 'path', 'hint']);
export type FootholdKind = z.infer<typeof FootholdKindSchema>;

const FootholdMapSchema = z.object({
  schemaVersion: z.literal(1),
  footholds: z.array(
    z.object({
      canonicalId: z.string().min(1),
      yields: z.array(FootholdKindSchema).nonempty(),
      note: z.string().optional(),
    }),
  ),
});

/** canonicalId → 渡すものの種類。 */
export type FootholdMap = ReadonlyMap<string, readonly FootholdKind[]>;

export function loadFootholdMap(text: string): FootholdMap {
  const map = new Map<string, readonly FootholdKind[]>();
  for (const f of FootholdMapSchema.parse(parseYaml(text)).footholds) {
    if (map.has(f.canonicalId)) throw new Error(`[footholds] ${f.canonicalId} が複数回載っています`);
    map.set(f.canonicalId, f.yields);
  }
  return map;
}

const sources = import.meta.glob<string>('../../../data/attack-chain/footholds.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const BUNDLED_FOOTHOLD_MAP: FootholdMap = loadFootholdMap(
  Object.values(sources)[0] ?? 'schemaVersion: 1\nfootholds: []\n',
);

/** 1 件の手がかり：source で出ている脅威が、同じゾーンの経路上のノード（affected）を弱める。 */
export interface FootholdLink {
  threatId: string;
  threatName: string;
  sourceNodeId: string;
  yields: readonly FootholdKind[];
  /** 経路上のノードのうち、source と同じゾーンにあるもの（source 自身を含む。攻撃者は除く）。 */
  affectedNodeIds: string[];
}

export interface FindFootholdChainsInput {
  nodes: readonly DiagramNode[];
  edges: readonly DiagramEdge[];
  boundaries: readonly DiagramBoundary[];
  threats: readonly ThreatView[];
  attackerId: string;
  /** いずれかの経路に現れるノード（AttackGraphResult.nodeIds）。 */
  routeNodeIds: readonly string[];
  footholds?: FootholdMap;
}

/** 攻撃者から線をたどって（向きを問わず）届くノード。 */
function reachableFrom(attackerId: string, edges: readonly DiagramEdge[]): Set<string> {
  const adj = new Map<string, string[]>();
  for (const e of edges) {
    adj.set(e.source, [...(adj.get(e.source) ?? []), e.target]);
    adj.set(e.target, [...(adj.get(e.target) ?? []), e.source]);
  }
  const seen = new Set([attackerId]);
  const queue = [attackerId];
  while (queue.length > 0) {
    for (const next of adj.get(queue.shift() as string) ?? []) {
      if (!seen.has(next)) {
        seen.add(next);
        queue.push(next);
      }
    }
  }
  return seen;
}

/**
 * 攻撃者から届くノードで出ている「手がかりを渡す脅威」と、それが弱める経路上のノードを返す。
 * 受容・誤検知にした脅威は数えない。弱める経路上のノードが無いものは返さない。
 */
export function findFootholdChains(input: FindFootholdChainsInput): FootholdLink[] {
  const footholds = input.footholds ?? BUNDLED_FOOTHOLD_MAP;
  const reachable = reachableFrom(input.attackerId, input.edges);
  const owning = resolveNodeBoundaries(input.nodes, input.boundaries);
  /** 最も内側の、Internet 以外の信頼境界（無ければ undefined＝ゾーンなし）。 */
  const zoneOf = (nodeId: string) => owning.get(nodeId)?.find((b) => b.trustLevel !== 'Internet')?.id;
  const routeNodes = input.routeNodeIds.filter((id) => id !== input.attackerId);
  // 内包された子ノード（例：バックアップの中の認証材料）は線を持たないため、親が届けば届くとみなす。
  const parentOf = new Map(input.nodes.map((n) => [n.id, n.parentId] as const));
  const isReachable = (nodeId: string): boolean => {
    for (let id: string | undefined = nodeId, depth = 0; id && depth < 16; id = parentOf.get(id), depth++) {
      if (reachable.has(id)) return true;
    }
    return false;
  };

  const links: FootholdLink[] = [];
  for (const t of input.threats) {
    const yields = t.canonicalId ? footholds.get(t.canonicalId) : undefined;
    if (!yields || isSuppressed(t)) continue;
    const sourceNodeId = t.subject?.kind === 'node' ? t.subject.id : t.subject ? undefined : t.nodeId;
    if (!sourceNodeId || sourceNodeId === input.attackerId || !isReachable(sourceNodeId)) continue;
    const zone = zoneOf(sourceNodeId);
    const affectedNodeIds = routeNodes.filter(
      (id) => id === sourceNodeId || (zone !== undefined && zoneOf(id) === zone),
    );
    if (affectedNodeIds.length === 0) continue;
    links.push({ threatId: t.id, threatName: t.name ?? t.category, sourceNodeId, yields, affectedNodeIds });
  }
  return links;
}
