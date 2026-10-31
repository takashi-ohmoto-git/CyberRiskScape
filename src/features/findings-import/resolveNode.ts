import type { ComponentTypeId, LayerKey } from '../../core/model/types';

/**
 * 指摘の取り込みで共通の、ノードの参照解決（docs/architecture.md §8.6「共通の口」）。
 * `--node`（一括）・`--map`（ホスト名・IP → ノード）で指定された参照（ノード ID または C 番号）を図のノードに引く。
 */

/** 取り込み対象のノード 1 件分（プロジェクトの全レイヤーから集める）。 */
export interface ImportNodeRef {
  id: string;
  layer: LayerKey;
  seq?: number;
  type: ComponentTypeId;
  label?: string;
  posture?: object;
  attackSurface?: object;
}

export type NodeLookup = { kind: 'found'; node: ImportNodeRef } | { kind: 'unknown' } | { kind: 'ambiguous' };

export function lookupNode(nodes: readonly ImportNodeRef[], ref: string): NodeLookup {
  const byId = nodes.find((n) => n.id === ref);
  if (byId) return { kind: 'found', node: byId };
  const m = /^C(\d+)$/.exec(ref);
  if (m) {
    const hits = nodes.filter((n) => n.seq === Number(m[1]));
    if (hits.length === 1) return { kind: 'found', node: hits[0] };
    if (hits.length > 1) return { kind: 'ambiguous' };
  }
  return { kind: 'unknown' };
}

export interface HostIdentity {
  hostnames: readonly string[];
  fqdns?: readonly string[];
  ips: readonly string[];
}

export type HostResolution =
  | { kind: 'found'; node: ImportNodeRef }
  | { kind: 'unlinked'; reason: 'none' | 'unknownNode' | 'ambiguous'; ref?: string };

/**
 * ホスト 1 台をノードに解決する。`nodeRef`（--node）が最優先。
 * なければ `map` を ホスト名 → FQDN → IP の順に引く。どれにも当たらなければ未結合。
 */
export function resolveHost(
  nodes: readonly ImportNodeRef[],
  host: HostIdentity,
  map: Readonly<Record<string, string>> = {},
  nodeRef?: string,
): HostResolution {
  const ref = nodeRef ?? [...host.hostnames, ...(host.fqdns ?? []), ...host.ips].map((k) => map[k]).find((v) => v !== undefined);
  if (!ref) return { kind: 'unlinked', reason: 'none' };
  const found = lookupNode(nodes, ref);
  if (found.kind === 'found') return { kind: 'found', node: found.node };
  return { kind: 'unlinked', reason: found.kind === 'ambiguous' ? 'ambiguous' : 'unknownNode', ref };
}
