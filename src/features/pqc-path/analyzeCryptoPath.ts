import { enumeratePaths } from '../../core/graph/enumeratePaths';
import type {
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  TrustLevel,
} from '../../core/model/types';
import { resolveNodeTrust } from '../../core/threat-engine/resolveNodeTrust';
import { classifyAlgorithm } from '../../crypto-behavior/loader';
import type { AlgorithmTable, TerminationBehavior } from '../../crypto-behavior/schema';
import type {
  CryptoPathResult,
  CryptoRoute,
  CryptoSegment,
  EffectiveTermination,
  SegmentPqc,
  SegmentProbability,
  SegmentSignatureClass,
  SegmentWarning,
} from './types';

export interface AnalyzeCryptoPathInput {
  nodes: readonly DiagramNode[];
  edges: readonly DiagramEdge[];
  boundaries: readonly DiagramBoundary[];
  sourceId: string;
  targetId: string;
  /** 型ごとの終端判定の既定値（data/crypto-behavior/termination.yaml）。 */
  behaviors: readonly TerminationBehavior[];
  /** PQC 判定の基準表（data/crypto-behavior/pqc-algorithms.yaml）。 */
  algorithms: AlgorithmTable;
}

/** 悪い順（先頭ほど悪い）。 */
const PQC_BADNESS: readonly SegmentPqc[] = ['plain', 'vulnerable', 'transitional', 'unknown', 'pqc'];
const SIG_BADNESS: readonly SegmentSignatureClass[] = [
  'vulnerable',
  'transitional',
  'unknown',
  'pqc',
];

function worst<T extends string>(order: readonly T[], values: readonly T[]): T | undefined {
  let best: number | undefined;
  for (const v of values) {
    const i = order.indexOf(v);
    if (best === undefined || i < best) best = i;
  }
  return best === undefined ? undefined : order[best];
}

/** 経路の途中で区間を切る判定（unknown は安全側に倒して切る）。 */
const CUTTING = new Set(['terminate', 'inspect', 'unknown']);

function uniq(values: (string | undefined)[]): string[] {
  return [...new Set(values.filter((v): v is string => !!v && v.trim() !== ''))];
}

/**
 * 送信元→送信先の暗号経路を、区間（暗号が切れる単位）ごとに分析する純粋関数。
 * YAML の読み込みは呼び出し側が行い、ここでは受け取った判定データだけを使う。
 */
export function analyzeCryptoPath(input: AnalyzeCryptoPathInput): CryptoPathResult {
  const { nodes, edges, boundaries, sourceId, targetId, behaviors, algorithms } = input;

  let undirectedFallback = false;
  let enumerated = enumeratePaths(nodes, edges, sourceId, targetId, { directed: true });
  if (enumerated.paths.length === 0) {
    enumerated = enumeratePaths(nodes, edges, sourceId, targetId, { directed: false });
    if (enumerated.paths.length === 0) {
      return { routes: [], uniqueSegments: [], undirectedFallback: false, truncated: false };
    }
    undirectedFallback = true;
  }

  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  const edgeById = new Map(edges.map((e) => [e.id, e]));
  const behaviorByType = new Map(behaviors.map((b) => [b.componentType, b]));
  const trust: Map<string, TrustLevel> = resolveNodeTrust([...nodes], [...boundaries]);

  const effectiveTermination = (nodeId: string, isEndpoint: boolean): EffectiveTermination => {
    if (isEndpoint) return { value: 'endpoint', confidence: 'endpoint' };
    const node = nodeById.get(nodeId);
    if (node?.crypto?.termination) {
      return { value: node.crypto.termination, confidence: 'confirmed' };
    }
    const b = node ? behaviorByType.get(node.type) : undefined;
    if (b) return { value: b.default, confidence: 'default' };
    return { value: 'unknown', confidence: 'unknown' };
  };

  const buildSegment = (
    route: { nodeIds: string[]; edgeIds: string[] },
    a: number,
    b: number,
  ): CryptoSegment => {
    const fromNodeId = route.nodeIds[a];
    const toNodeId = route.nodeIds[b];
    const startTermination = effectiveTermination(fromNodeId, a === 0);
    const viaNodeIds = route.nodeIds.slice(a + 1, b);
    const edgeIds = route.edgeIds.slice(a, b);
    const segEdges = edgeIds.map((id) => edgeById.get(id)).filter((e): e is DiagramEdge => !!e);
    const fromNode = nodeById.get(fromNodeId);
    const toNode = nodeById.get(toNodeId);

    const viaTerms = viaNodeIds.map((id) => effectiveTermination(id, false).value);

    let probability: SegmentProbability = 'low';
    const ends = [trust.get(fromNodeId), trust.get(toNodeId)];
    if (ends.includes('Internet') || segEdges.some((e) => e.network === 'Internet')) {
      probability = 'high';
    } else if (ends.includes('Partner')) {
      probability = 'medium';
    }

    const pqcValues: SegmentPqc[] = segEdges.map((e) => {
      if (e.encryption === 'Plain') return 'plain';
      const kex = e.crypto?.kex;
      return (kex ? classifyAlgorithm(kex, algorithms) : null) ?? 'unknown';
    });

    const sigValues: SegmentSignatureClass[] = [
      ...segEdges.map((e) => e.crypto?.signature),
      toNode?.crypto?.signature,
    ]
      .filter((s): s is string => !!s && s.trim() !== '')
      .map((s) => classifyAlgorithm(s, algorithms) ?? 'unknown');

    const warnings: SegmentWarning[] = [];
    if (viaTerms.includes('passive-decrypt')) warnings.push('passive-decrypt');
    if (startTermination.value === 'inspect') warnings.push('inspect-resign');
    if (viaTerms.includes('tunnel')) warnings.push('outer-tunnel');
    if (new Set(segEdges.map((e) => e.encryption)).size > 1) warnings.push('mixed-channel');

    return {
      fromNodeId,
      toNodeId,
      viaNodeIds,
      edgeIds,
      startTermination,
      providerManaged:
        fromNode?.crypto?.managedBy === 'provider' || toNode?.crypto?.managedBy === 'provider',
      probability,
      pqc: worst(PQC_BADNESS, pqcValues) ?? 'unknown',
      signatureClass: worst(SIG_BADNESS, sigValues) ?? 'unknown',
      protocols: uniq(segEdges.map((e) => e.crypto?.protocol ?? e.encryption)),
      kex: uniq(segEdges.map((e) => e.crypto?.kex)),
      signatures: uniq(segEdges.map((e) => e.crypto?.signature)),
      warnings,
    };
  };

  const routes: CryptoRoute[] = enumerated.paths.map((p) => {
    const last = p.nodeIds.length - 1;
    // 区間の境界になるノード位置（始点・終点を含む）
    const bounds: number[] = [0];
    for (let i = 1; i < last; i++) {
      const term = effectiveTermination(p.nodeIds[i], false).value;
      if (!CUTTING.has(term)) continue;
      // E2EE の例外：前後の edge が両方 E2EE なら内側の暗号は変わらないので切らない
      const bothE2ee =
        edgeById.get(p.edgeIds[i - 1])?.encryption === 'E2EE' &&
        edgeById.get(p.edgeIds[i])?.encryption === 'E2EE';
      if (bothE2ee) continue;
      bounds.push(i);
    }
    bounds.push(last);

    const segments: CryptoSegment[] = [];
    for (let k = 0; k < bounds.length - 1; k++) {
      segments.push(buildSegment(p, bounds[k], bounds[k + 1]));
    }
    return { nodeIds: p.nodeIds, edgeIds: p.edgeIds, segments };
  });

  const seen = new Set<string>();
  const uniqueSegments: CryptoSegment[] = [];
  for (const r of routes) {
    for (const s of r.segments) {
      const key = `${s.fromNodeId}|${s.toNodeId}|${s.edgeIds.join(',')}`;
      if (seen.has(key)) continue;
      seen.add(key);
      uniqueSegments.push(s);
    }
  }

  return { routes, uniqueSegments, undirectedFallback, truncated: enumerated.truncated };
}
