import type {
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  Finding,
  LayerKey,
  Severity,
  ThreatView,
} from '../../core/model/types';
import { buildAttackGraph } from './buildAttackGraph';
import { buildEntryEdges, ENTRY_SEARCH_APPLICABLE, findEntryPoints } from './findEntryPoints';
import { reachableFrom, recommendTargets } from './recommendTargets';
import { ssvcPointsFor, type SsvcAssessment, type SsvcInput } from './ssvc';

/**
 * 指摘の文脈と推奨の優先度（docs/attack-tree-analysis.md §12）。
 * 取り込んだ指摘を攻撃経路に載せ、露出・届く標的・悪用状況・連鎖を事実として列挙し、4 段の推奨順を付ける。
 * 元の深刻度は変えない。推奨と根拠であり、悪用できるとは言わない。判断は人。
 */

export type FindingExposure =
  /** 侵入口の候補にあるノード。 */
  | 'entry'
  /** 攻撃者から（侵入候補の仮想の線を含めて）到達できるノード。 */
  | 'reachable'
  | 'unreachable'
  /** 未結合、またはノードが図から消えている。 */
  | 'unbound'
  /** 攻撃者が図に無く、経路を評価できない。 */
  | 'unevaluated';

export type FindingPriority = 'P1' | 'P2' | 'P3' | 'P4';

export interface LayerContext {
  layer: LayerKey;
  nodes: readonly DiagramNode[];
  edges: readonly DiagramEdge[];
  boundaries: readonly DiagramBoundary[];
  threats: readonly ThreatView[];
}

/** 経路上で指摘が 2 つ以上のノードに並ぶ連鎖 1 件（攻撃者 → 標的の経路の一部）。 */
export interface FindingChain {
  layer: LayerKey;
  targetId: string;
  /** 経路上で指摘を持つノードの id（経路順）。 */
  nodeIds: string[];
  findingIds: string[];
  /** 連鎖内の指摘がすべて Medium 以下。「個々は低いが組み合わさると標的に届く」。 */
  allMediumOrBelow: boolean;
}

export interface PrioritizedFinding {
  finding: Finding;
  /** 指摘の結び付け先（Finding.subject）。 */
  nodeId?: string;
  layer?: LayerKey;
  exposure: FindingExposure;
  /** 入口・到達の判定が未入力の攻撃面属性の仮定に依存した。 */
  exposureAssumed: boolean;
  /** 届く推奨標的と最短ホップ数（短い順）。 */
  reachesTargets: { nodeId: string; hops: number }[];
  /** KEV の印があれば active、KEV が無く EPSS がしきい値以上なら likely、どちらも無ければ unknown。 */
  exploitation: 'active' | 'likely' | 'unknown';
  /** この指摘を含む連鎖（PrioritizeResult.chains の添字）。 */
  chainIndexes: number[];
  priority: FindingPriority;
  /** CISA SSVC の判定（P1〜P4 とは別の物差し。仮定の印つき）。 */
  ssvc: SsvcAssessment;
}

export interface PrioritizeResult {
  /** 優先度 → 深刻度 → 標的までのホップ数 → 連鎖の数 の順。 */
  items: PrioritizedFinding[];
  chains: FindingChain[];
  /** レイヤーごとに使った攻撃者のノード id。 */
  attackers: Partial<Record<LayerKey, string>>;
  /** 経路の列挙が上限に達したレイヤーがある（連鎖に漏れがありうる）。 */
  truncated: boolean;
}

/** EPSS による優先度の引き上げのしきい値の既定（FIRST の目安に沿った 10%）。 */
export const DEFAULT_EPSS_THRESHOLD = 0.1;

const SEVERITY_RANK: Record<Severity, number> = { Low: 0, Medium: 1, High: 2, Critical: 3 };
const PRIORITY_RANK: Record<FindingPriority, number> = { P1: 0, P2: 1, P3: 2, P4: 3 };

/** EPSS による引き上げ（1 段上。P1 はそのまま）。 */
const RAISED: Record<FindingPriority, FindingPriority> = { P1: 'P1', P2: 'P1', P3: 'P2', P4: 'P3' };

/** 無向の最短ホップ数（攻撃者ノードは経由しない）。 */
function hopsFrom(start: string, edges: readonly DiagramEdge[], attackerId: string): Map<string, number> {
  const adj = new Map<string, string[]>();
  for (const e of edges) {
    if (e.source === attackerId || e.target === attackerId) continue;
    adj.set(e.source, [...(adj.get(e.source) ?? []), e.target]);
    adj.set(e.target, [...(adj.get(e.target) ?? []), e.source]);
  }
  const dist = new Map<string, number>([[start, 0]]);
  const queue = [start];
  while (queue.length > 0) {
    const cur = queue.shift()!;
    for (const next of adj.get(cur) ?? []) {
      if (!dist.has(next)) {
        dist.set(next, dist.get(cur)! + 1);
        queue.push(next);
      }
    }
  }
  return dist;
}

/** ノードの業務の文脈から SSVC への入力を取り出す。 */
function businessOf(n: DiagramNode | undefined): Pick<SsvcInput, 'businessCriticality' | 'businessCriticalitySource'> {
  const b = n?.businessContext;
  return b ? { businessCriticality: b.criticality, businessCriticalitySource: b.criticalitySource } : {};
}

function pickAttacker(ctx: LayerContext, attackerId: string | undefined): string | undefined {
  const usable = (n: DiagramNode) => ENTRY_SEARCH_APPLICABLE.has(n.type);
  if (attackerId !== undefined) {
    const n = ctx.nodes.find((x) => x.id === attackerId);
    return n && usable(n) ? n.id : undefined;
  }
  return ctx.nodes.find(usable)?.id;
}

/**
 * 指摘を攻撃経路に載せて優先度を付ける純粋関数。レイヤーごとに評価する。
 * 攻撃者は `attackerId`、無ければ各レイヤーの図の攻撃者ノードの先頭。攻撃者の無いレイヤーの指摘は
 * `unevaluated`（KEV の印があれば P1、それ以外は P4）。
 * KEV が無く EPSS がしきい値以上（exploitation 'likely'）で、露出が入口・入口の奥の指摘は 1 段上げる（下げはしない）。
 */
export function prioritizeFindings(
  layers: readonly LayerContext[],
  findings: readonly Finding[],
  attackerId?: string,
  options: { epssThreshold?: number } = {},
): PrioritizeResult {
  const epssThreshold = options.epssThreshold ?? DEFAULT_EPSS_THRESHOLD;
  const items: PrioritizedFinding[] = [];
  const chains: FindingChain[] = [];
  const attackers: Partial<Record<LayerKey, string>> = {};
  let truncated = false;

  const base = (f: Finding): Omit<PrioritizedFinding, 'exposure' | 'priority' | 'ssvc'> => ({
    finding: f,
    ...(f.subject ? { nodeId: f.subject.nodeId, layer: f.subject.layer } : {}),
    exposureAssumed: false,
    reachesTargets: [],
    exploitation: f.kev ? 'active' : 'unknown',
    chainIndexes: [],
  });
  const flat = (f: Finding, exposure: 'unbound' | 'unevaluated'): PrioritizedFinding => {
    const b = base(f);
    return { ...b, exposure, priority: f.kev ? 'P1' : 'P4', ssvc: ssvcPointsFor({ ...b, exposure, isTarget: false }) };
  };

  const handled = new Set<string>();
  for (const ctx of layers) {
    const here = findings.filter((f) => f.subject?.layer === ctx.layer);
    const ids = new Set(ctx.nodes.map((n) => n.id));
    // 内包された資産の指摘は親のノードで数える。
    const parentOf = new Map(ctx.nodes.map((n) => [n.id, n.parentId && ids.has(n.parentId) ? n.parentId : n.id]));
    const nodeById = new Map(ctx.nodes.map((n) => [n.id, n] as const));
    const attacker = pickAttacker(ctx, attackerId);
    for (const f of here) handled.add(f.id);

    if (!attacker) {
      for (const f of here) items.push(flat(f, parentOf.has(f.subject!.nodeId) ? 'unevaluated' : 'unbound'));
      continue;
    }
    attackers[ctx.layer] = attacker;

    const entries = findEntryPoints(ctx.nodes, ctx.edges, ctx.boundaries, ctx.threats, attacker);
    const entryById = new Map(entries.map((c) => [c.nodeId, c]));
    const analysisEdges = [...ctx.edges, ...buildEntryEdges(attacker, entries)];
    const reachable = reachableFrom(attacker, analysisEdges);
    // 仮定でない入口だけから到達できるノード。ここに無い到達は未入力の仮定に依存する。
    const firmReachable = reachableFrom(attacker, [
      ...ctx.edges,
      ...buildEntryEdges(attacker, entries.filter((c) => !c.assumed)),
    ]);
    const targets = recommendTargets(ctx.nodes, ctx.edges, ctx.boundaries, ctx.threats, attacker).filter((t) => t.reachable);
    const targetIds = new Set(targets.map((t) => t.nodeId));

    const findingsByNode = new Map<string, Finding[]>();
    for (const f of here) {
      const top = parentOf.get(f.subject!.nodeId);
      if (top === undefined || top === attacker) continue;
      findingsByNode.set(top, [...(findingsByNode.get(top) ?? []), f]);
    }

    // 連鎖：標的への経路上で、指摘をもつノードが 2 つ以上並ぶもの。
    const layerChains: FindingChain[] = [];
    const seenChains = new Set<string>();
    for (const t of targets) {
      const g = buildAttackGraph(ctx.nodes, analysisEdges, attacker, t.nodeId);
      if (g.truncated) truncated = true;
      for (const route of g.routes) {
        const onRoute = route.nodeIds
          .map((id) => parentOf.get(id) ?? id)
          .filter((id, i, a) => a.indexOf(id) === i && findingsByNode.has(id));
        if (onRoute.length < 2) continue;
        const key = `${t.nodeId}|${onRoute.join(',')}`;
        if (seenChains.has(key)) continue;
        seenChains.add(key);
        const fs = onRoute.flatMap((id) => findingsByNode.get(id)!);
        layerChains.push({
          layer: ctx.layer,
          targetId: t.nodeId,
          nodeIds: onRoute,
          findingIds: fs.map((f) => f.id),
          allMediumOrBelow: fs.every((f) => SEVERITY_RANK[f.severity] <= SEVERITY_RANK.Medium),
        });
      }
    }
    const chainOffset = chains.length;
    chains.push(...layerChains);

    for (const f of here) {
      const top = parentOf.get(f.subject!.nodeId);
      if (top === undefined) {
        items.push(flat(f, 'unbound'));
        continue;
      }
      const entry = entryById.get(top);
      const exposure: FindingExposure = entry ? 'entry' : reachable.has(top) ? 'reachable' : 'unreachable';
      const exposureAssumed = entry ? entry.assumed : exposure === 'reachable' && !firmReachable.has(top);
      const dist = hopsFrom(top, analysisEdges, attacker);
      const reachesTargets =
        exposure === 'unreachable'
          ? []
          : targets
              .flatMap((t) => (dist.has(t.nodeId) ? [{ nodeId: t.nodeId, hops: dist.get(t.nodeId)! }] : []))
              .sort((a, b) => a.hops - b.hops);
      const chainIndexes = layerChains.flatMap((c, i) => (c.findingIds.includes(f.id) ? [chainOffset + i] : []));
      const exploitation: PrioritizedFinding['exploitation'] = f.kev ? 'active' : f.epss && f.epss.score >= epssThreshold ? 'likely' : 'unknown';
      const hasTarget = reachesTargets.length > 0;
      const computed: FindingPriority =
        exploitation === 'active' || (exposure === 'entry' && hasTarget)
          ? 'P1'
          : (exposure === 'reachable' && hasTarget) || chainIndexes.length > 0
            ? 'P2'
            : exposure === 'entry' || exposure === 'reachable'
              ? 'P3'
              : 'P4';
      const priority: FindingPriority =
        exploitation === 'likely' && (exposure === 'entry' || exposure === 'reachable') ? RAISED[computed] : computed;
      const b = { ...base(f), exposureAssumed, reachesTargets, exploitation, chainIndexes };
      items.push({ ...b, exposure, priority, ssvc: ssvcPointsFor({ ...b, exposure, isTarget: targetIds.has(top), ...businessOf(nodeById.get(top)) }) });
    }
  }

  // 未結合の指摘（subject なし）と、解析対象外のレイヤーの指摘。
  for (const f of findings) if (!handled.has(f.id)) items.push(flat(f, 'unbound'));

  items.sort(
    (a, b) =>
      PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority] ||
      SEVERITY_RANK[b.finding.severity] - SEVERITY_RANK[a.finding.severity] ||
      (a.reachesTargets[0]?.hops ?? Number.MAX_SAFE_INTEGER) - (b.reachesTargets[0]?.hops ?? Number.MAX_SAFE_INTEGER) ||
      b.chainIndexes.length - a.chainIndexes.length ||
      a.finding.id.localeCompare(b.finding.id),
  );
  return { items, chains, attackers, truncated };
}
