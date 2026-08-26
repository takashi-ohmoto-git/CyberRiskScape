import type { AttackGraphResult, AttackRoute } from './buildAttackGraph';
import {
  edgeElementKey,
  nodeElementKey,
  threatEvidenceScore,
  type HopCoverage,
  type HopEvidenceProvider,
} from './hopEvidence';

/** coverage==='partial' のホップ加算。 */
export const PARTIAL_COVERAGE_PENALTY = 1;
/** coverage==='full' のホップ加算（既定モード）。残存経路モードでは Infinity。 */
export const FULL_COVERAGE_PENALTY = 8;

/** コスト算出済みの 1 経路。 */
export interface AnalyzedRoute {
  route: AttackRoute;
  /** 経路コスト（coverage ペナルティ込み）。Infinity = 遮断。 */
  cost: number;
  /** cost が有限か。 */
  feasible: boolean;
  /** 経路中で最も低コスト（=最脆弱）なホップの key。同点は先勝ち。攻撃者ステップは対象外。 */
  weakestHopKey: string;
  /** hopKey → 採用した edgeId（並行チャネルのうち最小コストのもの）。 */
  chosenChannels: Map<string, string>;
  /**
   * コスト同点時のタイブレイク用。経路上の脅威根拠の濃さ（大きいほど脆弱扱い）。
   * コスト本体には加算しない。
   */
  evidenceScore: number;
}

/** チョークポイント（ノード or ホップ）1 件分。 */
export interface ChokePoint {
  /** `node:<nodeId>` または `hop:<hopKey>`。 */
  elementKey: string;
  /** 全 routes 中の通過本数（feasible かどうかに依らずカウント）。 */
  routeHits: number;
  /** node: その要素の coverage / hop: 最も弱い（none 寄りの）チャネル edge coverage。 */
  coverage: HopCoverage;
}

export interface AnalyzeGraphResult {
  /** コスト昇順（同点はホップ数少ない順→安定）。先頭が最脆弱ルート。 */
  routes: AnalyzedRoute[];
  /** routes 先頭の cost。routes 空なら Infinity。 */
  minCost: number;
  feasible: boolean;
  /** ランキング済み全件（UI 側で上位表示）。 */
  chokePoints: ChokePoint[];
  /** グラフ上の全要素（ノード＋全チャネルエッジ）が evaluated===false のとき true。 */
  allUnevaluated: boolean;
}

const COVERAGE_RANK: Record<HopCoverage, number> = { none: 0, partial: 1, full: 2 };

/** 2 つの被覆度のうち、より閉じた（none < partial < full）方を返す。 */
function strongerCoverage(a: HopCoverage, b: HopCoverage): HopCoverage {
  return COVERAGE_RANK[a] >= COVERAGE_RANK[b] ? a : b;
}

/** 2 つの被覆度のうち、より弱い（none 寄りの）方を返す。 */
function weakerCoverage(a: HopCoverage, b: HopCoverage): HopCoverage {
  return COVERAGE_RANK[a] <= COVERAGE_RANK[b] ? a : b;
}

/** 既定では full に大ペナルティ、残存経路モードでは full を遮断（Infinity）。 */
function coveragePenalty(coverage: HopCoverage, residualOnly: boolean): number {
  if (coverage === 'full') return residualOnly ? Infinity : FULL_COVERAGE_PENALTY;
  if (coverage === 'partial') return PARTIAL_COVERAGE_PENALTY;
  return 0;
}

/**
 * `buildAttackGraph` の結果に DREAD/Control 由来の重み（HopEvidence）を載せ、
 * ノード列ベースの各経路について、並行チャネル（論理ホップ内の edgeIds）から
 * 最小コストのものを選びつつコストを算定する純粋関数。
 *
 * コスト算出は v1 `analyzeAttackTree`（prefix 木ボトムアップ）と数値互換：
 * 攻撃者ステップ = difficulty(攻撃者) + penalty(coverage(攻撃者))、
 * 以降の各ステップ = difficulty(到達ノード) + difficulty(採用エッジ)
 *   + penalty(stronger(coverage(到達ノード), coverage(採用エッジ)))。
 * 単一チャネルの一本鎖では v1 の minCost と完全一致する。
 */
export function analyzeAttackGraph(
  graph: AttackGraphResult,
  getEvidence: HopEvidenceProvider,
  residualOnly = false,
): AnalyzeGraphResult {
  const analyzedRoutes: AnalyzedRoute[] = graph.routes.map((route) => analyzeRoute(graph, route, getEvidence, residualOnly));

  // コスト昇順 → 脅威根拠が濃い順（同コストで High 脅威経路を優先）→ ホップ数少ない順
  analyzedRoutes.sort((r1, r2) => {
    if (r1.cost !== r2.cost) return r1.cost - r2.cost;
    if (r1.evidenceScore !== r2.evidenceScore) return r2.evidenceScore - r1.evidenceScore;
    return r1.route.nodeIds.length - r2.route.nodeIds.length;
  });

  const minCost = analyzedRoutes.length > 0 ? analyzedRoutes[0].cost : Infinity;
  const feasible = Number.isFinite(minCost);

  const chokePoints = computeChokePoints(graph, getEvidence);
  const allUnevaluated = computeAllUnevaluated(graph, getEvidence);

  return { routes: analyzedRoutes, minCost, feasible, chokePoints, allUnevaluated };
}

/** 1 経路のコスト・チャネル選択・最脆弱ホップを算定する。 */
function analyzeRoute(
  graph: AttackGraphResult,
  route: AttackRoute,
  getEvidence: HopEvidenceProvider,
  residualOnly: boolean,
): AnalyzedRoute {
  const { nodeIds, hopKeys } = route;
  const chosenChannels = new Map<string, string>();

  // ステップ0（攻撃者）
  const attackerEvidence = getEvidence(nodeElementKey(nodeIds[0]));
  let cost = attackerEvidence.difficulty + coveragePenalty(attackerEvidence.coverage, residualOnly);
  let evidenceScore = threatEvidenceScore(attackerEvidence.threats);

  let weakestHopKey = '';
  let weakestStepCost = Infinity;

  for (let i = 0; i < hopKeys.length; i++) {
    const hopKeyStr = hopKeys[i];
    const nodeId = nodeIds[i + 1];
    const hop = graph.hops.get(hopKeyStr);
    const nodeEvidence = getEvidence(nodeElementKey(nodeId));
    evidenceScore += threatEvidenceScore(nodeEvidence.threats);

    // チャネル選択: penalty 込みステップコスト最小の edge を採用（同点は edgeIds 先頭優先）
    let bestEdgeId = '';
    let bestStepCost = Infinity;
    for (const edgeId of hop?.edgeIds ?? []) {
      const edgeEvidence = getEvidence(edgeElementKey(edgeId));
      const coverage = strongerCoverage(nodeEvidence.coverage, edgeEvidence.coverage);
      const stepCost =
        nodeEvidence.difficulty + edgeEvidence.difficulty + coveragePenalty(coverage, residualOnly);
      if (stepCost < bestStepCost) {
        bestStepCost = stepCost;
        bestEdgeId = edgeId;
      }
    }

    if (bestEdgeId) {
      chosenChannels.set(hopKeyStr, bestEdgeId);
      evidenceScore += threatEvidenceScore(getEvidence(edgeElementKey(bestEdgeId)).threats);
    }
    cost += bestStepCost;

    if (bestStepCost < weakestStepCost) {
      weakestStepCost = bestStepCost;
      weakestHopKey = hopKeyStr;
    }
  }

  return {
    route,
    cost,
    feasible: Number.isFinite(cost),
    weakestHopKey,
    chosenChannels,
    evidenceScore,
  };
}

/** 中間ノード（攻撃者・標的除く）と論理ホップについて routeHits・coverage を集計しランキングする。 */
function computeChokePoints(graph: AttackGraphResult, getEvidence: HopEvidenceProvider): ChokePoint[] {
  const routeHits = new Map<string, number>();

  for (const route of graph.routes) {
    const { nodeIds, hopKeys } = route;
    for (let i = 1; i < nodeIds.length - 1; i++) {
      const key = `node:${nodeIds[i]}`;
      routeHits.set(key, (routeHits.get(key) ?? 0) + 1);
    }
    for (const hopKeyStr of hopKeys) {
      const key = `hop:${hopKeyStr}`;
      routeHits.set(key, (routeHits.get(key) ?? 0) + 1);
    }
  }

  const chokePoints: ChokePoint[] = [];
  for (const [elementKey, hits] of routeHits) {
    let coverage: HopCoverage;
    if (elementKey.startsWith('node:')) {
      const nodeId = elementKey.slice('node:'.length);
      coverage = getEvidence(nodeElementKey(nodeId)).coverage;
    } else {
      const hopKeyStr = elementKey.slice('hop:'.length);
      const hop = graph.hops.get(hopKeyStr);
      coverage = 'full';
      for (const edgeId of hop?.edgeIds ?? []) {
        const edgeCoverage = getEvidence(edgeElementKey(edgeId)).coverage;
        coverage = weakerCoverage(coverage, edgeCoverage);
      }
      if (!hop || hop.edgeIds.length === 0) coverage = 'none';
    }
    chokePoints.push({ elementKey, routeHits: hits, coverage });
  }

  chokePoints.sort((c1, c2) => {
    if (c1.routeHits !== c2.routeHits) return c2.routeHits - c1.routeHits;
    return COVERAGE_RANK[c1.coverage] - COVERAGE_RANK[c2.coverage];
  });

  return chokePoints;
}

/** グラフ上の全ノード・全チャネルエッジが evaluated===false かを判定する。 */
function computeAllUnevaluated(graph: AttackGraphResult, getEvidence: HopEvidenceProvider): boolean {
  for (const nodeId of graph.nodeIds) {
    if (getEvidence(nodeElementKey(nodeId)).evaluated) return false;
  }
  for (const hop of graph.hops.values()) {
    for (const edgeId of hop.edgeIds) {
      if (getEvidence(edgeElementKey(edgeId)).evaluated) return false;
    }
  }
  return true;
}
