import {
  ATTACK_OBJECTIVE_APPLICABLE,
  AUTH_PROVIDER_EXCLUDED_CATEGORIES,
  type DiagramEdge,
  type DiagramNode,
  type LayerKey,
  type ProjectMeta,
  type ThreatView,
} from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import { BRANDING } from '../../core/branding';
import { componentRegistry } from '../../component-library/defaultRegistry';
import { getLocale, type Locale } from '../../i18n';
import { buildAttackGraph } from '../attack-tree/buildAttackGraph';
import { analyzeAttackGraph } from '../attack-tree/analyzeAttackGraph';
import { assessRouteDetection, type DetectionState } from '../attack-tree/detectionGaps';
import { buildHopEvidence, NEUTRAL_EVIDENCE } from '../attack-tree/hopEvidence';
import { getDetectionRequirements, type DetectionRequirement } from './requirements';

/**
 * 脅威モデルから、攻撃経路上のノードごとに「監視すべき振る舞い」「必要なログ」「ログの届き方」を作る純粋関数。
 *
 * - 要件（何を監視すべきか・どのログが要るか）は `data/detection-requirements/detection.yaml`（canonicalId で対応）。
 * - 対象ノードは buildInvestigationPlan と同じ決め方（攻撃者 → 攻撃目標の経路上。経路が無ければ全ノード・優先度なし）。
 * - ログの状態は attack-tree の assessRouteDetection（検知の空白、docs/attack-tree-analysis.md §11）をそのまま使う。
 * - 「検知できる」とは言わない。示すのは監視すべきことと、ログが監視先に届くと図から読めるかだけ。
 */

export interface DetectionRequirementsInput {
  threats: ThreatView[];
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  projectMeta: ProjectMeta;
  layer: LayerKey;
}

/** 経路ごとに載せる最大数（コストの低い順）。 */
export const MAX_ROUTES = 10;

export interface DetectionRequirementEntry {
  id: string;
  title: string;
  watch: string[];
  logs: string[];
  attack: string[];
  /** この要件に当たる脅威の名前（同じノード内）。 */
  threatNames: string[];
}

export interface DetectionNodeLog {
  state: DetectionState;
  /** 何も入力されていないため、ログなしと仮定した。 */
  assumed: boolean;
}

export interface DetectionNode {
  /** ElementalID（例: C3）。 */
  id: string;
  label: string;
  type: string;
  /** 通る攻撃経路の本数。経路が無い図（全ノード対象）では null。 */
  routeHits: number | null;
  /** ログの状態。この型はログの状況を図で表せない場合は null。 */
  log: DetectionNodeLog | null;
  requirements: DetectionRequirementEntry[];
}

export interface DetectionRoute {
  /** 攻撃者ノード（ElementalID）と、その攻撃目標。 */
  attacker: string;
  objective: string;
  /** 経路上のノード（ElementalID、経路順、攻撃者を含む）。 */
  nodes: string[];
  /** ログが監視先に届かない連続区間（ElementalID、経路順）。 */
  gaps: string[][];
  /** 評価対象のノードのうち、監視先に届くものが 1 件も無い。 */
  blind: boolean;
}

export interface DetectionRequirements {
  locale: Locale;
  product: string;
  system: string;
  layer: LayerKey;
  /** 生成日（YYYY-MM-DD）。 */
  generatedAt: string;
  /** true: 攻撃経路上のノードに絞った。false: 経路が無いので全ノード（優先度なし）。 */
  pathBased: boolean;
  /** 実行可能な経路の総数（routes は MAX_ROUTES まで）。 */
  totalRoutes: number;
  routes: DetectionRoute[];
  nodes: DetectionNode[];
}

export function buildDetectionRequirements(
  input: DetectionRequirementsInput,
  now: Date,
  locale: Locale = getLocale(),
): DetectionRequirements {
  const reqByCanonical = new Map<string, DetectionRequirement>();
  for (const r of getDetectionRequirements(locale)) for (const c of r.match.canonicalIds) reqByCanonical.set(c, r);

  const nodeById = new Map(input.nodes.map((n) => [n.id, n]));
  const isAttacker = (n: DiagramNode) => ATTACK_OBJECTIVE_APPLICABLE.has(n.type);
  const eid = (id: string): string => {
    const n = nodeById.get(id);
    return n && n.seq != null ? formatElementalId('node', n.seq) : id;
  };
  // ログの属性を入力できる型か（AttackTreeModal と同じ条件。SHADOW は評価側で扱う）
  const isLogInputAvailable = (n: DiagramNode) => {
    const category = componentRegistry.get(n.type)?.category;
    return category === undefined || !AUTH_PROVIDER_EXCLUDED_CATEGORIES.has(category);
  };

  // ── 攻撃経路（攻撃者ごと）と、載る経路の本数 ──
  const evidence = buildHopEvidence(input.threats);
  const getEvidence = (key: string) => evidence.get(key) ?? NEUTRAL_EVIDENCE;
  const hits = new Map<string, number>();
  const logOf = new Map<string, DetectionNodeLog>();
  const routes: DetectionRoute[] = [];
  let totalRoutes = 0;
  for (const attacker of input.nodes) {
    if (!isAttacker(attacker) || !attacker.attackObjectiveId) continue;
    const target = nodeById.get(attacker.attackObjectiveId);
    if (!target) continue;
    const analysis = analyzeAttackGraph(buildAttackGraph(input.nodes, input.edges, attacker.id, target.id), getEvidence);
    for (const r of analysis.routes) {
      for (const id of new Set(r.route.nodeIds)) hits.set(id, (hits.get(id) ?? 0) + 1);
      if (!r.feasible) continue;
      totalRoutes++;
      const d = assessRouteDetection({
        routeNodeIds: r.route.nodeIds,
        nodes: input.nodes,
        attackerId: attacker.id,
        isLogInputAvailable,
      });
      for (const n of d.nodes) logOf.set(n.nodeId, { state: n.state, assumed: n.assumed });
      if (routes.length < MAX_ROUTES) {
        routes.push({
          attacker: eid(attacker.id),
          objective: eid(target.id),
          nodes: r.route.nodeIds.map(eid),
          gaps: d.gaps.map((g) => g.map(eid)),
          blind: d.blind,
        });
      }
    }
  }
  for (const id of [...hits.keys()]) {
    const n = nodeById.get(id);
    if (!n || isAttacker(n)) hits.delete(id);
  }
  const pathBased = hits.size > 0;

  const targets = pathBased ? input.nodes.filter((n) => hits.has(n.id)) : input.nodes.filter((n) => !isAttacker(n));

  // 経路外（全ノード対象）のときは、ノード単独でログの状態を評価する。
  const logStateOf = (n: DiagramNode): DetectionNodeLog | null => {
    const known = logOf.get(n.id);
    if (known) return known;
    const d = assessRouteDetection({ routeNodeIds: [n.id], nodes: input.nodes, attackerId: '', isLogInputAvailable });
    const one = d.nodes[0];
    return one ? { state: one.state, assumed: one.assumed } : null;
  };

  // ── ノードごとの要件（誤検知は除く。リスク受容は監視の要否と無関係なので含める）──
  const reqsByNode = new Map<string, DetectionRequirementEntry[]>();
  for (const t of input.threats) {
    if (t.suppression?.status === 'false-positive' || (t.subject && t.subject.kind !== 'node') || !t.canonicalId) continue;
    const req = reqByCanonical.get(t.canonicalId);
    if (!req) continue;
    const nodeId = t.subject?.id ?? t.nodeId;
    const list = reqsByNode.get(nodeId) ?? [];
    const name = t.name ?? t.category;
    const existing = list.find((v) => v.id === req.id);
    if (existing) {
      existing.threatNames.push(name);
    } else {
      list.push({
        id: req.id,
        title: req.title,
        watch: [...req.watch],
        logs: [...req.logs],
        attack: [...(req.attack ?? [])],
        threatNames: [name],
      });
    }
    reqsByNode.set(nodeId, list);
  }

  const nodes: DetectionNode[] = targets.map((n) => ({
    id: eid(n.id),
    label: getNodeDisplayName(n),
    type: n.type,
    routeHits: pathBased ? (hits.get(n.id) ?? 0) : null,
    log: logStateOf(n),
    requirements: reqsByNode.get(n.id) ?? [],
  }));
  nodes.sort(
    (a, b) => (b.routeHits ?? 0) - (a.routeHits ?? 0) || a.id.localeCompare(b.id, undefined, { numeric: true }),
  );

  return {
    locale,
    product: BRANDING.name,
    system: input.projectMeta.systemName.trim() || input.projectMeta.name.trim() || BRANDING.name,
    layer: input.layer,
    generatedAt: `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`,
    pathBased,
    totalRoutes,
    routes,
    nodes,
  };
}
