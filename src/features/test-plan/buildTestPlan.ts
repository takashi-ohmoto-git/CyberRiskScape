import {
  ATTACK_OBJECTIVE_APPLICABLE,
  isSuppressed,
  type DiagramEdge,
  type DiagramNode,
  type ElementKind,
  type LayerKey,
  type ProjectMeta,
  type Severity,
  type ThreatView,
} from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import { effectiveSeverity } from '../../core/model/risk';
import { BRANDING } from '../../core/branding';
import { getLocale, type Locale } from '../../i18n';
import { buildAttackGraph } from '../attack-tree/buildAttackGraph';
import { analyzeAttackGraph } from '../attack-tree/analyzeAttackGraph';
import { buildHopEvidence, NEUTRAL_EVIDENCE } from '../attack-tree/hopEvidence';
import { getViewpoints, type PentestViewpoint } from './viewpoints';

/**
 * 脅威モデルから、ペネトレーションテスト計画書（ベンダー中立）の構造を作る純粋関数。
 *
 * - 確認観点（何を確かめるか）は `data/test-templates/pentest.yaml`（canonicalId で対応）。コードは持たない。
 * - 攻撃経路は `buildAttackGraph` / `buildHopEvidence` / `analyzeAttackGraph` をそのまま使う
 *   （AttackTreeModal と同じ呼び出し）。
 */

/** buildThreatReport と同じ入力形（boundaries は使わないので省略可）。 */
export interface TestPlanInput {
  threats: ThreatView[];
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  projectMeta: ProjectMeta;
  layer: LayerKey;
  framework?: string;
}

export interface PlanElement {
  /** ElementalID（例: C3 / DF2）。 */
  id: string;
  label: string;
}

export interface PlanInboundEdge {
  id: string;
  /** 通信の相手側（攻撃者・外部のノード）。 */
  peer: PlanElement;
  auth: string;
  encryption: string;
  network: string;
}

export interface PlanEntryPoint {
  node: PlanElement;
  type: string;
  inbound: PlanInboundEdge[];
}

export interface PlanRoute {
  path: PlanElement[];
  /** 経路コスト。遮断されている（到達不能）ときは null。 */
  cost: number | null;
  /** 最も脆弱なホップ（経路順の端点）。無ければ null。 */
  weakestHop: { from: PlanElement; to: PlanElement } | null;
}

export interface PlanChokePoint {
  kind: 'node' | 'hop';
  label: string;
  routeHits: number;
}

export interface PlanScenario {
  attacker: PlanElement;
  objective: PlanElement;
  routes: PlanRoute[];
  chokePoints: PlanChokePoint[];
}

export interface PlanViewpoint {
  id: string;
  title: string;
  checks: string[];
  references: { standard: string; id: string }[];
  /** この観点に当たる脅威の名前（同じ要素内）。 */
  threatNames: string[];
}

export interface PlanThreat {
  severity: Severity;
  name: string;
  ruleId: string;
  description: string;
}

export interface PlanFocusGroup {
  target: PlanElement & { kind: ElementKind };
  maxSeverity: Severity;
  threats: PlanThreat[];
  viewpoints: PlanViewpoint[];
}

export interface PlanSuppressed {
  target: PlanElement;
  severity: Severity;
  name: string;
  ruleId: string;
  status: string;
  note: string;
}

export interface TestPlan {
  locale: Locale;
  product: string;
  system: string;
  layer: LayerKey;
  framework: string;
  /** 生成日（YYYY-MM-DD）。 */
  generatedAt: string;
  entryPoints: PlanEntryPoint[];
  scenarios: PlanScenario[];
  focusGroups: PlanFocusGroup[];
  suppressed: PlanSuppressed[];
}

const SEVERITY_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low'];
const sevRank = (s: Severity) => SEVERITY_ORDER.indexOf(s);
const KIND_ORDER: ElementKind[] = ['node', 'edge', 'boundary'];
const TOP_ROUTES = 3;
const TOP_CHOKE_POINTS = 3;
const DESCRIPTION_MAX = 160;

/** 説明文を最初の一文（最大 160 文字）に縮める。全文は脅威レポート側にある。 */
function shortDescription(text: string): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  const end = flat.search(/[。]|\.\s/);
  const sentence = end >= 0 ? flat.slice(0, end + 1) : flat;
  return sentence.length > DESCRIPTION_MAX ? `${sentence.slice(0, DESCRIPTION_MAX)}…` : sentence;
}

export function buildTestPlan(input: TestPlanInput, now: Date, locale: Locale = getLocale()): TestPlan {
  const viewpointByCanonical = new Map<string, PentestViewpoint>();
  for (const v of getViewpoints(locale)) for (const c of v.match.canonicalIds) viewpointByCanonical.set(c, v);

  const nodeById = new Map(input.nodes.map((n) => [n.id, n]));
  const edgeById = new Map(input.edges.map((e) => [e.id, e]));
  const nodeEl = (n: DiagramNode): PlanElement => ({
    id: n.seq != null ? formatElementalId('node', n.seq) : n.id,
    label: getNodeDisplayName(n),
  });
  const nodeElById = (id: string): PlanElement => {
    const n = nodeById.get(id);
    return n ? nodeEl(n) : { id, label: '' };
  };
  const edgeEl = (e: DiagramEdge): PlanElement => {
    const id = e.seq != null ? formatElementalId('edge', e.seq) : e.id;
    const name = e.dataFlowName?.trim();
    return { id, label: `${name ? `${name} ` : ''}(${nodeElById(e.source).id} → ${nodeElById(e.target).id})` };
  };

  // ── 2. 入口 ──
  // 規則: 次のどちらかの通信を受ける側のノードを「攻撃者が直接届く入口」とする（攻撃者ノード自身は除く）。
  //   (a) 攻撃者系ノード（脅威アクター・内部犯・攻撃エージェント）につながるエッジ
  //   (b) network が Internet のエッジ
  // 受ける側は dataFlow で決める（outbound/未指定=target、inbound=source、bidirectional=両端）。
  const isAttacker = (n: DiagramNode | undefined) => !!n && ATTACK_OBJECTIVE_APPLICABLE.has(n.type);
  const entryMap = new Map<string, PlanEntryPoint>();
  for (const e of input.edges) {
    const src = nodeById.get(e.source);
    const tgt = nodeById.get(e.target);
    if (!src || !tgt) continue;
    if (!(e.network === 'Internet' || isAttacker(src) || isAttacker(tgt))) continue;
    const flow = e.dataFlow ?? 'outbound';
    const receivers: [DiagramNode, DiagramNode][] = [];
    if (flow === 'outbound' || flow === 'bidirectional') receivers.push([tgt, src]);
    if (flow === 'inbound' || flow === 'bidirectional') receivers.push([src, tgt]);
    for (const [recv, peer] of receivers) {
      if (isAttacker(recv)) continue;
      const entry = entryMap.get(recv.id) ?? { node: nodeEl(recv), type: recv.type, inbound: [] };
      entry.inbound.push({
        id: edgeEl(e).id,
        peer: nodeEl(peer),
        auth: e.auth,
        encryption: e.encryption,
        network: e.network,
      });
      entryMap.set(recv.id, entry);
    }
  }
  const entryPoints = [...entryMap.values()];

  // ── 3. 攻撃シナリオ（objective を持つ攻撃者ごと）──
  const evidence = buildHopEvidence(input.threats);
  const getEvidence = (key: string) => evidence.get(key) ?? NEUTRAL_EVIDENCE;
  const scenarios: PlanScenario[] = [];
  for (const attacker of input.nodes) {
    if (!isAttacker(attacker) || !attacker.attackObjectiveId) continue;
    const target = nodeById.get(attacker.attackObjectiveId);
    if (!target) continue;
    const graph = buildAttackGraph(input.nodes, input.edges, attacker.id, target.id);
    const analysis = analyzeAttackGraph(graph, getEvidence);
    const routes: PlanRoute[] = analysis.routes.slice(0, TOP_ROUTES).map((r) => {
      const i = r.route.hopKeys.indexOf(r.weakestHopKey);
      return {
        path: r.route.nodeIds.map(nodeElById),
        cost: r.feasible ? r.cost : null,
        weakestHop:
          i >= 0
            ? { from: nodeElById(r.route.nodeIds[i]), to: nodeElById(r.route.nodeIds[i + 1]) }
            : null,
      };
    });
    const chokePoints: PlanChokePoint[] = analysis.chokePoints.slice(0, TOP_CHOKE_POINTS).map((c) => {
      if (c.elementKey.startsWith('node:')) {
        const el = nodeElById(c.elementKey.slice('node:'.length));
        return { kind: 'node', label: `${el.id} ${el.label}`.trim(), routeHits: c.routeHits };
      }
      const hop = graph.hops.get(c.elementKey.slice('hop:'.length));
      const label = hop ? `${nodeElById(hop.a).id} – ${nodeElById(hop.b).id}` : c.elementKey;
      return { kind: 'hop', label, routeHits: c.routeHits };
    });
    scenarios.push({ attacker: nodeEl(attacker), objective: nodeEl(target), routes, chokePoints });
  }

  // ── 4 / 5. 脅威 ──
  const elementOf = (t: ThreatView): PlanElement & { kind: ElementKind } => {
    const kind: ElementKind = t.subject?.kind ?? 'node';
    const id = t.subject?.id ?? t.nodeId;
    if (kind === 'node') return { kind, ...nodeElById(id) };
    if (kind === 'edge') {
      const e = edgeById.get(id);
      return { kind, ...(e ? edgeEl(e) : { id, label: '' }) };
    }
    return { kind, id, label: '' };
  };

  const groups = new Map<string, PlanFocusGroup>();
  const suppressed: PlanSuppressed[] = [];
  for (const t of [...input.threats].sort((a, b) => sevRank(effectiveSeverity(a)) - sevRank(effectiveSeverity(b)))) {
    const target = elementOf(t);
    const severity = effectiveSeverity(t);
    const name = t.name ?? t.category;
    const ruleId = t.ruleId ?? t.id;
    if (isSuppressed(t)) {
      suppressed.push({
        target,
        severity,
        name,
        ruleId,
        status: t.suppression!.status,
        note: t.suppression!.note?.trim() ?? '',
      });
      continue;
    }
    const key = `${target.kind}:${t.subject?.id ?? t.nodeId}`;
    const group = groups.get(key) ?? { target, maxSeverity: severity, threats: [], viewpoints: [] };
    group.threats.push({ severity, name, ruleId, description: shortDescription(t.description) });
    const vp = t.canonicalId ? viewpointByCanonical.get(t.canonicalId) : undefined;
    if (vp) {
      // 観点は要素ごとに 1 回だけ載せる。
      const existing = group.viewpoints.find((v) => v.id === vp.id);
      if (existing) existing.threatNames.push(name);
      else
        group.viewpoints.push({
          id: vp.id,
          title: vp.title,
          checks: [...vp.checks],
          references: vp.references.map((r) => ({ ...r })),
          threatNames: [name],
        });
    }
    groups.set(key, group);
  }

  const elementSortKey = (g: PlanFocusGroup) => [KIND_ORDER.indexOf(g.target.kind), g.target.id] as const;
  const focusGroups = [...groups.values()].sort((a, b) => {
    if (a.maxSeverity !== b.maxSeverity) return sevRank(a.maxSeverity) - sevRank(b.maxSeverity);
    const [ka, ia] = elementSortKey(a);
    const [kb, ib] = elementSortKey(b);
    return ka - kb || ia.localeCompare(ib, undefined, { numeric: true });
  });

  return {
    locale,
    product: BRANDING.name,
    system: input.projectMeta.systemName.trim() || input.projectMeta.name.trim() || BRANDING.name,
    layer: input.layer,
    framework: input.framework ?? 'ALL',
    // 文書に載せる日付なので、UTC ではなく実行環境の日付にする。
    generatedAt: `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`,
    entryPoints,
    scenarios,
    focusGroups,
    suppressed,
  };
}
