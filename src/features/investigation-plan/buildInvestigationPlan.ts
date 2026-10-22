import {
  ATTACK_OBJECTIVE_APPLICABLE,
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
import { buildHopEvidence, NEUTRAL_EVIDENCE } from '../attack-tree/hopEvidence';
import { getInvestigationViewpoints, type InvestigationToolStep, type InvestigationViewpoint } from './viewpoints';

/**
 * 脅威モデルから、侵害の疑いがあるときの調査計画（ベンダー中立）の構造を作る純粋関数。
 *
 * - 観点（何を確かめるか・どのログを見るか）は `data/investigation-templates/compromise.yaml`
 *   （canonicalId で対応）。コードは持たない。
 * - 対象ノードは、攻撃者 → 攻撃目標の経路上のノード（buildTestPlan と同じ決め方）。
 *   経路が 1 本も無い図では全ノードを対象にし、優先度は付けない。
 * - 「調べられない恐れ」は、型が宣言している posture グループ（コンポーネントライブラリ）と
 *   ノードの posture 入力から決める。
 */

export interface InvestigationPlanInput {
  threats: ThreatView[];
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  projectMeta: ProjectMeta;
  layer: LayerKey;
}

export type InvestigationTool = 'velociraptor';

export type InvestigationLimitationCode =
  | 'logNotCollected'
  | 'logCollectionUnset'
  | 'logRetentionShort'
  | 'logRetentionUnset'
  | 'logNotModelable';

export interface InvestigationLimitation {
  code: InvestigationLimitationCode;
}

export interface InvestigationViewpointEntry {
  id: string;
  title: string;
  checks: string[];
  logs: string[];
  /** この観点に当たる脅威の名前（同じノード内）。 */
  threatNames: string[];
  /** リスク受容済みの脅威による当たり（調査は「起きたか」を確かめるので除外しない）。 */
  accepted: { threat: string; note: string }[];
  /** `tool` 指定時だけ入る。 */
  toolSteps?: InvestigationToolStep[];
}

export interface InvestigationNode {
  /** ElementalID（例: C3）。 */
  id: string;
  label: string;
  type: string;
  /** 攻撃経路に載る本数。経路が無い図（全ノード対象）では null。 */
  routeHits: number | null;
  viewpoints: InvestigationViewpointEntry[];
  limitations: InvestigationLimitation[];
}

export interface InvestigationPlan {
  locale: Locale;
  product: string;
  system: string;
  layer: LayerKey;
  /** 生成日（YYYY-MM-DD）。 */
  generatedAt: string;
  tool: InvestigationTool | null;
  /** true: 攻撃経路上のノードに絞った。false: 経路が無いので全ノード（優先度なし）。 */
  pathBased: boolean;
  nodes: InvestigationNode[];
}

export function buildInvestigationPlan(
  input: InvestigationPlanInput,
  now: Date,
  locale: Locale = getLocale(),
  tool: InvestigationTool | null = null,
): InvestigationPlan {
  const viewpointByCanonical = new Map<string, InvestigationViewpoint>();
  for (const v of getInvestigationViewpoints(locale)) for (const c of v.match.canonicalIds) viewpointByCanonical.set(c, v);

  const nodeById = new Map(input.nodes.map((n) => [n.id, n]));
  const isAttacker = (n: DiagramNode) => ATTACK_OBJECTIVE_APPLICABLE.has(n.type);

  // ── 攻撃経路上のノードと、載る経路の本数 ──
  const evidence = buildHopEvidence(input.threats);
  const getEvidence = (key: string) => evidence.get(key) ?? NEUTRAL_EVIDENCE;
  const hits = new Map<string, number>();
  for (const attacker of input.nodes) {
    if (!isAttacker(attacker) || !attacker.attackObjectiveId) continue;
    const target = nodeById.get(attacker.attackObjectiveId);
    if (!target) continue;
    const analysis = analyzeAttackGraph(buildAttackGraph(input.nodes, input.edges, attacker.id, target.id), getEvidence);
    for (const r of analysis.routes) {
      for (const id of new Set(r.route.nodeIds)) hits.set(id, (hits.get(id) ?? 0) + 1);
    }
  }
  // 攻撃者ノード自身は調査の対象にしない。
  for (const id of [...hits.keys()]) {
    const n = nodeById.get(id);
    if (!n || isAttacker(n)) hits.delete(id);
  }
  const pathBased = hits.size > 0;
  const targets = pathBased ? input.nodes.filter((n) => hits.has(n.id)) : input.nodes.filter((n) => !isAttacker(n));

  // ── ノードごとの観点（検出された脅威の canonicalId で引く。誤検知は除く）──
  const viewpointsByNode = new Map<string, InvestigationViewpointEntry[]>();
  for (const t of input.threats) {
    // 誤検知は当たらないので除く。リスク受容は「防ぐ費用をかけない」判断にすぎないので含める。
    if (t.suppression?.status === 'false-positive' || (t.subject && t.subject.kind !== 'node') || !t.canonicalId) continue;
    const vp = viewpointByCanonical.get(t.canonicalId);
    if (!vp) continue;
    const nodeId = t.subject?.id ?? t.nodeId;
    const list = viewpointsByNode.get(nodeId) ?? [];
    const name = t.name ?? t.category;
    const existing = list.find((v) => v.id === vp.id);
    const acceptedNote = t.suppression?.status === 'accepted' ? { threat: name, note: t.suppression.note?.trim() ?? '' } : null;
    if (existing) {
      existing.threatNames.push(name);
      if (acceptedNote) existing.accepted.push(acceptedNote);
    } else {
      list.push({
        id: vp.id,
        title: vp.title,
        checks: [...vp.checks],
        logs: [...vp.logs],
        threatNames: [name],
        accepted: acceptedNote ? [acceptedNote] : [],
        ...(tool && vp.tools?.[tool] ? { toolSteps: vp.tools[tool].map((s) => ({ ...s })) } : {}),
      });
    }
    viewpointsByNode.set(nodeId, list);
  }

  const limitationsOf = (n: DiagramNode): InvestigationLimitation[] => {
    const groups = componentRegistry.getPostureGroups(n.type);
    const hasLog = groups.includes('log');
    const hasRetention = hasLog || groups.includes('logRetention');
    if (!hasRetention) return [{ code: 'logNotModelable' }];
    const out: InvestigationLimitation[] = [];
    if (hasLog) {
      const v = n.posture?.logCollection as string | undefined;
      if (v === 'NotCollected') out.push({ code: 'logNotCollected' });
      else if (v !== 'Collected') out.push({ code: 'logCollectionUnset' });
    }
    const r = n.posture?.logRetention as string | undefined;
    if (r === 'Under90Days') out.push({ code: 'logRetentionShort' });
    else if (r !== 'Under1Year' && r !== 'OneYearOrMore') out.push({ code: 'logRetentionUnset' });
    return out;
  };

  const nodes: InvestigationNode[] = targets.map((n) => ({
    id: n.seq != null ? formatElementalId('node', n.seq) : n.id,
    label: getNodeDisplayName(n),
    type: n.type,
    routeHits: pathBased ? (hits.get(n.id) ?? 0) : null,
    viewpoints: viewpointsByNode.get(n.id) ?? [],
    limitations: limitationsOf(n),
  }));
  // 通る経路の多いノードから。同数は ElementalID の番号順。
  nodes.sort((a, b) => (b.routeHits ?? 0) - (a.routeHits ?? 0) || a.id.localeCompare(b.id, undefined, { numeric: true }));

  return {
    locale,
    product: BRANDING.name,
    system: input.projectMeta.systemName.trim() || input.projectMeta.name.trim() || BRANDING.name,
    layer: input.layer,
    // 文書に載せる日付なので、UTC ではなく実行環境の日付にする。
    generatedAt: `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`,
    tool,
    pathBased,
    nodes,
  };
}
