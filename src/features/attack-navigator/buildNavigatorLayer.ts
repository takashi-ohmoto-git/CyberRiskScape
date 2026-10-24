import {
  ATTACK_OBJECTIVE_APPLICABLE,
  isSuppressed,
  type DiagramEdge,
  type DiagramNode,
  type ProjectMeta,
  type Severity,
  type ThreatView,
} from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import { effectiveSeverity } from '../../core/model/risk';
import { BRANDING } from '../../core/branding';
import { getLocale, translate, type Locale } from '../../i18n';
import { buildAttackGraph } from '../attack-tree/buildAttackGraph';
import { analyzeAttackGraph } from '../attack-tree/analyzeAttackGraph';
import { buildHopEvidence, edgeElementKey, nodeElementKey, NEUTRAL_EVIDENCE } from '../attack-tree/hopEvidence';

/**
 * 脅威モデルの検出脅威から、MITRE ATT&CK Navigator レイヤー（JSON）を組み立てる純粋関数。
 *
 * 狙い：CTEM / BAS / SOC のツールが取り込める「標準の拡張」に載せる（独自形式を発明しない）。
 * 各脅威ルールの references に書かれた ATT&CK / ATLAS の technique へのリンク・表記から ID を取り出し、
 * ATT&CK Enterprise の technique を Navigator レイヤーとして出す。ATLAS（AML.T*）は Enterprise の行列に
 * 無いため、レイヤーの説明文に一覧として添える（ATLAS Navigator は別物のため混ぜない）。
 *
 * 攻撃シナリオ（攻撃者 → 標的）との対応：攻撃経路分析（buildAttackGraph / analyzeAttackGraph。
 * test-plan と同じ呼び出し）の上位経路に載るノード・エッジで発火した脅威の technique に、シナリオ名と
 * チョークポイントを metadata として付ける。攻撃者を指定すると、そのシナリオの上位経路上の脅威だけで
 * レイヤーを作る（BAS で「この経路で模擬すべき technique」を渡す用途）。攻撃手順は含まない。
 *
 * 限界：technique ID は references の自由記述（title / url）から取り出す。ルールが references を持たない、
 * または ATT&CK/ATLAS 以外を参照している場合は拾えない。カバレッジの網羅は保証しない。
 */

/** ATT&CK Enterprise technique ID（例: T1078 / T1078.004）。 */
const ATTACK_RE = /\bT\d{4}(?:\.\d{3})?\b/g;
/** ATLAS technique ID（例: AML.T0051 / AML.T0052.001）。 */
const ATLAS_RE = /\bAML\.T\d{4}(?:\.\d{3})?\b/g;

/** test-plan の攻撃シナリオと同じ本数（上位経路・チョークポイント）。 */
const TOP_ROUTES = 3;
const TOP_CHOKE_POINTS = 3;

const SCORE_BY_SEVERITY: Record<Severity, number> = {
  Low: 25,
  Medium: 50,
  High: 75,
  Critical: 100,
};

const SEV_RANK: Record<Severity, number> = { Low: 1, Medium: 2, High: 3, Critical: 4 };

export interface NavigatorMetadata {
  name: string;
  value: string;
}

export interface NavigatorTechnique {
  techniqueID: string;
  score: number;
  color: string;
  comment: string;
  enabled: boolean;
  metadata?: NavigatorMetadata[];
}

/** MITRE ATT&CK Navigator レイヤー（schema layer v4.5 の必要部分）。 */
export interface NavigatorLayer {
  name: string;
  versions: { attack: string; navigator: string; layer: string };
  domain: 'enterprise-attack';
  description: string;
  techniques: NavigatorTechnique[];
  gradient: { colors: string[]; minValue: number; maxValue: number };
  /** ATLAS（AML.T*）の technique ID。Enterprise 行列に無いため参考として分離して持つ。 */
  atlasTechniques: string[];
  /** 図の攻撃シナリオ数（JSON には出さない）。 */
  scenarioCount: number;
}

export interface NavigatorInput {
  threats: ThreatView[];
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  projectMeta: ProjectMeta;
}

export interface NavigatorOptions {
  /** 指定すると、この攻撃者ノード（id）のシナリオの上位経路上の脅威だけで作る。 */
  attackerNodeId?: string;
}

interface Scenario {
  attackerId: string;
  label: string;
  /** 上位経路に載る要素キー（`node:<id>` / `edge:<id>`。攻撃者自身は除く）。 */
  elementKeys: Set<string>;
  /** チョークポイントの要素キー → 表示ラベル。 */
  chokePoints: Map<string, string>;
}

const elId = (n: DiagramNode) => (n.seq != null ? formatElementalId('node', n.seq) : n.id);
const elLabel = (n: DiagramNode) => `${elId(n)} ${getNodeDisplayName(n)}`.trim();

/** 攻撃者（objective あり）ごとに、上位経路の要素とチョークポイントを集める。 */
function buildScenarios(input: NavigatorInput): Scenario[] {
  const nodeById = new Map(input.nodes.map((n) => [n.id, n]));
  const evidence = buildHopEvidence(input.threats);
  const getEvidence = (key: string) => evidence.get(key) ?? NEUTRAL_EVIDENCE;
  const scenarios: Scenario[] = [];

  for (const attacker of input.nodes) {
    if (!ATTACK_OBJECTIVE_APPLICABLE.has(attacker.type) || !attacker.attackObjectiveId) continue;
    const target = nodeById.get(attacker.attackObjectiveId);
    if (!target) continue;
    const graph = buildAttackGraph(input.nodes, input.edges, attacker.id, target.id);
    const analysis = analyzeAttackGraph(graph, getEvidence);

    const elementKeys = new Set<string>();
    for (const r of analysis.routes.slice(0, TOP_ROUTES)) {
      for (const id of r.route.nodeIds) if (id !== attacker.id) elementKeys.add(nodeElementKey(id));
      for (const hk of r.route.hopKeys) {
        for (const eid of graph.hops.get(hk)?.edgeIds ?? []) elementKeys.add(edgeElementKey(eid));
      }
    }

    const chokePoints = new Map<string, string>();
    for (const c of analysis.chokePoints.slice(0, TOP_CHOKE_POINTS)) {
      if (c.elementKey.startsWith('node:')) {
        const n = nodeById.get(c.elementKey.slice('node:'.length));
        if (n) chokePoints.set(c.elementKey, elLabel(n));
      } else {
        const hop = graph.hops.get(c.elementKey.slice('hop:'.length));
        if (!hop) continue;
        const a = nodeById.get(hop.a);
        const b = nodeById.get(hop.b);
        const label = `${a ? elId(a) : hop.a} – ${b ? elId(b) : hop.b}`;
        for (const eid of hop.edgeIds) chokePoints.set(edgeElementKey(eid), label);
      }
    }

    scenarios.push({
      attackerId: attacker.id,
      label: `${elLabel(attacker)} → ${elLabel(target)}`,
      elementKeys,
      chokePoints,
    });
  }
  return scenarios;
}

/** 脅威の対象要素キー。node / edge 以外（境界など）は攻撃経路に載らないので null。 */
function threatElementKey(t: ThreatView): string | null {
  const kind = t.subject?.kind ?? 'node';
  const id = t.subject?.id ?? t.nodeId;
  if (kind === 'node') return nodeElementKey(id);
  if (kind === 'edge') return edgeElementKey(id);
  return null;
}

function colorForScore(score: number): string {
  if (score >= 100) return '#b10026'; // Critical
  if (score >= 75) return '#e3211c'; // High
  if (score >= 50) return '#fc8d59'; // Medium
  return '#fee08b'; // Low
}

function extract(re: RegExp, text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(re)) out.push(m[0]);
  return out;
}

export function buildNavigatorLayer(
  input: NavigatorInput,
  now: Date,
  locale: Locale = getLocale(),
  options: NavigatorOptions = {},
): NavigatorLayer {
  const t = (key: string, params?: Record<string, string | number>) =>
    translate(key as Parameters<typeof translate>[0], locale, params);

  const allScenarios = buildScenarios(input);
  const selected = options.attackerNodeId
    ? allScenarios.filter((s) => s.attackerId === options.attackerNodeId)
    : undefined;
  // 攻撃者を指定したときは、そのシナリオだけを対応づけの対象にする。
  const scenarios = selected ?? allScenarios;

  // technique ID → { 最大 severity, 脅威名, シナリオ名, チョークポイント }
  const attack = new Map<
    string,
    { sev: Severity; names: Set<string>; scenarios: Set<string>; chokes: Set<string> }
  >();
  const atlas = new Set<string>();

  for (const threat of input.threats) {
    if (isSuppressed(threat)) continue;
    const refs = threat.references ?? [];
    if (refs.length === 0) continue;
    const key = threatElementKey(threat);
    const onScenarios = key ? scenarios.filter((s) => s.elementKeys.has(key)) : [];
    if (selected && onScenarios.length === 0) continue; // 指定シナリオの経路外

    const text = refs.map((r) => `${r.title} ${r.url ?? ''}`).join(' ');
    const sev = effectiveSeverity(threat);
    const name = threat.name ?? threat.category;

    for (const id of extract(ATLAS_RE, text)) atlas.add(id);
    // ATLAS を先に取り除く（AML.T0051 の "T0051" を ATT&CK と誤認しないため）
    const attackText = text.replace(ATLAS_RE, ' ');
    for (const id of extract(ATTACK_RE, attackText)) {
      const cur = attack.get(id) ?? { sev, names: new Set(), scenarios: new Set(), chokes: new Set() };
      if (SEV_RANK[sev] > SEV_RANK[cur.sev]) cur.sev = sev;
      cur.names.add(name);
      for (const s of onScenarios) {
        cur.scenarios.add(s.label);
        const choke = key ? s.chokePoints.get(key) : undefined;
        if (choke) cur.chokes.add(choke);
      }
      attack.set(id, cur);
    }
  }

  const metaScenario = t('navigator.meta.scenario');
  const metaChoke = t('navigator.meta.chokepoint');
  const techniques: NavigatorTechnique[] = [...attack.entries()]
    .map(([techniqueID, v]) => {
      const score = SCORE_BY_SEVERITY[v.sev];
      const metadata: NavigatorMetadata[] = [
        ...[...v.scenarios].map((value) => ({ name: metaScenario, value })),
        ...[...v.chokes].map((value) => ({ name: metaChoke, value })),
      ];
      return {
        techniqueID,
        score,
        color: colorForScore(score),
        comment: [...v.names].join('; '),
        enabled: true,
        ...(metadata.length > 0 ? { metadata } : {}),
      };
    })
    .sort((a, b) => b.score - a.score || a.techniqueID.localeCompare(b.techniqueID));

  const system = input.projectMeta.systemName.trim() || input.projectMeta.name.trim() || BRANDING.name;
  const date = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
  const atlasTechniques = [...atlas].sort();
  const atlasNote =
    atlasTechniques.length > 0 ? ` ${t('navigator.description.atlas', { ids: atlasTechniques.join(', ') })}` : '';
  const scenario = selected?.[0];
  const scenarioNote = scenario ? ` ${t('navigator.description.scenario', { scenario: scenario.label })}` : '';

  return {
    name: scenario
      ? t('navigator.layerNameScenario', { product: BRANDING.name, system, scenario: scenario.label })
      : t('navigator.layerName', { product: BRANDING.name, system }),
    versions: { attack: '15', navigator: '4.9.0', layer: '4.5' },
    domain: 'enterprise-attack',
    description: `${t('navigator.description.main', { system, product: BRANDING.name, date })}${scenarioNote}${atlasNote}`,
    techniques,
    gradient: { colors: ['#fee08b', '#fc8d59', '#e3211c', '#b10026'], minValue: 25, maxValue: 100 },
    atlasTechniques,
    scenarioCount: allScenarios.length,
  };
}

export function navigatorLayerToJson(layer: NavigatorLayer): string {
  // atlasTechniques・scenarioCount は Navigator の標準フィールドではないので JSON からは外す（ATLAS は説明文に残る）。
  const { atlasTechniques: _atlas, scenarioCount: _count, ...standard } = layer;
  void _atlas;
  void _count;
  return JSON.stringify(standard, null, 2);
}
