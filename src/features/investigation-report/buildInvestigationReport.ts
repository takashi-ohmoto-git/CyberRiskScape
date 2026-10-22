import { z } from 'zod';
import { formatElementalId } from '../../core/model/elementalId';
import { formatLocalDate } from '../../core/model/localDate';
import type { DiagramNode, LayerKey } from '../../core/model/types';
import { getLocale, type Locale } from '../../i18n';
import {
  buildInvestigationPlan,
  type InvestigationLimitation,
  type InvestigationPlanInput,
} from '../investigation-plan/buildInvestigationPlan';
import { clip, type EvidenceCount, type HostEvidence, type ObservedPeriod } from './evidence';

/**
 * 集めた証拠（トリアージ JSON・Velociraptor の収集結果）を脅威モデルのノードに重ね、ノードごとに
 * 「痕跡あり／否定できない／未調査／痕跡なし」を報告する純粋関数。侵害の有無は判定しない。
 *
 * - 対象ノードと「調べられない恐れ」は `buildInvestigationPlan`（調査計画）をそのまま呼んで得る
 *   （攻撃経路上のノード。経路が無い図では攻撃者以外の全ノード）。ロジックは複製しない。
 * - 痕跡とみなす結果は YAML が決める（`evidence.ts`）。
 */

export type NodeStatus = 'traces-found' | 'not-negatable' | 'not-investigated' | 'no-traces';

/** 重い順。 */
export const STATUS_ORDER: readonly NodeStatus[] = ['traces-found', 'not-negatable', 'not-investigated', 'no-traces'];

export type NotNegatableReason = 'periodUnknown' | 'skipped' | 'noSearch';

export type RetentionValue = 'Under90Days' | 'Under1Year' | 'OneYearOrMore';

export type ReportPeriod =
  | ({ basis: 'observed' } & ObservedPeriod)
  | { basis: 'retention'; to: string; retention: RetentionValue };

export interface HostMapEntry {
  host: string;
  node: string;
}

const HostMapSchema = z.object({
  hosts: z.array(z.object({ host: z.string().min(1), node: z.string().min(1) })).max(10000),
});

export function parseHostMap(raw: unknown): { ok: true; hosts: HostMapEntry[] } | { ok: false; error: string } {
  const r = HostMapSchema.safeParse(raw);
  if (!r.success) {
    const issue = r.error.issues[0];
    return { ok: false, error: clip(issue ? `${issue.path.join('.')}: ${issue.message}` : 'invalid') };
  }
  return { ok: true, hosts: r.data.hosts };
}

export type UnknownHostReason = 'notInHostMap' | 'nodeNotInDiagram' | 'nodeNotInScope';

export interface UnknownHost {
  reason: UnknownHostReason;
  evidence: HostEvidence;
}

export interface ReportNode {
  /** ElementalID（例: C3）。 */
  id: string;
  label: string;
  type: string;
  routeHits: number | null;
  status: NodeStatus;
  period?: ReportPeriod;
  /** status が not-negatable のときの理由。 */
  reasons: NotNegatableReason[];
  limitations: InvestigationLimitation[];
  evidence: HostEvidence[];
}

export interface RejectedInput {
  path: string;
  reason: string;
}

export interface InvestigationReport {
  locale: Locale;
  product: string;
  system: string;
  layer: LayerKey;
  generatedAt: string;
  pathBased: boolean;
  summary: Record<NodeStatus, number> & { evidence: number; unknownHosts: number; rejected: number };
  nodes: ReportNode[];
  unknownHosts: UnknownHost[];
  /** YAML に載っていない artifact（全証拠の合計）。 */
  unmapped: EvidenceCount[];
  /** 読み込めなかった入力。 */
  rejected: RejectedInput[];
}

const isIp = (s: string) => /^[\d.]+$/.test(s) || s.includes(':');
const hostKey = (s: string) => s.trim().toLowerCase();
const firstLabel = (s: string) => (isIp(s) ? s : (s.split('.')[0] ?? s));

/** 大文字小文字を無視し、FQDN の先頭ラベル（web01.example.local → web01）でも一致させる。 */
export function hostsMatch(a: string, b: string): boolean {
  const x = hostKey(a);
  const y = hostKey(b);
  if (!x || !y) return false;
  return x === y || firstLabel(x) === firstLabel(y);
}

const earliest = (xs: string[]) => [...xs].sort()[0];
const latest = (xs: string[]) => [...xs].sort().at(-1);

function nodePeriod(node: DiagramNode, evidence: HostEvidence[]): ReportPeriod | undefined {
  const observed = evidence.filter((e) => e.observed);
  if (observed.length > 0) {
    const from = earliest(observed.map((e) => e.observed!.from))!;
    const to = latest(observed.map((e) => e.observed!.to).filter((x): x is string => !!x));
    return { basis: 'observed', from, ...(to ? { to } : {}) };
  }
  const retention = node.posture?.logRetention as RetentionValue | undefined;
  const collected = latest(evidence.map((e) => e.collectedAt).filter((x): x is string => !!x));
  if (collected && (retention === 'Under90Days' || retention === 'Under1Year' || retention === 'OneYearOrMore')) {
    return { basis: 'retention', to: collected, retention };
  }
  return undefined;
}

export function buildInvestigationReport(
  input: InvestigationPlanInput,
  evidence: HostEvidence[],
  hostMap: HostMapEntry[],
  rejected: RejectedInput[],
  now: Date,
  locale: Locale = getLocale(),
): InvestigationReport {
  const plan = buildInvestigationPlan(input, now, locale, null);
  const elemental = (n: DiagramNode) => (n.seq != null ? formatElementalId('node', n.seq) : n.id);
  const diagramNode = (ref: string): DiagramNode | undefined =>
    input.nodes.find((n) => n.id === ref || elemental(n).toLowerCase() === ref.trim().toLowerCase());

  // 証拠 → ノード（対応表のホスト名で照合）。
  const attached = new Map<string, HostEvidence[]>();
  const unknownHosts: UnknownHost[] = [];
  const inScope = new Set(plan.nodes.map((n) => n.id));
  for (const ev of evidence) {
    const entries = hostMap.filter((h) => hostsMatch(h.host, ev.host));
    if (entries.length === 0) {
      unknownHosts.push({ reason: 'notInHostMap', evidence: ev });
      continue;
    }
    let placed = false;
    let worst: UnknownHostReason = 'nodeNotInDiagram';
    for (const entry of entries) {
      const dn = diagramNode(entry.node);
      if (!dn) continue;
      const id = elemental(dn);
      if (!inScope.has(id)) {
        worst = 'nodeNotInScope';
        continue;
      }
      placed = true;
      const list = attached.get(id) ?? [];
      if (!list.includes(ev)) list.push(ev);
      attached.set(id, list);
    }
    if (!placed) unknownHosts.push({ reason: worst, evidence: ev });
  }

  const nodes: ReportNode[] = plan.nodes.map((pn) => {
    const evs = attached.get(pn.id) ?? [];
    const dn = diagramNode(pn.id)!;
    const reasons: NotNegatableReason[] = [];
    let status: NodeStatus;
    let period: ReportPeriod | undefined;
    if (evs.length === 0) {
      status = 'not-investigated';
    } else if (evs.some((e) => e.traceCount > 0)) {
      status = 'traces-found';
      period = nodePeriod(dn, evs);
    } else {
      period = nodePeriod(dn, evs);
      if (!period) reasons.push('periodUnknown');
      if (evs.some((e) => e.skipped.length > 0)) reasons.push('skipped');
      if (evs.some((e) => !e.searched)) reasons.push('noSearch');
      status = reasons.length > 0 ? 'not-negatable' : 'no-traces';
    }
    return {
      id: pn.id,
      label: pn.label,
      type: pn.type,
      routeHits: pn.routeHits,
      status,
      ...(period ? { period } : {}),
      reasons,
      limitations: pn.limitations,
      evidence: evs,
    };
  });
  // 状態の重い順（同じ状態の中は調査計画の並びのまま）。
  nodes.sort((a, b) => STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status));

  const unmapped = new Map<string, number>();
  for (const e of evidence) for (const u of e.unmapped) unmapped.set(u.name, (unmapped.get(u.name) ?? 0) + u.count);

  const count = (s: NodeStatus) => nodes.filter((n) => n.status === s).length;
  return {
    locale,
    product: plan.product,
    system: plan.system,
    layer: plan.layer,
    generatedAt: formatLocalDate(now),
    pathBased: plan.pathBased,
    summary: {
      'traces-found': count('traces-found'),
      'not-negatable': count('not-negatable'),
      'not-investigated': count('not-investigated'),
      'no-traces': count('no-traces'),
      evidence: evidence.length,
      unknownHosts: unknownHosts.length,
      rejected: rejected.length,
    },
    nodes,
    unknownHosts,
    unmapped: [...unmapped.entries()]
      .map(([name, c]) => ({ name, count: c }))
      .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)),
    rejected,
  };
}
