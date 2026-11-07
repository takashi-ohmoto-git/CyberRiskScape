import type {
  Asset,
  BomComponent,
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  Finding,
  LayerKey,
  Severity,
  ThreatView,
} from '../../core/model/types';
import { isSuppressed } from '../../core/model/types';
import { effectiveSeverity } from '../../core/model/risk';
import { formatElementalId } from '../../core/model/elementalId';
import { resolveNodeBoundaries } from '../../core/canvas/boundaryCrossing';
import {
  prioritizeFindings,
  type FindingExposure,
  type FindingPriority,
  type LayerContext,
} from './prioritizeFindings';

/**
 * 文脈の照会（候補 J+Y）：アラートの IP・FQDN・ホスト名・purl から、図のノード・前段・脅威・指摘・露出を引く。
 * 読み取り専用の純粋関数。露出と優先度は prioritizeFindings の結果を使う（グラフ処理は複製しない）。
 * 優先度は推奨であり、悪用できるとは言わない。
 */

export interface ContextQuery {
  ip?: string;
  host?: string;
  purl?: string;
}

export interface ContextInput {
  layers: readonly LayerContext[];
  assets: readonly Asset[] | undefined;
  bomComponents: readonly BomComponent[] | undefined;
  findings: readonly Finding[] | undefined;
  /** 攻撃者のノード id。無ければ各レイヤーの先頭の攻撃者ノード。 */
  attackerId?: string;
}

export type ContextMatchedBy = 'asset' | 'bomComponent' | 'nodeLabel';

/** 前段として数えるコンポーネント型（data/component-library に存在するもの）。 */
export const FRONT_DOOR_TYPES: ReadonlySet<string> = new Set(['REVERSE_PROXY', 'GATEWAY', 'CDN', 'WAF', 'LOAD_BALANCER']);

export interface ContextNodeRef {
  layer: LayerKey;
  nodeId: string;
  elementalId: string;
  name: string;
  type: string;
}

export interface ContextFinding {
  id: string;
  title: string | null;
  product: string;
  severity: Severity;
  priority: FindingPriority;
  exposure: FindingExposure;
  exposureAssumed: boolean;
  kev: boolean;
  reachesTargets: { name: string; hops: number }[];
  /** この指摘を含む連鎖の件数。 */
  chainCount: number;
}

export interface ContextThreat {
  id: string;
  name: string;
  effectiveSeverity: Severity;
  suppressed: boolean;
  canonicalId: string | null;
}

export interface ContextMatch {
  matchedBy: ContextMatchedBy;
  /** 一致した記録の要約。 */
  record: Record<string, unknown>;
  bound: boolean;
  /** bound:false のときの理由。 */
  note?: string;
  node?: ContextNodeRef & { boundaries: { label: string; trustLevel: string }[] };
  frontDoors?: ContextNodeRef[];
  threats?: ContextThreat[];
  findings?: ContextFinding[];
  exposure?: { value: FindingExposure; assumed: boolean; reachesTargets: { name: string; hops: number }[] };
}

export interface ContextResult {
  query: ContextQuery;
  /** 露出の評価に使った攻撃者が図に無い。 */
  noAttacker: boolean;
  truncated: boolean;
  matches: ContextMatch[];
}

const MAX_MATCHES = 20;
const MAX_ITEMS = 50;
const SEVERITY_RANK: Record<Severity, number> = { Low: 0, Medium: 1, High: 2, Critical: 3 };

const eqi = (a: string | undefined, b: string) => a !== undefined && a.toLowerCase() === b.toLowerCase();

/** purl から `@版` を除く（qualifiers `?` と subpath `#` の前の `@` だけを見る）。 */
function purlWithoutVersion(p: string): string {
  const end = p.search(/[?#]/);
  const body = end < 0 ? p : p.slice(0, end);
  const rest = end < 0 ? '' : p.slice(end);
  const at = body.lastIndexOf('@');
  // `pkg:npm/@scope/name` の @ は版ではない（`/` より後ろにある @ だけが版）。
  return at > body.lastIndexOf('/') ? `${body.slice(0, at)}${rest}` : p;
}

function purlMatches(identifier: string, q: string): boolean {
  if (identifier === q) return true;
  const hasVersion = purlWithoutVersion(q) !== q;
  return !hasVersion && purlWithoutVersion(identifier) === q;
}

const nodeName = (n: DiagramNode) => `${n.seq != null ? formatElementalId('node', n.seq) : n.id} ${n.label?.trim() || n.type}`;

function nodeRef(layer: LayerKey, n: DiagramNode): ContextNodeRef {
  return {
    layer,
    nodeId: n.id,
    elementalId: n.seq != null ? formatElementalId('node', n.seq) : n.id,
    name: n.label?.trim() || n.type,
    type: n.type,
  };
}

function boundaryLabel(b: DiagramBoundary): string {
  return b.label?.trim() || b.blastRadiusLabel?.trim() || b.type;
}

/** peer からノードへデータが向かう線か（向きは edge.dataFlow で決める）。 */
function peerSendsToNode(e: DiagramEdge, peerId: string): boolean {
  const flow = e.dataFlow ?? 'outbound';
  if (flow === 'bidirectional') return true;
  return (flow === 'outbound') === (e.source === peerId);
}

function frontDoorsOf(ctx: LayerContext, node: DiagramNode): ContextNodeRef[] {
  const byId = new Map(ctx.nodes.map((n) => [n.id, n]));
  const out = new Map<string, ContextNodeRef>();
  for (const e of ctx.edges) {
    if (e.source === e.target) continue;
    const peerId = e.source === node.id ? e.target : e.target === node.id ? e.source : undefined;
    if (peerId === undefined) continue;
    const peer = byId.get(peerId);
    if (!peer || !FRONT_DOOR_TYPES.has(peer.type) || !peerSendsToNode(e, peerId)) continue;
    out.set(peer.id, nodeRef(ctx.layer, peer));
  }
  return [...out.values()];
}

export function lookupContext(input: ContextInput, query: ContextQuery): ContextResult {
  const given = [query.ip, query.host, query.purl].filter((v) => v !== undefined && v !== '');
  if (given.length !== 1) throw new Error('ip・host・purl のうち 1 つだけを指定してください。');

  type Raw = { matchedBy: ContextMatchedBy; record: Record<string, unknown>; subject?: { layer: LayerKey; nodeId: string } };
  const raws: Raw[] = [];

  if (query.ip !== undefined || query.host !== undefined) {
    for (const a of input.assets ?? []) {
      const hit =
        query.ip !== undefined
          ? a.ip === query.ip || a.identifiers.some((i) => i.scheme === 'ip' && i.value === query.ip)
          : eqi(a.host, query.host!) ||
            eqi(a.domain, query.host!) ||
            a.identifiers.some((i) => (i.scheme === 'fqdn' || i.scheme === 'hostname') && eqi(i.value, query.host!));
      if (!hit) continue;
      raws.push({
        matchedBy: 'asset',
        record: {
          id: a.id,
          product: a.source.product,
          kind: a.kind,
          host: a.host,
          ...(a.ip ? { ip: a.ip } : {}),
          ...(a.domain ? { domain: a.domain } : {}),
          ...(a.port !== undefined ? { port: a.port } : {}),
          ...(a.serviceName ? { serviceName: a.serviceName } : {}),
        },
        subject: a.subject,
      });
    }
  }
  if (query.host !== undefined) {
    for (const l of input.layers) {
      for (const n of l.nodes) {
        if (!eqi(n.label?.trim(), query.host)) continue;
        raws.push({ matchedBy: 'nodeLabel', record: { label: n.label }, subject: { layer: l.layer, nodeId: n.id } });
      }
    }
  }
  if (query.purl !== undefined) {
    for (const c of input.bomComponents ?? []) {
      if (!c.identifiers.some((i) => i.scheme === 'purl' && purlMatches(i.value, query.purl!))) continue;
      raws.push({
        matchedBy: 'bomComponent',
        record: {
          id: c.id,
          product: c.source.product,
          name: c.name,
          ...(c.version ? { version: c.version } : {}),
          purl: c.identifiers.find((i) => i.scheme === 'purl')?.value,
        },
        subject: c.subject,
      });
    }
  }

  // 結び先のあるノードだけ、露出を別に評価する（仮の指摘を 1 件ずつ結び付けて prioritizeFindings を再利用）。
  const probe = (layer: LayerKey, nodeId: string): Finding => ({
    id: `__probe:${layer}:${nodeId}`,
    source: { format: 'probe', product: 'probe', importedAt: '1970-01-01T00:00:00Z' },
    externalId: nodeId,
    identifiers: [],
    severity: 'Low',
    canonicalIds: [],
    subject: { layer, nodeId },
  } as unknown as Finding);
  const layerOf = new Map(input.layers.map((l) => [l.layer, l]));
  const boundNodes = new Map<string, { layer: LayerKey; nodeId: string }>();
  for (const r of raws) {
    if (r.subject && layerOf.get(r.subject.layer)?.nodes.some((n) => n.id === r.subject!.nodeId)) {
      boundNodes.set(`${r.subject.layer}:${r.subject.nodeId}`, r.subject);
    }
  }
  const exposureResult = prioritizeFindings(
    input.layers,
    [...boundNodes.values()].map((s) => probe(s.layer, s.nodeId)),
    input.attackerId,
  );
  const exposureByNode = new Map(
    exposureResult.items.map((i) => [`${i.layer}:${i.nodeId}`, i] as const),
  );
  const prioritized = prioritizeFindings(input.layers, input.findings ?? [], input.attackerId);

  const matches: ContextMatch[] = [];
  const seen = new Set<string>();
  for (const r of raws) {
    if (matches.length >= MAX_MATCHES) break;
    const dedupeKey = `${r.matchedBy}:${JSON.stringify(r.record)}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    const ctx = r.subject ? layerOf.get(r.subject.layer) : undefined;
    const node = ctx && r.subject ? ctx.nodes.find((n) => n.id === r.subject!.nodeId) : undefined;
    if (!ctx || !node) {
      matches.push({
        matchedBy: r.matchedBy,
        record: r.record,
        bound: false,
        note: r.subject ? '結び付け先のノードが図に見つからない（未結合として扱う）。' : '図のノードに結び付いていない（未結合）。',
      });
      continue;
    }

    const names = new Map(ctx.nodes.map((n) => [n.id, nodeName(n)]));
    const owning = resolveNodeBoundaries(ctx.nodes, ctx.boundaries).get(node.id) ?? [];
    const threats: ContextThreat[] = ctx.threats
      .filter((t: ThreatView) => t.nodeId === node.id)
      .map((t) => ({
        id: t.id,
        name: t.name ?? t.category,
        effectiveSeverity: effectiveSeverity(t),
        suppressed: isSuppressed(t),
        canonicalId: t.canonicalId ?? null,
      }))
      .sort((a, b) => SEVERITY_RANK[b.effectiveSeverity] - SEVERITY_RANK[a.effectiveSeverity])
      .slice(0, MAX_ITEMS);

    const ids = new Set(ctx.nodes.map((n) => n.id));
    const topOf = (id: string) => {
      const n = ctx.nodes.find((x) => x.id === id);
      return n?.parentId && ids.has(n.parentId) ? n.parentId : id;
    };
    const nodeFindings: ContextFinding[] = prioritized.items
      .filter((i) => i.layer === ctx.layer && i.nodeId !== undefined && topOf(i.nodeId) === node.id)
      .slice(0, MAX_ITEMS)
      .map((i) => ({
        id: i.finding.id,
        title: i.finding.title ?? null,
        product: i.finding.source.product,
        severity: i.finding.severity,
        priority: i.priority,
        exposure: i.exposure,
        exposureAssumed: i.exposureAssumed,
        kev: !!i.finding.kev,
        reachesTargets: i.reachesTargets.map((t) => ({ name: names.get(t.nodeId) ?? t.nodeId, hops: t.hops })),
        chainCount: i.chainIndexes.length,
      }));

    const ex = exposureByNode.get(`${ctx.layer}:${node.id}`);
    matches.push({
      matchedBy: r.matchedBy,
      record: r.record,
      bound: true,
      node: { ...nodeRef(ctx.layer, node), boundaries: owning.map((b) => ({ label: boundaryLabel(b), trustLevel: b.trustLevel })) },
      frontDoors: frontDoorsOf(ctx, node),
      threats,
      findings: nodeFindings,
      exposure: {
        value: ex?.exposure ?? 'unevaluated',
        assumed: ex?.exposureAssumed ?? false,
        reachesTargets: (ex?.reachesTargets ?? []).map((t) => ({ name: names.get(t.nodeId) ?? t.nodeId, hops: t.hops })),
      },
    });
  }

  return {
    query,
    noAttacker: Object.keys(exposureResult.attackers).length === 0,
    truncated: raws.length > MAX_MATCHES,
    matches,
  };
}
