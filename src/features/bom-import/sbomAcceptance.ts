import { LAYER_KEYS, type BomComponent, type DiagramNode, type Finding, type LayerKey, type Severity } from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';
import { componentRegistry } from '../../component-library/defaultRegistry';

/**
 * SBOM の検収レポート（受け取った SBOM が図のどこに結びついているか、新しさ、指摘の件数）の事実の集計。
 * 検収の補助であり、合否・ライセンスの適否は判定しない。設計の背景は docs/research/nco-advisory-2026-11-05.md §3（候補 Z）。
 */

export interface SbomAcceptanceInput {
  layers: { [layer: string]: { nodes: DiagramNode[] } | undefined };
  bomComponents?: readonly BomComponent[];
  findings?: readonly Finding[];
}

export interface SbomAcceptanceOptions {
  now: Date;
  /** 既定 90。 */
  maxAgeDays?: number;
  /** 未結合の部品名を並べる上限（既定 5）。 */
  maxNames?: number;
}

export interface SourceGroup {
  product: string;
  scope: string | null;
  components: number;
  nodes: string[];
  /** 最も古い BOM 作成時刻。 */
  observedAt?: string;
  stale: boolean;
  noTimestamp: boolean;
}

export interface UnboundGroup {
  product: string;
  scope: string | null;
  count: number;
  names: string[];
}

export interface NodeVulnerabilities {
  node: string | null;
  counts: Record<Severity, number>;
  kev: number;
  total: number;
}

export interface SbomAcceptanceResult {
  maxAgeDays: number;
  componentCount: number;
  nodesWithoutSbom: string[];
  unboundComponents: UnboundGroup[];
  perSource: SourceGroup[];
  vulnerabilities: NodeVulnerabilities[];
  licensesMissing: number;
}

const DAY_MS = 86_400_000;

function nodeName(n: DiagramNode): string {
  return `${n.seq != null ? formatElementalId('node', n.seq) : n.id} ${n.label?.trim() || n.type}`;
}

export function sbomAcceptance(input: SbomAcceptanceInput, options: SbomAcceptanceOptions): SbomAcceptanceResult {
  const maxAgeDays = options.maxAgeDays ?? 90;
  const maxNames = options.maxNames ?? 5;
  const comps = (input.bomComponents ?? []).filter((c) => c.source.format === 'cyclonedx' || c.source.format === 'spdx');

  const nodeOf = (subject: { layer: LayerKey; nodeId: string } | undefined) =>
    subject ? input.layers[subject.layer]?.nodes.find((n) => n.id === subject.nodeId) : undefined;

  const boundKeys = new Set<string>();
  const unboundMap = new Map<string, UnboundGroup>();
  const srcMap = new Map<string, SourceGroup & { nodeSet: Set<string>; times: string[] }>();

  for (const c of comps) {
    const node = nodeOf(c.subject);
    const scope = c.source.scope ?? null;
    const key = `${c.source.product}|${scope ?? ''}`;
    if (node) {
      boundKeys.add(`${c.subject!.layer}:${node.id}`);
    } else {
      const g = unboundMap.get(key) ?? { product: c.source.product, scope, count: 0, names: [] };
      g.count++;
      if (g.names.length < maxNames) g.names.push(c.version ? `${c.name}@${c.version}` : c.name);
      unboundMap.set(key, g);
    }
    const s =
      srcMap.get(key) ??
      { product: c.source.product, scope, components: 0, nodes: [], stale: false, noTimestamp: false, nodeSet: new Set<string>(), times: [] };
    s.components++;
    if (node) s.nodeSet.add(nodeName(node));
    if (c.observedAt) s.times.push(c.observedAt);
    else s.noTimestamp = true;
    srcMap.set(key, s);
  }

  const perSource: SourceGroup[] = [...srcMap.values()].map(({ nodeSet, times, ...g }) => {
    const valid = times.filter((t) => !Number.isNaN(Date.parse(t))).sort((a, b) => Date.parse(a) - Date.parse(b));
    const oldest = valid[0];
    return {
      ...g,
      nodes: [...nodeSet],
      ...(oldest ? { observedAt: oldest } : {}),
      stale: oldest ? (options.now.getTime() - Date.parse(oldest)) / DAY_MS > maxAgeDays : false,
      noTimestamp: g.noTimestamp || valid.length < times.length,
    };
  });

  const nodesWithoutSbom: string[] = [];
  for (const layer of LAYER_KEYS) {
    for (const n of input.layers[layer]?.nodes ?? []) {
      const groups = componentRegistry.getPostureGroups(n.type);
      if (!groups.some((g) => g === 'patch' || g === 'dependency')) continue;
      if (!boundKeys.has(`${layer}:${n.id}`)) nodesWithoutSbom.push(nodeName(n));
    }
  }

  const vulnMap = new Map<string, NodeVulnerabilities>();
  for (const f of input.findings ?? []) {
    if (f.source.format !== 'cyclonedx') continue;
    const node = nodeOf(f.subject);
    const key = node ? `${f.subject!.layer}:${node.id}` : '';
    const v = vulnMap.get(key) ?? {
      node: node ? nodeName(node) : null,
      counts: { Critical: 0, High: 0, Medium: 0, Low: 0 },
      kev: 0,
      total: 0,
    };
    v.counts[f.severity]++;
    if (f.kev) v.kev++;
    v.total++;
    vulnMap.set(key, v);
  }
  // 結合済みを先、未結合を最後に並べる。
  const vulnerabilities = [...vulnMap.values()].sort((a, b) => Number(a.node === null) - Number(b.node === null));

  return {
    maxAgeDays,
    componentCount: comps.length,
    nodesWithoutSbom,
    unboundComponents: [...unboundMap.values()],
    perSource,
    vulnerabilities,
    licensesMissing: comps.filter((c) => !c.licenses || c.licenses.length === 0).length,
  };
}
