import { MAX_FINDINGS, type Finding, type FindingIdentifier } from '../../core/model/types';
import { normalizeSeverity } from '../findings-import/replaceFindings';
import { resolveHost, type HostResolution, type ImportNodeRef } from '../findings-import/resolveNode';
import type { ScapCounts, ScapFormat, ScapHost } from './parseScap';
import { xccdfRuleToCanonicalIds, type XccdfMap } from './xccdfMap';

/**
 * 正規化した SCAP の結果を共通モデルの指摘（`Finding`）へ変換する純粋関数（docs/architecture.md §8.6）。
 * 持つのは XCCDF の fail と、OVAL の vulnerability/patch の true だけ。ARF では XCCDF の check が
 * 参照する OVAL 定義は二重に数えない。文字列は `PersistedFindingSchema` の上限に収める。
 */

const TEXT_MAX = 200;
const EXTERNAL_ID_MAX = 500;

export interface ScapToFindingsInput {
  format: ScapFormat;
  hosts: readonly ScapHost[];
  map: XccdfMap;
  nodes: readonly ImportNodeRef[];
  /** `--map`：ホスト名・FQDN・IP → ノード ID（または C 番号）。 */
  nodeMap?: Readonly<Record<string, string>>;
  /** `--node`：ファイル内のすべてのホストに適用（最優先）。 */
  nodeRef?: string;
  importedAt: string;
}

export interface HostConversion {
  host: ScapHost;
  resolution: HostResolution;
  findings: Finding[];
  /** 上限で保存しなかった件数。 */
  truncated: number;
  counts: ScapCounts;
  /** FAIL（XCCDF）または true（OVAL）だが canonicalId の対応が無いもの。 */
  unmapped: { kind: 'xccdf-rule' | 'oval-def'; id: string; severity?: string; title?: string }[];
}

export interface ScapConversion {
  findings: Finding[];
  truncated: number;
  perHost: HostConversion[];
  /** ノードに結びつかなかったホストの scope。 */
  unlinkedHosts: string[];
}

const cut = (s: string, n = TEXT_MAX): string => s.slice(0, n);

function convertHost(
  host: ScapHost,
  resolution: HostResolution,
  input: ScapToFindingsInput,
): { findings: Finding[]; unmapped: HostConversion['unmapped'] } {
  const source = {
    format: input.format,
    product: host.product,
    ...(host.productVersion ? { productVersion: host.productVersion } : {}),
    scope: cut(host.scope),
    importedAt: input.importedAt.slice(0, 40),
  };
  const subject = resolution.kind === 'found' ? { layer: resolution.node.layer, nodeId: resolution.node.id } : undefined;
  const common = {
    source,
    ...(subject ? { subject } : {}),
    resource: { label: cut(host.scope), type: 'host' },
    ...(host.observedAt ? { observedAt: host.observedAt.slice(0, 40) } : {}),
  };
  const seen = new Set<string>();
  const findings: Finding[] = [];
  const unmapped: HostConversion['unmapped'] = [];
  const push = (f: Finding) => {
    if (seen.has(f.id)) return;
    seen.add(f.id);
    findings.push(f);
  };

  for (const x of host.xccdfFails) {
    const canonicalIds = xccdfRuleToCanonicalIds(input.map, x.idref);
    if (canonicalIds.length === 0) {
      unmapped.push({ kind: 'xccdf-rule', id: x.idref, severity: x.severity, title: x.title });
    }
    const identifiers: FindingIdentifier[] = [{ scheme: 'xccdf-rule', value: cut(x.idref) }];
    for (const i of x.idents) {
      const sys = i.system.toLowerCase();
      if (sys.includes('cce')) identifiers.push({ scheme: 'cce', value: i.value });
      else if (sys.includes('cve')) identifiers.push({ scheme: 'cve', value: i.value });
    }
    for (const o of x.ovalRefs) identifiers.push({ scheme: 'oval-def', value: o });
    const externalId = cut(`${host.scope}:${x.idref}`, EXTERNAL_ID_MAX);
    push({
      id: `${host.product}:${externalId}`,
      ...common,
      externalId,
      identifiers: identifiers.slice(0, 20),
      title: cut(x.title ?? x.idref),
      severity: normalizeSeverity(x.severity),
      ...(x.severity ? { sourceSeverity: cut(x.severity, 50) } : {}),
      canonicalIds: canonicalIds.slice(0, 20),
    });
  }

  const referenced = new Set(host.xccdfOvalRefs);
  for (const o of host.ovalTrue) {
    if (input.format === 'arf' && referenced.has(o.definitionId)) continue;
    const canonicalIds = input.map.ovalClasses[o.class] ?? [];
    if (canonicalIds.length === 0) {
      unmapped.push({ kind: 'oval-def', id: o.definitionId, severity: o.severity, title: o.title });
    }
    const externalId = cut(`${host.scope}:${o.definitionId}`, EXTERNAL_ID_MAX);
    push({
      id: `${host.product}:${externalId}`,
      ...common,
      externalId,
      identifiers: [
        { scheme: 'oval-def', value: cut(o.definitionId) },
        ...o.cves.map((c) => ({ scheme: 'cve', value: c })),
      ].slice(0, 20),
      title: cut(o.title ?? o.definitionId),
      severity: normalizeSeverity(o.severity),
      ...(o.severity ? { sourceSeverity: cut(o.severity, 50) } : {}),
      canonicalIds: [...canonicalIds].slice(0, 20),
    });
  }
  return { findings, unmapped };
}

export function scapToFindings(input: ScapToFindingsInput): ScapConversion {
  let budget = MAX_FINDINGS;
  let truncatedTotal = 0;
  const perHost: HostConversion[] = [];
  const unlinkedHosts: string[] = [];
  const all: Finding[] = [];
  for (const host of input.hosts) {
    const resolution = resolveHost(
      input.nodes,
      { hostnames: host.hostnames, fqdns: host.fqdns, ips: host.ips },
      input.nodeMap,
      input.nodeRef,
    );
    if (resolution.kind === 'unlinked') unlinkedHosts.push(host.scope);
    const { findings, unmapped } = convertHost(host, resolution, input);
    const kept = findings.slice(0, budget);
    budget -= kept.length;
    const truncated = findings.length - kept.length;
    truncatedTotal += truncated;
    all.push(...kept);
    perHost.push({ host, resolution, findings: kept, truncated, counts: host.counts, unmapped });
  }
  return { findings: all, truncated: truncatedTotal, perHost, unlinkedHosts };
}
