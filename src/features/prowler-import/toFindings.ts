import { MAX_FINDINGS, type Finding, type Severity } from '../../core/model/types';
import { lookupNode, type ImportNodeRef } from './applyProwler';
import { resourceLabel, type NormalizedProwlerFinding, type ProwlerResource } from './parseProwlerOcsf';
import { findProwlerMapping, type ProwlerMapping } from './prowlerMap';

/**
 * Prowler の FAIL を共通モデルの指摘（`Finding`）へ変換する純粋関数（docs/architecture.md §8.2・§8.3）。
 * PASS は運用状況（posture）に反映済みなので持たない。MANUAL も持たない。
 * 文字列の長さは `PersistedFindingSchema` の上限に収める。
 */

const PRODUCT = 'Prowler';
const TEXT_MAX = 200;
const EXTERNAL_ID_MAX = 500;

const mask = (s: string): string => s.replace(/\b\d{12}\b/g, '*');

function normalizeSeverity(raw: string | undefined): Severity {
  switch (raw?.toLowerCase()) {
    case 'critical':
      return 'Critical';
    case 'high':
      return 'High';
    case 'medium':
      return 'Medium';
    default:
      return 'Low';
  }
}

export interface ToFindingsInput {
  findings: readonly NormalizedProwlerFinding[];
  map: readonly ProwlerMapping[];
  nodes: readonly ImportNodeRef[];
  nodeMap?: Readonly<Record<string, string>>;
  productVersion?: string;
  /** 取り込み時刻（ISO 8601）。 */
  importedAt: string;
}

function toFinding(
  f: NormalizedProwlerFinding,
  r: ProwlerResource | undefined,
  multi: boolean,
  input: ToFindingsInput,
): Finding {
  const resourceKey = r ? mask(r.uid ?? r.name ?? '') : '';
  const base = f.uid ? mask(f.uid) : `${f.checkId}:${resourceKey}`;
  const externalId = (multi ? `${base}#${resourceKey}` : base).slice(0, EXTERNAL_ID_MAX);

  let subject: Finding['subject'];
  if (r) {
    const nodeMap = input.nodeMap ?? {};
    const ref = r.nodeTag ?? (r.uid ? nodeMap[r.uid] : undefined) ?? (r.name ? nodeMap[r.name] : undefined);
    const found = ref ? lookupNode(input.nodes, ref) : undefined;
    if (found?.kind === 'found') subject = { layer: found.node.layer, nodeId: found.node.id };
  }

  return {
    id: `${PRODUCT}:${externalId}`,
    source: {
      format: 'ocsf',
      product: PRODUCT,
      ...(input.productVersion ? { productVersion: input.productVersion.slice(0, 50) } : {}),
      importedAt: input.importedAt.slice(0, 40),
    },
    externalId,
    identifiers: [{ scheme: 'prowler-check', value: f.checkId.slice(0, TEXT_MAX) }],
    ...(f.title ? { title: f.title.slice(0, TEXT_MAX) } : {}),
    severity: normalizeSeverity(f.severity),
    ...(f.severity ? { sourceSeverity: f.severity.slice(0, 50) } : {}),
    canonicalIds: [...(findProwlerMapping(input.map, f.checkId)?.canonicalIds ?? [])].slice(0, 20),
    ...(subject ? { subject } : {}),
    ...(r
      ? {
          resource: {
            label: resourceLabel(r).slice(0, TEXT_MAX),
            ...(r.type ? { type: r.type.slice(0, TEXT_MAX) } : {}),
            ...(r.region ? { region: r.region.slice(0, 50) } : {}),
          },
        }
      : {}),
    ...(f.observedAt ? { observedAt: f.observedAt.slice(0, 40) } : {}),
  };
}

export function toFindings(input: ToFindingsInput): { findings: Finding[]; truncated: number } {
  const seen = new Set<string>();
  /** 検査 × 製品側 ID × 資源の組（まったく同じ指摘の重複を除く）。 */
  const seenExact = new Set<string>();
  const out: Finding[] = [];
  for (const f of input.findings) {
    if (f.status !== 'FAIL') continue;
    const targets: (ProwlerResource | undefined)[] = f.resources.length > 0 ? f.resources : [undefined];
    for (const r of targets) {
      const exact = JSON.stringify([f.checkId, f.uid ?? '', r?.uid ?? '', r?.name ?? '']);
      if (seenExact.has(exact)) continue;
      seenExact.add(exact);
      let finding = toFinding(f, r, f.resources.length > 1, input);
      // 製品側の ID が別の資源と重なったら、資源で区別して残す（黙って捨てない）
      if (seen.has(finding.id) && r) finding = toFinding(f, r, true, input);
      if (seen.has(finding.id)) continue;
      seen.add(finding.id);
      out.push(finding);
    }
  }
  const truncated = Math.max(0, out.length - MAX_FINDINGS);
  return { findings: truncated > 0 ? out.slice(0, MAX_FINDINGS) : out, truncated };
}

export interface FindingsDiff {
  added: number;
  resolved: number;
  continued: number;
}

/** 同じ製品の指摘を丸ごと置き換える（スナップショット）。他製品の指摘は触らない。 */
export function replaceFindings(
  existing: readonly Finding[] | undefined,
  incoming: readonly Finding[],
  product: string,
): { findings: Finding[]; diff: FindingsDiff } {
  const prev = (existing ?? []).filter((f) => f.source.product === product);
  const prevIds = new Set(prev.map((f) => f.id));
  const nextIds = new Set(incoming.map((f) => f.id));
  const continued = [...nextIds].filter((id) => prevIds.has(id)).length;
  return {
    findings: [...(existing ?? []).filter((f) => f.source.product !== product), ...incoming],
    diff: { added: nextIds.size - continued, resolved: prevIds.size - continued, continued },
  };
}
