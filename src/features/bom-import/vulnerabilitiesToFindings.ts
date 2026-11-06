import type { Finding, FindingIdentifier, FindingSource, Severity } from '../../core/model/types';
import { normalizeSeverity } from '../findings-import/replaceFindings';
import type { ParsedBomItem, ParsedVulnerability } from './parseBom';

/**
 * CycloneDX の vulnerabilities（VEX を含む）を、共通モデルの指摘（Finding）に変換する純粋関数
 * （docs/architecture.md §8.2・§8.8）。1 件の脆弱性 × 影響を受ける部品ごとに指摘 1 件。
 *
 * - canonicalIds は常に `known-vulnerability-unpatched` だけ。ライブラリの CVE を CWE の脅威に結ぶと、
 *   アプリ実装の欠陥と誤読されるため CWE は使わない
 * - VEX の analysis.state が not_affected・false_positive・resolved のものは指摘にせず、件数だけ返す
 * - 影響部品（affects）を部品に解決できない脆弱性は、結ぶ先が無いので指摘にせず件数だけ返す
 */

export const UNPATCHED_CANONICAL_ID = 'known-vulnerability-unpatched';

const EXCLUDED_STATES = new Set(['not_affected', 'false_positive', 'resolved']);
const SEVERITY_RANK: Record<Severity, number> = { Low: 0, Medium: 1, High: 2, Critical: 3 };
const TEXT_MAX = 200;

export interface VulnerabilityConversion {
  findings: Finding[];
  /** VEX で除外した件数（脆弱性 × 部品の単位。影響部品が無ければ脆弱性 1 件を 1 と数える）。 */
  excluded: number;
  /** 影響部品を特定できず、指摘にしなかった脆弱性の件数。 */
  withoutAffects: number;
}

function idScheme(id: string, sourceName?: string): string {
  const upper = id.toUpperCase();
  if (upper.startsWith('CVE-')) return 'cve';
  if (upper.startsWith('GHSA-')) return 'ghsa';
  const name = sourceName?.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 50);
  return name || 'vuln';
}

/** ratings の最大。score しか無ければ CVSS の帯で分ける。none・info・unknown は Low。 */
function severityOf(ratings: ParsedVulnerability['ratings']): { severity: Severity; sourceSeverity?: string } {
  let best: { severity: Severity; sourceSeverity?: string } = { severity: 'Low' };
  let bestRank = -1;
  for (const r of ratings) {
    const fromScore = (s: number): Severity => (s >= 9 ? 'Critical' : s >= 7 ? 'High' : s >= 4 ? 'Medium' : 'Low');
    const severity = r.severity ? normalizeSeverity(r.severity) : r.score !== undefined ? fromScore(r.score) : undefined;
    if (!severity || SEVERITY_RANK[severity] <= bestRank) continue;
    bestRank = SEVERITY_RANK[severity];
    const raw = r.severity ?? (r.score !== undefined ? String(r.score) : undefined);
    best = { severity, ...(raw ? { sourceSeverity: raw.slice(0, 50) } : {}) };
  }
  return best;
}

function push(list: FindingIdentifier[], scheme: string, value: string | undefined) {
  if (!value || value.length > TEXT_MAX) return;
  if (!list.some((i) => i.scheme === scheme && i.value === value)) list.push({ scheme, value });
}

export function vulnerabilitiesToFindings(
  vulns: readonly ParsedVulnerability[],
  source: FindingSource,
  subject: Finding['subject'] | undefined,
  observedAt: string | undefined,
): VulnerabilityConversion {
  const byId = new Map<string, Finding>();
  let excluded = 0;
  let withoutAffects = 0;

  for (const v of vulns) {
    if (v.state && EXCLUDED_STATES.has(v.state)) {
      excluded += Math.max(1, v.affects.length);
      continue;
    }
    if (v.affects.length === 0) {
      withoutAffects += 1;
      continue;
    }
    const sev = severityOf(v.ratings);
    for (const part of v.affects as ParsedBomItem[]) {
      const purl = part.identifiers.find((i) => i.scheme === 'purl')?.value;
      const label = `${part.name}${part.version ? `@${part.version}` : ''}`;
      const identifiers: FindingIdentifier[] = [];
      push(identifiers, idScheme(v.id, v.source), v.id);
      for (const r of v.references) push(identifiers, idScheme(r.id, r.source), r.id);
      push(identifiers, 'purl', purl);
      const externalId = `${v.id}:${purl ?? label}`.slice(0, 500);
      const id = `${source.product}:${externalId}`;
      if (byId.has(id)) continue;
      byId.set(id, {
        id,
        source,
        externalId,
        identifiers,
        title: `${v.id} ${label}`.slice(0, TEXT_MAX),
        severity: sev.severity,
        ...(sev.sourceSeverity ? { sourceSeverity: sev.sourceSeverity } : {}),
        canonicalIds: [UNPATCHED_CANONICAL_ID],
        ...(subject ? { subject } : {}),
        ...(observedAt ? { observedAt } : {}),
      });
    }
  }

  // 上限で切るときに重い指摘を残すため、深刻度の高い順（同順位は入力順）に並べる。
  const findings = [...byId.values()].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
  return { findings, excluded, withoutAffects };
}
