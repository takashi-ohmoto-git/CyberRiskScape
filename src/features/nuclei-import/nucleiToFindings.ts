import { CVSS_VECTOR_RE, type Finding, type FindingIdentifier, type LayerKey, type Severity } from '../../core/model/types';
import { UNPATCHED_CANONICAL_ID } from '../bom-import/vulnerabilitiesToFindings';
import { capFindings } from '../findings-import/replaceFindings';
import { cweToCanonicalIds, type FindingMapping } from '../findings-report/findingMap';
import type { NucleiResult } from './parseNuclei';

/**
 * Nuclei の結果を共通モデルの指摘（`Finding`）へ変換する純粋関数（docs/architecture.md §8.6）。
 * 要求・応答・curl・抽出値・説明は読まないので保存されない。場所は URL のクエリ・userinfo・フラグメントを落とす。
 * - info と matcher-status=false は保存せず件数だけ数える
 * - CVE を持つ結果は「既知の脆弱性に対するパッチの未適用」だけに対応づける（CWE は識別子としてのみ記録）
 * - CVE が無く CWE を持つ結果は CWE の対応表で脅威に対応づける
 */

const TITLE_MAX = 120;
const LABEL_MAX = 200;
const EXTERNAL_ID_MAX = 500;
const PRODUCT = 'Nuclei';
const PLAIN_LABEL = /^[A-Za-z0-9.\-:[\]_]{1,200}$/;

export interface NucleiReport {
  product: 'Nuclei';
  results: number;
  stored: number;
  /** 上限（MAX_FINDINGS）で保存しなかった件数。 */
  truncated: number;
  /** info の結果（保存しない）。 */
  excludedInfo: number;
  /** matcher-status が false の結果（保存しない）。 */
  excludedNoMatch: number;
  /** CVE を持たず CWE を持つが、辞書に載らず脅威に対応づけられなかった指摘の数。 */
  cweUnmapped: number;
  /** CVE を持つ指摘の数。 */
  withCve: number;
}

export interface NucleiToFindingsInput {
  results: readonly NucleiResult[];
  map: readonly FindingMapping[];
  scope: string;
  subject?: { layer: LayerKey; nodeId: string };
  importedAt: string;
}

/** matched-at（無ければ host）から表示用の場所を作る。http(s) は origin + pathname のみ。 */
export function nucleiLabel(matchedAt: string | undefined, host: string | undefined): string | undefined {
  for (const raw of [matchedAt, host]) {
    const v = raw?.trim();
    if (!v) continue;
    if (/^https?:\/\//i.test(v)) {
      try {
        const u = new URL(v);
        const path = u.pathname === '/' ? '' : u.pathname;
        return `${u.origin}${path}`.slice(0, LABEL_MAX);
      } catch {
        continue;
      }
    }
    if (PLAIN_LABEL.test(v)) return v;
  }
  return undefined;
}

function severityOf(raw: string | undefined): Severity {
  switch (raw?.trim().toLowerCase()) {
    case 'critical':
      return 'Critical';
    case 'high':
      return 'High';
    case 'low':
      return 'Low';
    default:
      return 'Medium';
  }
}

export function nucleiToFindings(input: NucleiToFindingsInput): { findings: Finding[]; report: NucleiReport } {
  const report: NucleiReport = {
    product: PRODUCT,
    results: input.results.length,
    stored: 0,
    truncated: 0,
    excludedInfo: 0,
    excludedNoMatch: 0,
    cweUnmapped: 0,
    withCve: 0,
  };
  const source = { format: 'nuclei' as const, product: PRODUCT, scope: input.scope.slice(0, 200), importedAt: input.importedAt.slice(0, 40) };
  const all: Finding[] = [];
  const seen = new Set<string>();
  for (const r of input.results) {
    if (r['matcher-status'] === false) {
      report.excludedNoMatch++;
      continue;
    }
    const sevRaw = r.info?.severity;
    if (sevRaw?.trim().toLowerCase() === 'info') {
      report.excludedInfo++;
      continue;
    }
    const cls = r.info?.classification;
    const cves = [...new Set((cls?.['cve-id'] ?? []).map((c) => c.trim().toUpperCase()).filter((c) => /^CVE-\d{4}-\d{4,}$/.test(c)))].slice(0, 20);
    const cwes = [
      ...new Set(
        (cls?.['cwe-id'] ?? [])
          .map((c) => /cwe-?(\d{1,5})(?!\d)/i.exec(c)?.[1])
          .filter((n): n is string => n !== undefined)
          .map((n) => String(Number(n)))
          .filter((n) => n !== '0'),
      ),
    ].slice(0, 20);

    let canonicalIds: string[] = [];
    if (cves.length > 0) {
      canonicalIds = [UNPATCHED_CANONICAL_ID];
      report.withCve++;
    } else if (cwes.length > 0) {
      const ids = new Set<string>();
      for (const c of cwes) for (const id of cweToCanonicalIds(input.map, Number(c)) ?? []) ids.add(id);
      canonicalIds = [...ids].slice(0, 20);
      if (canonicalIds.length === 0) report.cweUnmapped++;
    }

    const identifiers: FindingIdentifier[] = [
      { scheme: 'rule', value: r['template-id'].slice(0, 200) },
      ...cves.map((c) => ({ scheme: 'cve', value: c })),
      ...cwes.map((c) => ({ scheme: 'cwe', value: c })),
    ];
    const epss = cls?.['epss-score'];
    if (typeof epss === 'number' && Number.isFinite(epss)) identifiers.push({ scheme: 'epss', value: String(epss) });
    const inUnit = (n: unknown): n is number => typeof n === 'number' && Number.isFinite(n) && n >= 0 && n <= 1;
    const pct = cls?.['epss-percentile'];
    const cvss = cls?.['cvss-metrics']?.trim();

    const label = nucleiLabel(r['matched-at'], r.host);
    const externalId = `${r['template-id']}:${label ?? ''}:${r['matcher-name'] ?? ''}`.slice(0, EXTERNAL_ID_MAX);
    const id = `${PRODUCT}:${externalId}`;
    if (seen.has(id)) continue;
    seen.add(id);
    all.push({
      id,
      source,
      externalId,
      identifiers,
      title: (r.info?.name?.trim() || r['template-id']).slice(0, TITLE_MAX),
      severity: severityOf(sevRaw),
      ...(sevRaw ? { sourceSeverity: sevRaw.slice(0, 50) } : {}),
      canonicalIds,
      ...(inUnit(epss) ? { epss: { score: epss, ...(inUnit(pct) ? { percentile: pct } : {}) } } : {}),
      ...(cvss && CVSS_VECTOR_RE.test(cvss) ? { cvss } : {}),
      ...(input.subject ? { subject: input.subject } : {}),
      ...(label ? { resource: { label } } : {}),
      ...(r.timestamp ? { observedAt: r.timestamp.slice(0, 40) } : {}),
    });
  }
  const capped = capFindings(all);
  report.stored = capped.findings.length;
  report.truncated = capped.truncated;
  return { findings: capped.findings, report };
}
