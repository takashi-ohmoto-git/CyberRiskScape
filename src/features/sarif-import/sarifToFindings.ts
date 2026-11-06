import type { Finding, FindingIdentifier, LayerKey, Severity } from '../../core/model/types';
import { capFindings, normalizeSeverity } from '../findings-import/replaceFindings';
import { cweToCanonicalIds, type FindingMapping } from '../findings-report/findingMap';
import type { SarifResult, SarifRule, SarifRun } from './parseSarif';

/**
 * 汎用の SARIF の結果を共通モデルの指摘（`Finding`）へ変換する純粋関数（docs/architecture.md §8.6）。
 * message の本文・コード片・codeFlows は保存しない。場所は相対的な表記に落とす（利用者名を持ち帰らない）。
 */

const TITLE_MAX = 120;
const LABEL_MAX = 200;
const EXTERNAL_ID_MAX = 500;
const EXCLUDED_KINDS = ['pass', 'notApplicable', 'informational'];

export interface SarifRunReport {
  product: string;
  productVersion?: string;
  results: number;
  stored: number;
  /** 上限（MAX_FINDINGS）で保存しなかった件数。 */
  truncated: number;
  excluded: { suppressed: number; absent: number; kind: number };
  /** CWE を持つが、辞書（data/finding-maps/cwe.yaml）に載っていなかった指摘の数。 */
  cweUnmapped: number;
}

export interface SarifConversion {
  findings: Finding[];
  runs: SarifRunReport[];
}

export interface SarifToFindingsInput {
  runs: readonly SarifRun[];
  map: readonly FindingMapping[];
  scope: string;
  subject?: { layer: LayerKey; nodeId: string };
  importedAt: string;
}

/** uri を相対的な表記に落とす（file://・ドライブ・ホームディレクトリを落とす）。 */
export function scrubUri(uri: string): string {
  let p = uri.trim();
  try {
    p = decodeURIComponent(p);
  } catch {
    // 不正なエスケープはそのまま扱う
  }
  p = p.replace(/\\/g, '/').replace(/^file:\/\/[^/]*/i, '');
  p = p.replace(/^\/?[A-Za-z]:\//, '/');
  p = p.replace(/^\/?(?:home|Users)\/[^/]+\//i, '').replace(/^\/?root\//, '');
  return p.replace(/^\/+/, '');
}

function cweFromText(s: string): number | undefined {
  const m = /cwe[-_/ ]?(\d{1,5})(?!\d)/i.exec(s);
  return m ? Number(m[1]) : undefined;
}

function collectCwes(rule: SarifRule | undefined, result: SarifResult): number[] {
  const out = new Set<number>();
  const add = (n: number | undefined) => {
    if (n !== undefined && n > 0) out.add(n);
  };
  for (const t of [...(rule?.properties?.tags ?? []), ...(result.properties?.tags ?? [])]) add(cweFromText(t));
  for (const d of [...(rule?.relationships ?? []).map((r) => r.target), ...(result.taxa ?? [])]) {
    if (!d?.id) continue;
    const fromText = cweFromText(d.id);
    if (fromText !== undefined) add(fromText);
    else if (/^\d{1,5}$/.test(d.id) && d.toolComponent?.name?.toUpperCase() === 'CWE') add(Number(d.id));
  }
  return [...out];
}

function severityOf(rule: SarifRule | undefined, result: SarifResult): { severity: Severity; source: string } {
  const raw = result.properties?.['security-severity'] ?? rule?.properties?.['security-severity'];
  const score = raw === undefined ? NaN : Number(raw);
  if (Number.isFinite(score)) {
    const severity: Severity = score >= 9 ? 'Critical' : score >= 7 ? 'High' : score >= 4 ? 'Medium' : 'Low';
    return { severity, source: String(raw) };
  }
  const level = result.level ?? rule?.defaultConfiguration?.level ?? 'warning';
  const severity: Severity =
    level === 'error' ? 'High' : level === 'warning' ? 'Medium' : level === 'note' || level === 'none' ? 'Low' : normalizeSeverity(level);
  return { severity, source: level };
}

function exclusionOf(r: SarifResult): 'suppressed' | 'absent' | 'kind' | undefined {
  if (r.suppressions?.some((s) => s.status === undefined || s.status === 'accepted')) return 'suppressed';
  if (r.baselineState === 'absent') return 'absent';
  if (r.kind !== undefined && EXCLUDED_KINDS.includes(r.kind)) return 'kind';
  return undefined;
}

export function sarifToFindings(input: SarifToFindingsInput): SarifConversion {
  const all: Finding[] = [];
  const runs: SarifRunReport[] = [];
  const counts: number[] = [];
  const seen = new Set<string>();
  for (const run of input.runs) {
    const driver = run.tool.driver;
    const product = driver.name.slice(0, 100);
    const productVersion = (driver.semanticVersion ?? driver.version)?.slice(0, 50);
    const rules = driver.rules ?? [];
    const report: SarifRunReport = {
      product,
      ...(productVersion ? { productVersion } : {}),
      results: (run.results ?? []).length,
      stored: 0,
      truncated: 0,
      excluded: { suppressed: 0, absent: 0, kind: 0 },
      cweUnmapped: 0,
    };
    const source = {
      format: 'sarif' as const,
      product,
      ...(productVersion ? { productVersion } : {}),
      scope: input.scope.slice(0, 200),
      importedAt: input.importedAt.slice(0, 40),
    };
    let own = 0;
    for (const r of run.results ?? []) {
      const ex = exclusionOf(r);
      if (ex) {
        report.excluded[ex]++;
        continue;
      }
      const ruleId = r.ruleId ?? r.rule?.id;
      const rule = rules.find((x) => ruleId !== undefined && x.id === ruleId) ?? (r.ruleIndex !== undefined ? rules[r.ruleIndex] : undefined);
      const rid = ruleId ?? rule?.id ?? 'unknown';
      const phys = r.locations?.[0]?.physicalLocation;
      const uri = phys?.artifactLocation?.uri ? scrubUri(phys.artifactLocation.uri) : undefined;
      const line = phys?.region?.startLine;
      const label = uri ? `${uri}${line !== undefined ? `:${line}` : ''}` : undefined;

      const cwes = collectCwes(rule, r);
      const canonicalIds = new Set<string>();
      for (const c of cwes) for (const id of cweToCanonicalIds(input.map, c) ?? []) canonicalIds.add(id);
      if (cwes.length > 0 && canonicalIds.size === 0) report.cweUnmapped++;

      const identifiers: FindingIdentifier[] = [
        { scheme: 'rule', value: rid.slice(0, 200) },
        ...cwes.map((c) => ({ scheme: 'cwe', value: String(c) })),
      ];
      const { severity, source: sourceSeverity } = severityOf(rule, r);
      const fingerprint = r.partialFingerprints ? Object.values(r.partialFingerprints)[0] : undefined;
      const externalId = (fingerprint ?? `${rid}:${uri ?? ''}:${line ?? ''}`).slice(0, EXTERNAL_ID_MAX);
      const id = `${product}:${externalId}`;
      if (seen.has(id)) continue;
      seen.add(id);
      all.push({
        id,
        source,
        externalId,
        identifiers: identifiers.slice(0, 20),
        title: (rule?.shortDescription?.text ?? r.message?.text ?? rid).slice(0, TITLE_MAX),
        severity,
        sourceSeverity: sourceSeverity.slice(0, 50),
        canonicalIds: [...canonicalIds].slice(0, 20),
        ...(input.subject ? { subject: input.subject } : {}),
        ...(label ? { resource: { label: label.slice(0, LABEL_MAX) } } : {}),
      });
      own++;
    }
    runs.push(report);
    counts.push(own);
  }
  const capped = capFindings(all);
  // 上限で切った分は後ろの run から差し引く
  let over = capped.truncated;
  for (let i = runs.length - 1; i >= 0; i--) {
    const cut = Math.min(counts[i], over);
    runs[i].stored = counts[i] - cut;
    runs[i].truncated = cut;
    over -= cut;
  }
  return { findings: capped.findings, runs };
}
