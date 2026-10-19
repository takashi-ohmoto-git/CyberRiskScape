import { SUPPRESSING_STATUSES } from '../../core/model/types';
import type { ControlStatusValue, LayerKey, Severity, SuppressionStatus } from '../../core/model/types';
import type { FindingMapping } from './findingMap';
import { cweToCanonicalIds } from './findingMap';
import type { NormalizedFinding } from './parseVeracode';

/**
 * Veracode の指摘と、構成図から検出した脅威を canonicalId で突き合わせる純粋関数。
 *   confirmed  : 構成図の脅威で、対応する指摘（未解決）もあるもの＝コードで確認された
 *   notInModel : 対応づけできた指摘だが、構成図に該当する脅威が無いもの＝構成図の描き漏れ候補
 *   unmapped   : CWE が無い／対応表に無い指摘
 *   priority   : confirmed に当たる指摘を、構成図側の重大度 → Veracode の重大度の順に並べた上位
 */

export const PRIORITY_LIMIT = 20;

/** 突き合わせに使う、構成図側の脅威 1 件分。 */
export interface ModelThreat {
  layer: LayerKey;
  ruleId?: string;
  canonicalId?: string;
  name: string;
  severity: Severity;
  /** 対象要素の表示文字列（ElementalID ＋名前）。 */
  asset: string;
  /** 記録済みのリスク対応方針。受容・誤検知でも「検出済み」として数え、指摘と食い違うことを示す。 */
  riskTreatment?: SuppressionStatus;
  /** 記録済みの対策実装状況。 */
  controlStatus?: ControlStatusValue;
}

export interface FindingGroup {
  count: number;
  maxSeverity: number;
  findings: NormalizedFinding[];
}

export interface ConfirmedEntry {
  canonicalId: string;
  modelThreats: ModelThreat[];
  findings: FindingGroup;
}

export interface NotInModelEntry {
  canonicalId: string;
  findings: FindingGroup;
}

export interface UnmappedEntry {
  /** CWE 番号。CWE 無しの指摘は undefined。 */
  cwe?: number;
  cweName?: string;
  capec: string[];
  findings: FindingGroup;
}

export interface PriorityEntry {
  finding: NormalizedFinding;
  /** 当たった（構成図にも存在する）canonicalId。 */
  canonicalIds: string[];
  modelSeverity: Severity;
}

export interface FindingsReport {
  summary: {
    openFindings: number;
    confirmedFindings: number;
    notInModelFindings: number;
    unmappedFindings: number;
    confirmedThreats: number;
    excludedSca: number;
    excludedClosed: number;
  };
  confirmed: ConfirmedEntry[];
  notInModel: NotInModelEntry[];
  unmapped: UnmappedEntry[];
  priority: PriorityEntry[];
}

export interface BuildFindingsReportInput {
  findings: NormalizedFinding[];
  threats: ModelThreat[];
  excluded: { sca: number; closed: number };
  map: readonly FindingMapping[];
}

const SEVERITY_RANK: Record<Severity, number> = { Low: 1, Medium: 2, High: 3, Critical: 4 };

function group(findings: NormalizedFinding[]): FindingGroup {
  return {
    count: findings.length,
    maxSeverity: Math.max(0, ...findings.map((f) => f.severity)),
    findings: [...findings].sort(compareFindings),
  };
}

/** Veracode の重大度が高い順、同順位は id 順。 */
function compareFindings(a: NormalizedFinding, b: NormalizedFinding): number {
  return b.severity - a.severity || a.id.localeCompare(b.id);
}

function pushTo<K, V>(m: Map<K, V[]>, key: K, value: V): void {
  const list = m.get(key);
  if (list) list.push(value);
  else m.set(key, [value]);
}

function maxModelRank(threats: readonly ModelThreat[]): number {
  return Math.max(0, ...threats.map((t) => SEVERITY_RANK[t.severity]));
}

export function buildFindingsReport(input: BuildFindingsReportInput): FindingsReport {
  const open = input.findings.filter((f) => f.status === 'open');

  const threatsByCanonical = new Map<string, ModelThreat[]>();
  for (const t of input.threats) {
    if (t.canonicalId) pushTo(threatsByCanonical, t.canonicalId, t);
  }

  const confirmedFindings = new Map<string, NormalizedFinding[]>();
  const notInModelFindings = new Map<string, NormalizedFinding[]>();
  const unmappedByCwe = new Map<number | undefined, NormalizedFinding[]>();
  const priorityRaw: PriorityEntry[] = [];
  const counted = { confirmed: 0, notInModel: 0, unmapped: 0 };

  for (const f of open) {
    const ids = f.cwe !== undefined ? cweToCanonicalIds(input.map, f.cwe) : undefined;
    if (!ids) {
      pushTo(unmappedByCwe, f.cwe, f);
      counted.unmapped += 1;
      continue;
    }
    const hit = ids.filter((id) => threatsByCanonical.has(id));
    if (hit.length === 0) {
      for (const id of ids) pushTo(notInModelFindings, id, f);
      counted.notInModel += 1;
      continue;
    }
    for (const id of hit) pushTo(confirmedFindings, id, f);
    counted.confirmed += 1;
    const rank = maxModelRank(hit.flatMap((id) => threatsByCanonical.get(id) ?? []));
    const modelSeverity = (Object.keys(SEVERITY_RANK) as Severity[]).find((s) => SEVERITY_RANK[s] === rank) ?? 'Low';
    priorityRaw.push({ finding: f, canonicalIds: hit, modelSeverity });
  }

  const confirmed: ConfirmedEntry[] = [...confirmedFindings.entries()]
    .map(([canonicalId, fs]) => ({
      canonicalId,
      modelThreats: threatsByCanonical.get(canonicalId) ?? [],
      findings: group(fs),
    }))
    .sort(
      (a, b) =>
        maxModelRank(b.modelThreats) - maxModelRank(a.modelThreats) ||
        b.findings.maxSeverity - a.findings.maxSeverity ||
        a.canonicalId.localeCompare(b.canonicalId),
    );

  const notInModel: NotInModelEntry[] = [...notInModelFindings.entries()]
    .map(([canonicalId, fs]) => ({ canonicalId, findings: group(fs) }))
    .sort((a, b) => b.findings.maxSeverity - a.findings.maxSeverity || a.canonicalId.localeCompare(b.canonicalId));

  const unmapped: UnmappedEntry[] = [...unmappedByCwe.entries()]
    .map(([cwe, fs]) => ({
      cwe,
      cweName: fs.find((f) => f.cweName)?.cweName,
      capec: [...new Set(fs.flatMap((f) => (f.capec ? [f.capec] : [])))].sort(),
      findings: group(fs),
    }))
    .sort(
      (a, b) =>
        b.findings.maxSeverity - a.findings.maxSeverity ||
        b.findings.count - a.findings.count ||
        (a.cwe ?? 1e9) - (b.cwe ?? 1e9),
    );

  const priority = priorityRaw
    .sort(
      (a, b) =>
        SEVERITY_RANK[b.modelSeverity] - SEVERITY_RANK[a.modelSeverity] || compareFindings(a.finding, b.finding),
    )
    .slice(0, PRIORITY_LIMIT);

  return {
    summary: {
      openFindings: open.length,
      confirmedFindings: counted.confirmed,
      notInModelFindings: counted.notInModel,
      unmappedFindings: counted.unmapped,
      confirmedThreats: confirmed.reduce((n, c) => n + c.modelThreats.length, 0),
      excludedSca: input.excluded.sca,
      excludedClosed: input.excluded.closed,
    },
    confirmed,
    notInModel,
    unmapped,
    priority,
  };
}

/**
 * `--fail-on` のゲート判定。未解決の指摘のうち「構成図の脅威と一致」したものについて、
 * 一致した脅威のうち未抑制（受容・誤検知でない）のものの最大重大度が failOn 以上なら違反。
 * 優先リスト（上位 20 件）ではなく、一致した全指摘を対象にする。
 */
export function evaluateFindingsGate(input: BuildFindingsReportInput, failOn: Severity): NormalizedFinding[] {
  const byCanonical = new Map<string, ModelThreat[]>();
  for (const t of input.threats) {
    if (t.canonicalId && !(t.riskTreatment && SUPPRESSING_STATUSES.includes(t.riskTreatment))) {
      pushTo(byCanonical, t.canonicalId, t);
    }
  }
  const offenders: NormalizedFinding[] = [];
  for (const f of input.findings) {
    if (f.status !== 'open' || f.cwe === undefined) continue;
    const ids = cweToCanonicalIds(input.map, f.cwe);
    if (!ids) continue;
    const rank = maxModelRank(ids.flatMap((id) => byCanonical.get(id) ?? []));
    if (rank >= SEVERITY_RANK[failOn]) offenders.push(f);
  }
  return offenders.sort(compareFindings);
}
