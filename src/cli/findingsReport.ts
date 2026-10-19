import type { LayerAnalysisResult } from './analyze';
import type { DiagramBoundary, DiagramEdge, DiagramNode, ElementRef, Severity } from '../core/model/types';
import { formatElementalId } from '../core/model/elementalId';
import { effectiveSeverity } from '../core/model/risk';
import { getLocale, translate } from '../i18n';
import {
  PRIORITY_LIMIT,
  type FindingGroup,
  type FindingsReport,
  type ModelThreat,
} from '../features/findings-report/buildFindingsReport';
import type { NormalizedFinding } from '../features/findings-report/parseVeracode';

/**
 * CLI `findings-report` サブコマンド：Veracode の指摘 × 構成図の脅威の突き合わせ結果を md / json にする。
 * `diff.ts` と同じ設計（`getLocale()` を読む純粋関数。CLI 側で `setLocale` 済みを前提にする）。
 */

/** 一覧表示の上限（md）。JSON は全件出す。 */
const MD_LIST_LIMIT = 10;

function assetLabel(
  subject: ElementRef | undefined,
  nodes: DiagramNode[],
  edges: DiagramEdge[],
  boundaries: DiagramBoundary[],
): string {
  if (!subject) return '';
  if (subject.kind === 'node') {
    const n = nodes.find((x) => x.id === subject.id);
    if (!n) return '';
    return `${n.seq != null ? formatElementalId('node', n.seq) : n.id} ${n.label?.trim() || n.type}`;
  }
  if (subject.kind === 'edge') {
    const e = edges.find((x) => x.id === subject.id);
    if (!e) return '';
    const id = e.seq != null ? formatElementalId('edge', e.seq) : e.id;
    const name = e.dataFlowName?.trim();
    return name ? `${id} ${name}` : id;
  }
  const b = boundaries.find((x) => x.id === subject.id);
  if (!b) return '';
  return `${b.seq != null ? formatElementalId('boundary', b.seq) : b.id} ${b.vlanName?.trim() || b.blastRadiusLabel?.trim() || b.type}`;
}

/** 全レイヤーの検出脅威を、突き合わせ用の形にまとめる。 */
export function collectModelThreats(results: readonly LayerAnalysisResult[]): ModelThreat[] {
  return results.flatMap((r) =>
    r.threats.map((t) => ({
      layer: r.layer,
      ruleId: t.ruleId,
      canonicalId: t.canonicalId,
      name: t.name ?? t.category,
      severity: effectiveSeverity(t),
      asset: assetLabel(t.subject, r.input.nodes, r.input.edges, r.input.boundaries),
      riskTreatment: t.suppression?.status,
      controlStatus: t.controlStatus?.status,
    })),
  );
}

const RISK_TREATMENT_KEYS = {
  avoid: 'threats.riskTreatment.avoid',
  reduce: 'threats.riskTreatment.reduce',
  transfer: 'threats.riskTreatment.transfer',
  accepted: 'threats.riskTreatment.accepted',
  'false-positive': 'threats.riskTreatment.falsePositive',
} as const;

const CONTROL_STATUS_KEYS = {
  implemented: 'threats.controlStatus.implemented',
  required: 'threats.controlStatus.required',
  'not-applicable': 'threats.controlStatus.notApplicable',
  rejected: 'threats.controlStatus.rejected',
} as const;

/** 構成図側で記録済みの判断（対応方針・対策実装状況）。指摘と食い違っていないかを見るために表示する。 */
function recordedDecision(m: ModelThreat): string {
  const locale = getLocale();
  const labels = [
    m.riskTreatment ? translate(RISK_TREATMENT_KEYS[m.riskTreatment], locale) : '',
    m.controlStatus ? translate(CONTROL_STATUS_KEYS[m.controlStatus], locale) : '',
  ].filter((l) => l !== '');
  return labels.length > 0 ? ` ${translate('findingsReport.recorded', locale, { labels: labels.join('・') })}` : '';
}

function findingLine(f: NormalizedFinding): string {
  const cwe = f.cwe !== undefined ? `CWE-${f.cwe}` : '';
  const parts = [`#${f.id}`, `[${f.scanType}]`, `S${f.severity}`, cwe, f.title, f.location ? `(${f.location})` : '']
    .filter((p) => p !== '')
    .join(' ');
  return f.capec ? `${parts} ${translate('findingsReport.capec', getLocale(), { value: f.capec })}` : parts;
}

function findingList(g: FindingGroup, out: string[]): void {
  const locale = getLocale();
  for (const f of g.findings.slice(0, MD_LIST_LIMIT)) out.push(`  - ${findingLine(f)}`);
  if (g.findings.length > MD_LIST_LIMIT) {
    out.push(`  - ${translate('findingsReport.more', locale, { count: g.findings.length - MD_LIST_LIMIT })}`);
  }
}

/** `--fail-on` のゲート判定結果。未指定のときは渡さない。 */
export interface FindingsGateResult {
  failOn: Severity;
  offenders: NormalizedFinding[];
}

export function findingsReportToMarkdown(report: FindingsReport, gate?: FindingsGateResult): string {
  const locale = getLocale();
  const t = (key: Parameters<typeof translate>[0], params?: Record<string, string | number>) =>
    translate(key, locale, params);
  const s = report.summary;
  const out: string[] = [t('findingsReport.heading'), '', t('findingsReport.intro'), ''];

  out.push(
    `- ${t('findingsReport.summary.open', { count: s.openFindings })}`,
    `- ${t('findingsReport.summary.confirmed', { count: s.confirmedFindings, threats: s.confirmedThreats })}`,
    `- ${t('findingsReport.summary.notInModel', { count: s.notInModelFindings })}`,
    `- ${t('findingsReport.summary.unmapped', { count: s.unmappedFindings })}`,
    `- ${t('findingsReport.summary.excluded', { sca: s.excludedSca, closed: s.excludedClosed })}`,
  );

  out.push('', t('findingsReport.section.confirmed'), '');
  if (report.confirmed.length === 0) out.push(t('findingsReport.section.confirmed.none'), '');
  for (const c of report.confirmed) {
    out.push(`### ${c.canonicalId}`, '', t('findingsReport.confirmed.modelThreats'));
    for (const m of c.modelThreats) {
      out.push(
        `- [${m.layer}] ${m.severity} ${m.name}${m.asset ? ` — ${m.asset}` : ''}${m.ruleId ? ` (${m.ruleId})` : ''}${recordedDecision(m)}`,
      );
    }
    out.push('', `- ${t('findingsReport.findingsCount', { count: c.findings.count, max: c.findings.maxSeverity })}`);
    findingList(c.findings, out);
    out.push('');
  }

  if (report.priority.length > 0) {
    out.push(t('findingsReport.section.priority', { limit: PRIORITY_LIMIT }), '');
    report.priority.forEach((p, i) => {
      out.push(
        `${i + 1}. ${findingLine(p.finding)} — ${t('findingsReport.priority.line', { modelSeverity: p.modelSeverity, severity: p.finding.severity })} → ${p.canonicalIds.join(', ')}`,
      );
    });
    out.push('');
  }

  out.push(t('findingsReport.section.notInModel'), '');
  if (report.notInModel.length === 0) out.push(t('findingsReport.section.notInModel.none'));
  for (const n of report.notInModel) {
    out.push(`- **${n.canonicalId}** — ${t('findingsReport.findingsCount', { count: n.findings.count, max: n.findings.maxSeverity })}`);
    findingList(n.findings, out);
  }

  out.push('', t('findingsReport.section.unmapped'), '');
  if (report.unmapped.length === 0) out.push(t('findingsReport.section.unmapped.none'));
  for (const u of report.unmapped) {
    const label = u.cwe !== undefined ? `CWE-${u.cwe}${u.cweName ? ` ${u.cweName}` : ''}` : t('findingsReport.cweUnknown');
    const capec = u.capec.length > 0 ? ` ${t('findingsReport.capec', { value: u.capec.join(', ') })}` : '';
    out.push(`- **${label}**${capec} — ${t('findingsReport.findingsCount', { count: u.findings.count, max: u.findings.maxSeverity })}`);
    findingList(u.findings, out);
  }

  out.push('', t('findingsReport.section.gate'), '');
  if (!gate) {
    out.push(t('findingsReport.gate.notConfigured'));
  } else if (gate.offenders.length === 0) {
    out.push(t('findingsReport.gate.pass', { failOn: gate.failOn }));
  } else {
    out.push(t('findingsReport.gate.fail', { failOn: gate.failOn, count: gate.offenders.length }));
    for (const f of gate.offenders) out.push(`- ${findingLine(f)}`);
  }

  return out.join('\n');
}

/** 機械処理用の JSON オブジェクト（キーは英語固定）。 */
export function findingsReportToJson(report: FindingsReport, gate?: FindingsGateResult): Record<string, unknown> {
  const group = (g: FindingGroup) => ({ count: g.count, maxSeverity: g.maxSeverity, findings: g.findings });
  return {
    schemaVersion: 1,
    kind: 'cyberriskscape-findings-report',
    summary: report.summary,
    confirmed: report.confirmed.map((c) => ({
      canonicalId: c.canonicalId,
      modelThreats: c.modelThreats,
      findings: group(c.findings),
    })),
    notInModel: report.notInModel.map((n) => ({ canonicalId: n.canonicalId, findings: group(n.findings) })),
    unmapped: report.unmapped.map((u) => ({
      cwe: u.cwe ?? null,
      cweName: u.cweName ?? null,
      capec: u.capec,
      findings: group(u.findings),
    })),
    priority: report.priority.map((p) => ({
      finding: p.finding,
      canonicalIds: p.canonicalIds,
      modelSeverity: p.modelSeverity,
    })),
    gate: gate
      ? { failOn: gate.failOn, passed: gate.offenders.length === 0, offenders: gate.offenders.map((f) => f.id) }
      : null,
  };
}
