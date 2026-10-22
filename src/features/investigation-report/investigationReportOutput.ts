import { translate, type TranslationKey } from '../../i18n';
import {
  STATUS_ORDER,
  type InvestigationReport,
  type ReportNode,
  type ReportPeriod,
} from './buildInvestigationReport';
import type { HostEvidence } from './evidence';

/** 侵害調査レポート（InvestigationReport）を Markdown / JSON に整形する。 */

type T = (key: TranslationKey, params?: Record<string, string | number>) => string;

/** 証拠由来の文字列は信頼できないので、インラインコードに入れて Markdown として解釈させない。 */
const code = (s: string) => `\`${s.replace(/`/g, "'").replace(/\s+/g, ' ')}\``;

function periodText(p: ReportPeriod, t: T): string {
  if (p.basis === 'observed') {
    return p.to
      ? t('investigationReport.period.observed', { from: p.from, to: p.to })
      : t('investigationReport.period.observed.noEnd', { from: p.from });
  }
  return t(`investigationReport.period.retention.${p.retention}` as TranslationKey, { to: p.to });
}

function evidenceLines(e: HostEvidence, t: T, indent: string): string[] {
  const out: string[] = [];
  out.push(
    `${indent}- ${t('investigationReport.evidence.line', {
      source: t(`investigationReport.evidence.source.${e.source}` as TranslationKey),
      host: e.host ? code(e.host) : t('investigationReport.evidence.unknownHost'),
      path: code(e.path),
      collected: e.collectedAt ?? t('investigationReport.evidence.unknownDate'),
    })}`,
  );
  const sub = `${indent}  - `;
  if (e.traceCount > 0) {
    out.push(
      `${sub}${t('investigationReport.evidence.traces', {
        count: e.traceCount,
        categories: e.categories.map((c) => `${c.name} ${c.count}`).join(', '),
      })}`,
    );
    out.push(`${sub}${t('investigationReport.evidence.top')}`);
    for (const h of e.top) out.push(`${indent}    - ${h.category}: ${code(h.location)} ${code(h.content)}`);
  } else if (e.searched) {
    out.push(`${sub}${t('investigationReport.evidence.noTraces')}`);
  }
  if (e.reference.length > 0) {
    out.push(
      `${sub}${t('investigationReport.evidence.reference', { list: e.reference.map((r) => `${r.name} ${r.count}`).join(', ') })}`,
    );
  }
  if (e.skipped.length > 0) {
    out.push(`${sub}${t('investigationReport.evidence.skipped')}`);
    for (const s of e.skipped) out.push(`${indent}    - ${code(s.path)}${s.reason ? ` — ${code(s.reason)}` : ''}`);
  }
  return out;
}

function nodeLines(n: ReportNode, t: T): string[] {
  const out: string[] = [`### ${`${n.id} ${n.label}`.trim()}（${n.type}）`, ''];
  out.push(`- ${t('investigationReport.node.status', { status: t(`investigationReport.status.${n.status}` as TranslationKey) })}`);
  if (n.status !== 'not-investigated') {
    out.push(
      `- ${n.period ? t('investigationReport.node.period', { period: periodText(n.period, t) }) : t('investigationReport.node.period.unknown')}`,
    );
  }
  if (n.reasons.length > 0) {
    out.push(`- ${t('investigationReport.node.reasons')}`);
    for (const r of n.reasons) out.push(`  - ${t(`investigationReport.reason.${r}` as TranslationKey)}`);
  }
  if (n.limitations.length > 0) {
    out.push(`- ${t('investigationReport.node.limitations')}`);
    for (const l of n.limitations) out.push(`  - ${t(`investigation.limit.${l.code}` as TranslationKey)}`);
  }
  if (n.evidence.length > 0) {
    out.push(`- ${t('investigationReport.node.evidence')}`);
    for (const e of n.evidence) out.push(...evidenceLines(e, t, '  '));
  }
  out.push('');
  return out;
}

export function investigationReportToMarkdown(report: InvestigationReport): string {
  const t: T = (key, params) => translate(key, report.locale, params);
  const s = report.summary;
  const out: string[] = [];

  out.push(`# ${t('investigationReport.title', { system: report.system, layer: report.layer })}`, '');
  out.push(`> ${t('investigationReport.disclaimer')}`, '');
  out.push(`- ${t('investigationReport.generated', { date: report.generatedAt, product: report.product })}`);
  out.push(`- ${report.pathBased ? t('investigationReport.scope.path') : t('investigationReport.scope.all')}`);
  out.push(
    `- ${t('investigationReport.summary', {
      found: s['traces-found'],
      notNegatable: s['not-negatable'],
      notInvestigated: s['not-investigated'],
      noTraces: s['no-traces'],
      evidence: s.evidence,
      unknown: s.unknownHosts,
      rejected: s.rejected,
    })}`,
    '',
  );

  out.push(`## ${t('investigationReport.legend.h')}`, '');
  for (const st of STATUS_ORDER) out.push(`- ${t(`investigationReport.legend.${st}` as TranslationKey)}`);
  out.push('');

  out.push(`## ${t('investigationReport.h.nodes')}`, '');
  if (report.nodes.length === 0) out.push(t('investigationReport.nodes.none'), '');
  for (const n of report.nodes) out.push(...nodeLines(n, t));

  out.push(`## ${t('investigationReport.h.unknownHosts')}`, '');
  if (report.unknownHosts.length === 0) {
    out.push(t('investigationReport.unknownHosts.none'), '');
  } else {
    out.push(t('investigationReport.unknownHosts.intro'), '');
    for (const u of report.unknownHosts) {
      out.push(`- ${t(`investigationReport.unknownHost.${u.reason}` as TranslationKey)}`);
      out.push(...evidenceLines(u.evidence, t, '  '));
    }
    out.push('');
  }

  if (report.unmapped.length > 0) {
    out.push(`## ${t('investigationReport.h.unmapped')}`, '', t('investigationReport.unmapped.intro'), '');
    for (const u of report.unmapped) out.push(`- ${code(u.name)}: ${u.count}`);
    out.push('');
  }

  if (report.rejected.length > 0) {
    out.push(`## ${t('investigationReport.h.rejected')}`, '');
    for (const r of report.rejected) out.push(`- ${code(r.path)} — ${code(r.reason)}`);
    out.push('');
  }
  return `${out.join('\n').trimEnd()}\n`;
}

/** JSON は InvestigationReport をそのまま出す（キーは英語）。 */
export function investigationReportToJson(report: InvestigationReport): string {
  return JSON.stringify({ kind: 'cyberriskscape-investigation-report', schemaVersion: 1, ...report }, null, 2);
}
