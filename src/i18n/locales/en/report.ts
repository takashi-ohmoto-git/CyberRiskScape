import type { TranslationKey } from '../ja';

/**
 * Exported report strings (English). Missing keys fall back to Japanese.
 * This output is used as audit evidence, so keep column/heading labels in
 * plain audit-document English (e.g. Threat ID, Severity, Target, Mitigation,
 * Source, Compliance references).
 */
export const enReport: Partial<Record<TranslationKey, string>> = {
  // ── Status (shared by ThreatReportRow.status and DCRH controls notes) ──
  'report.status.unaddressed': 'Unaddressed',
  'report.status.avoid': 'Avoided',
  'report.status.reduce': 'Reduced',
  'report.status.transfer': 'Transferred',
  'report.status.accepted': 'Risk accepted',
  'report.status.falsePositive': 'False positive',

  // ── Origin (ThreatReportRow.origin) ──
  'report.origin.manual': 'Manual',
  'report.origin.detected': 'Detected',

  // ── CSV column headers ──
  'report.csv.col.id': 'ID',
  'report.csv.col.asset': 'Target',
  'report.csv.col.framework': 'Framework',
  'report.csv.col.category': 'Category',
  'report.csv.col.name': 'Threat name',
  'report.csv.col.threat': 'Threat',
  'report.csv.col.severity': 'Rule severity',
  'report.csv.col.effectiveSeverity': 'Effective severity',
  'report.csv.col.impact': 'Impact',
  'report.csv.col.likelihood': 'Likelihood',
  'report.csv.col.mitigation': 'Mitigation',
  'report.csv.col.status': 'Risk treatment',
  'report.csv.col.controlStatus': 'Control status',
  'report.csv.col.comments': 'Comments',
  'report.csv.col.origin': 'Origin',

  // ── CSV leading project meta block ──
  'report.csv.meta.projectName': 'Project name',
  'report.csv.meta.systemName': 'System name',
  'report.csv.meta.purpose': 'System purpose',
  'report.csv.meta.businessImpact': 'Business impact',
  'report.csv.meta.securityObjectives': 'Security objectives',
  'report.csv.meta.framework': 'Framework',
  'report.csv.meta.layer': 'Layer',
  'report.csv.meta.threatCount': 'Threat count',

  // ── DCRH (Anthropic official THREAT_MODEL.md) output ──
  'report.dcrh.defaultContext': 'Threat model for {name} (exported from {brand}).',
  'report.dcrh.businessImpactLine': 'Business impact: {value}',
  'report.dcrh.securityObjectivesLine': 'Security objectives: {value}',
  'report.dcrh.dataFlowDescription': 'Data flow ({network} / {encryption})',
  'report.dcrh.reason.falsePositive': 'Excluded as a false positive',
  'report.dcrh.reason.notApplicable': 'Out of scope for controls (not-applicable)',
  'report.dcrh.reasonWithNote': '{label}: {note}',
  'report.dcrh.controlsWithNote': '{controls} ({extra})',

  'report.dcrh.openQuestions.actor':
    '- actor is not modeled in {brand}; the actor column in section 4 is left blank. Needs review.',
  'report.dcrh.openQuestions.likelihood':
    '- likelihood defaults to `possible` for threats without a risk score.',
  'report.dcrh.openQuestions.evidence':
    '- evidence (CVE / finding links, etc.) is always blank; this tool does not retain it.',
  'report.dcrh.openQuestions.sensitivity':
    '- sensitivity defaults to `medium` for all assets, as no corresponding data exists.',
  'report.dcrh.openQuestions.entryPoint':
    '- entry points list only data flows linked to a threat (unassigned edges are omitted).',
  'report.dcrh.openQuestions.section8':
    '- closes_class / effort in section 8 are provisional values. Needs review.',
};
