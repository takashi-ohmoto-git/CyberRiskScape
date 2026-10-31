import type { TranslationKey } from '../ja';

/** English translation for the CLI `findings-report` subcommand (Veracode findings x model threats). */
export const enFindingsReport: Partial<Record<TranslationKey, string>> = {
  'findingsReport.heading': '# Scan findings vs. threat model',
  'findingsReport.intro':
    'Veracode findings cross-referenced with the threats detected in the diagram, through a CWE mapping table. CWEs not in the table appear under "Findings that could not be mapped".',

  'findingsReport.summary.open': 'Open findings: {count}',
  'findingsReport.summary.confirmed': 'Matching a diagram threat: {count} (threats: {threats})',
  'findingsReport.summary.notInModel': 'No matching threat in the diagram: {count}',
  'findingsReport.summary.unmapped': 'Could not be mapped: {count}',
  'findingsReport.summary.excluded': 'Excluded: SCA {sca}, closed {closed}',

  'findingsReport.section.confirmed': '## Diagram threats confirmed in code',
  'findingsReport.section.confirmed.none': 'No matches.',
  'findingsReport.section.priority': '## Findings to check first (top {limit})',
  'findingsReport.section.notInModel': '## Findings with no matching threat in the diagram (possible gaps in the diagram)',
  'findingsReport.section.notInModel.none': 'None.',
  'findingsReport.section.unmapped': '## Findings that could not be mapped',
  'findingsReport.section.unmapped.none': 'None.',

  'findingsReport.section.gate': '## Gate result',
  'findingsReport.gate.pass': 'PASS (no findings backed by an unsuppressed threat at or above {failOn})',
  'findingsReport.gate.fail': 'FAIL ({count} finding(s) backed by an unsuppressed threat at or above {failOn})',
  'findingsReport.gate.notConfigured': 'Not configured (--fail-on omitted)',
  'findingsReport.gate.stderr':
    '--fail-on {failOn}: {count} finding(s) are backed by an unsuppressed threat at or above the threshold.',

  'findingsReport.confirmed.modelThreats': 'Diagram threats:',
  'findingsReport.findingsCount': 'Findings: {count} (max Veracode severity {max})',
  'findingsReport.more': '... and {count} more',
  'findingsReport.cweUnknown': 'No CWE',
  'findingsReport.capec': 'CAPEC: {value}',
  'findingsReport.recorded': '[Recorded decision: {labels}. Check that it does not contradict the findings]',
  'findingsReport.priority.line': 'diagram {modelSeverity} / Veracode {severity}',

  // For skill-scanner / mcp-scanner (Cisco AI Defense): cross-referenced through the AITech mapping table
  'findingsReport.intro.aitech':
    '{source} findings cross-referenced with the threats detected in the diagram, through an AITech taxonomy mapping table. Findings whose classification is not in the table appear under "Findings that could not be mapped".',
  'findingsReport.scopeNode':
    'Target node: {node} (only threats on this node, its edges, the nodes across those edges, and its containing parent/children are cross-referenced)',
  'findingsReport.summary.incompleteItems': 'Items whose scan did not complete: {count} (an unscanned item is not necessarily safe)',
  'findingsReport.findingsCount.label': 'Findings: {count} (max severity {max})',
  'findingsReport.aitechUnknown': 'No classification',
  'findingsReport.priority.lineSource': 'diagram {modelSeverity} / {source} {severity}',
  'findingsReport.gate.stderrSource':
    '--fail-on {failOn}: {count} {source} finding(s) are backed by an unsuppressed threat at or above the threshold.',
  'findingsReport.cli.sourceRequired':
    'Specify a scan results file with exactly one of --veracode, --skill-scanner or --mcp-scanner.',
  'findingsReport.cli.sourceExclusive':
    '--veracode, --skill-scanner and --mcp-scanner cannot be combined. Specify only one.',

  'findingsReport.cli.missingVeracode': 'Specify a Veracode results file with --veracode.',
  'findingsReport.cli.done':
    'Cross-referenced (open {open}, matched {confirmed}, not in diagram {notInModel}, unmapped {unmapped}, excluded SCA {sca} / closed {closed})',
};
