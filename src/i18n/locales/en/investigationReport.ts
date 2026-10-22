import type { TranslationKey } from '../ja';

/** English translation for the compromise investigation report (`investigation-report`). */
export const enInvestigationReport: Partial<Record<TranslationKey, string>> = {
  'investigationReport.title': 'Compromise investigation report: {system} ({layer})',
  'investigationReport.disclaimer':
    'This report does not determine whether a compromise occurred. The absence of traces is not proof that there was no compromise.',
  'investigationReport.generated': 'Generated: {date} (by {product} from the threat model and the collected evidence)',
  'investigationReport.scope.path': 'Scope: nodes on the attack routes from the attacker to the objective.',
  'investigationReport.scope.all':
    'Scope: all nodes. There is no route between an attacker and an objective in the diagram, so nothing was narrowed down.',
  'investigationReport.summary':
    'Summary: traces found {found} / cannot rule out {notNegatable} / not investigated {notInvestigated} / no traces {noTraces} (evidence {evidence}, hosts not in the diagram {unknown}, unreadable inputs {rejected})',
  'investigationReport.legend.h': 'Status legend',
  'investigationReport.legend.traces-found': 'Traces found: any mapped evidence contains a result treated as a trace.',
  'investigationReport.legend.not-negatable':
    'Cannot rule out: there is evidence, but the period examined is unknown, some files could not be read, or it contains no result that searches for traces. This does not mean there are no traces.',
  'investigationReport.legend.not-investigated': 'Not investigated: no evidence is mapped to the node.',
  'investigationReport.legend.no-traces':
    'No traces: there is evidence, no result treated as a trace, the period examined is known, and no file was unreadable. This does not mean there was no compromise.',
  'investigationReport.status.traces-found': 'Traces found',
  'investigationReport.status.not-negatable': 'Cannot rule out',
  'investigationReport.status.not-investigated': 'Not investigated',
  'investigationReport.status.no-traces': 'No traces',
  'investigationReport.h.nodes': 'Status by node',
  'investigationReport.nodes.none': 'There are no target nodes.',
  'investigationReport.node.status': 'Status: {status}',
  'investigationReport.node.period': 'Period examined: {period}',
  'investigationReport.node.period.unknown': 'Period examined: unknown',
  'investigationReport.period.observed': '{from} to {to} (observed in the evidence)',
  'investigationReport.period.observed.noEnd': 'from {from} (collection date unknown; observed in the evidence)',
  'investigationReport.period.retention.OneYearOrMore':
    'at least 1 year before the collection date ({to}) (from the log retention entered in the diagram; not observed)',
  'investigationReport.period.retention.Under1Year':
    '90 days or more, under 1 year before the collection date ({to}) (from the log retention entered in the diagram; not observed)',
  'investigationReport.period.retention.Under90Days':
    'under 90 days (collection date {to}; from the log retention entered in the diagram; not observed)',
  'investigationReport.node.reasons': 'Why it cannot be ruled out:',
  'investigationReport.reason.periodUnknown':
    'The period examined is unknown (neither the evidence nor the log retention entered in the diagram gives a clue).',
  'investigationReport.reason.skipped': 'Some files could not be read (see below).',
  'investigationReport.reason.noSearch': 'The evidence has no result that searches for traces (reference counts only).',
  'investigationReport.node.limitations': 'Risks that the node cannot be examined (same judgment as the investigation plan):',
  'investigationReport.node.evidence': 'Evidence:',
  'investigationReport.evidence.line': '{source}, host {host}, {path}, collected {collected}',
  'investigationReport.evidence.unknownHost': '(no host name)',
  'investigationReport.evidence.unknownDate': 'unknown',
  'investigationReport.evidence.source.triage': 'Triage',
  'investigationReport.evidence.source.velociraptor': 'Velociraptor',
  'investigationReport.evidence.traces': 'Results treated as traces: {count} ({categories})',
  'investigationReport.evidence.noTraces': 'Results treated as traces: 0',
  'investigationReport.evidence.top': 'Top results:',
  'investigationReport.evidence.reference': 'Reference only (counts): {list}',
  'investigationReport.evidence.skipped': 'Unreadable:',
  'investigationReport.h.unknownHosts': 'Hosts not in the diagram',
  'investigationReport.unknownHosts.none': 'None.',
  'investigationReport.unknownHosts.intro':
    'The following evidence could not be mapped to any node in the diagram. Check the host map (hosts.json).',
  'investigationReport.unknownHost.notInHostMap': 'not in the host map',
  'investigationReport.unknownHost.nodeNotInDiagram': 'the node in the host map is not in the diagram',
  'investigationReport.unknownHost.nodeNotInScope':
    'the node in the host map is outside the scope of this report (not on an attack route)',
  'investigationReport.h.unmapped': 'Results that could not be mapped',
  'investigationReport.unmapped.intro':
    'Results of artifacts that are not listed in the investigation viewpoints (compromise.yaml). They are not used to judge traces; only counts are shown.',
  'investigationReport.h.rejected': 'Unreadable inputs',
  'investigationReport.cli.done':
    'Wrote the investigation report ({layer}; traces found {found}, cannot rule out {notNegatable}, not investigated {notInvestigated}, no traces {noTraces}, hosts not in the diagram {unknown})',
  'investigationReport.cli.missingEvidence': 'Specify at least one --evidence.',
  'investigationReport.cli.missingHosts':
    'Specify --hosts (a JSON file whose hosts array holds host and node; see tools/triage/README for an example).',
  'investigationReport.cli.badHosts': 'Invalid --hosts format: {error}',
  'investigationReport.cli.noEvidenceFound':
    'No evidence was found (a triage JSON, or a Velociraptor collection that has a results/ folder, is required).',
  'investigationReport.read.notFound': 'cannot be read',
  'investigationReport.read.symlink': 'symbolic links are not read',
  'investigationReport.read.notJson': 'cannot be parsed as JSON',
  'investigationReport.read.unsupported': 'unsupported format (not a triage JSON)',
  'investigationReport.read.invalid': 'invalid format: {error}',
  'investigationReport.read.truncated': 'too large; only the first {mb} MB was read',
  'investigationReport.read.badLines': '{count} lines could not be parsed',
  'investigationReport.read.tooManyEntries': 'too many entries in the folder; the search stopped early',
  'investigationReport.read.noResults': 'no readable collection results',
} as const;
