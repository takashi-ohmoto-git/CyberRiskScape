import type { TranslationKey } from '../ja';

/** English translation for the CLI `diff` subcommand (model diff report). */
export const enDiff: Partial<Record<TranslationKey, string>> = {
  'diff.heading': '# Model diff report',

  'diff.summary.added': 'Added: {count}',
  'diff.summary.removed': 'Removed: {count}',
  'diff.summary.suppressionChanged': 'Disposition changed: {count} ({approvalCount} need approval)',
  'diff.summary.severityChanged': 'Effective severity changed: {count}',

  'diff.section.triggers': '## Triggers',
  'diff.triggers.none': 'No triggers matched.',
  'diff.triggers.manualHeading': '### Confirm in PR review (cannot be auto-judged from the model diff)',

  'diff.section.added': '## Added threats',
  'diff.section.removed': '## Removed threats',
  'diff.section.suppressionChanged': '## Disposition changes',
  'diff.section.severityChanged': '## Effective severity changes',
  'diff.section.gate': '## Gate result',

  'diff.table.none': '(none)',
  'diff.col.severity': 'Severity',
  'diff.col.asset': 'Asset',
  'diff.col.threat': 'Threat',
  'diff.col.before': 'Before',
  'diff.col.after': 'After',
  'diff.col.approval': 'Needs approval',

  'diff.approval.yes': 'Needs approval',
  'diff.approval.no': '',

  'diff.gate.pass': 'PASS (no new unsuppressed threats at or above {failOn})',
  'diff.gate.fail': 'FAIL ({count} new unsuppressed threat(s) at or above {failOn})',
  'diff.gate.notConfigured': 'Not configured (--fail-on omitted)',
  'diff.gate.stderr': '--fail-on {failOn}: {count} new unsuppressed threat(s) at or above the threshold.',
};
