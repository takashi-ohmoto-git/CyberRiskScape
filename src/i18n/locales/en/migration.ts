import type { TranslationKey } from '../ja';

/** English translation for the migration report (Microsoft Threat Modeling Tool threats x CyberRiskScape threats). */
export const enMigration: Partial<Record<TranslationKey, string>> = {
  'migration.heading': '# Migration report (Microsoft Threat Modeling Tool → CyberRiskScape)',
  'migration.intro':
    'Threats imported from TMT are matched against the threats CyberRiskScape detects in the same diagram, by element (a data flow and its two ends) and STRIDE category. TMT threats are generic STRIDE questions and do not map one-to-one to CyberRiskScape rules. An "overlap" only means that a concrete threat applies to the same question; it does not mean they are the same threat.',
  'migration.summary.heading': '## 1. Summary',
  'migration.summary.tmt': '- TMT threats: {total} (states: {states})',
  'migration.summary.detected':
    '- CyberRiskScape detected threats: {total} (Critical {critical} / High {high} / Medium {medium} / Low {low})',
  'migration.summary.covered': '- TMT threats with a CyberRiskScape threat on the same element and category: {covered} / {total}',
  'migration.summary.detectedOnly':
    '- Detected threats that overlap no TMT threat: {count} (of all detected threats, {beyond} are non-STRIDE AI / agent threats)',
  'migration.summary.assumed':
    '- Detected threats raised by assuming worst values for unset attributes: {count} (e.g. attributes left "Not Selected" in TMT; they disappear once you enter the actual values)',
  'migration.summary.recheck': '- Decisions to re-check: {count} (section 2)',
  'migration.recheck.heading': '## 2. Decisions to re-check',
  'migration.recheck.intro':
    'Threats marked Mitigated or Not Applicable in TMT where CyberRiskScape still raises an unsuppressed threat on the same element and category. Check whether the reasoning behind the TMT decision also holds for the concrete threat.',
  'migration.recheck.columns': '| TMT ID | TMT threat | TMT state (changed by) | Target | CyberRiskScape threats |',
  'migration.entries.heading': '## 3. Each TMT threat',
  'migration.entries.intro': 'All imported TMT threats. The last column lists CyberRiskScape threats detected on the same element and category.',
  'migration.entries.columns': '| TMT ID | TMT threat | Category | TMT state | Target | CyberRiskScape threats |',
  'migration.entries.noMatch': '(none on the same element and category)',
  'migration.detectedOnly.heading': '## 4. Threats only CyberRiskScape detected',
  'migration.detectedOnly.intro':
    'Detected threats that overlap no TMT threat (suppressed ones excluded), highest severity first. AI / agent threats and component-type-specific threats are not in the default TMT template.',
  'migration.detectedOnly.columns': '| Severity | Threat | Framework | Target | Assumed |',
  'migration.assumedMark': 'assumed (unset)',
  'migration.none': '(none)',
  'migration.next.heading': '## 5. Next steps',
  'migration.next.body':
    '1. Review the "[TMT] Review" notes in annotations and descriptions (unmapped types, line boundaries, unconnected flows)\n2. Enter the actual attributes for elements with assumed threats (authentication, encryption, attack surface, posture)\n3. For the decisions in section 2, re-record the TMT decision as the treatment / control status of the CyberRiskScape threats',
};
