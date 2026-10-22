import type { TranslationKey } from '../ja';

/** English translation for the compromise investigation plan (Markdown). */
export const enInvestigation: Partial<Record<TranslationKey, string>> = {
  'investigation.title': 'Compromise investigation plan: {system} ({layer})',
  'investigation.disclaimer':
    'This plan does not determine whether a compromise occurred. The absence of traces is not proof that there was no compromise.',
  'investigation.system': 'System: {system}',
  'investigation.generated': 'Generated: {date} (by {product} from the threat model)',
  'investigation.scope.path':
    'Scope: nodes on the attack routes from the attacker to the objective, ordered by the number of routes passing through them.',
  'investigation.scope.all':
    'Scope: all nodes. The diagram has no route connecting an attacker to an objective, so no priority is given.',
  'investigation.howTo':
    'Start from each node’s checks and logs to review. For nodes with a risk of not being able to investigate, first confirm the state of logging.',
  'investigation.h.nodes': 'Nodes to investigate',
  'investigation.nodes.none': 'There are no nodes to investigate.',
  'investigation.routeHits': 'Attack routes passing through: {hits}',
  'investigation.noViewpoint': 'No detected threat matched an investigation viewpoint.',
  'investigation.viewpoint': '{title} (threats: {threats})',
  'investigation.accepted': '* {threat}: risk accepted (no reason recorded). Acceptance is not a reason to skip investigation, so it is included.',
  'investigation.accepted.note': '* {threat}: risk accepted (decision: {note}). Acceptance is not a reason to skip investigation, so it is included.',
  'investigation.logs': 'Logs to review:',
  'investigation.toolHint': 'Hints for {tool}:',
  'investigation.limitations': 'Risk of not being able to investigate',
  'investigation.limit.none':
    'According to the diagram, log collection and retention raise no concern (confirm the actual state separately).',
  'investigation.limit.logNotCollected': 'Logs are not collected.',
  'investigation.limit.logCollectionUnset': 'Log collection is not specified (treated as not collected).',
  'investigation.limit.logRetentionShort': 'Log retention is under 90 days; the period you can look back may be short.',
  'investigation.limit.logRetentionUnset': 'Log retention is not specified; how far back you can look is unknown.',
  'investigation.limit.logNotModelable':
    'This type cannot express logging in the diagram (confirm collection and retention separately).',
};
