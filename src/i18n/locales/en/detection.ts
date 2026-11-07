import type { TranslationKey } from '../ja';

/** English translation for the detection requirements document (Markdown). */
export const enDetection: Partial<Record<TranslationKey, string>> = {
  'detection.title': 'Detection requirements per attack path: {system} ({layer})',
  'detection.disclaimer':
    'This document lists behaviors to monitor and logs needed. It does not mean they can actually be detected. Whether logs reach the monitoring destination is read from the diagram inputs and must be confirmed separately.',
  'detection.system': 'System: {system}',
  'detection.generated': 'Generated: {date} (by {product} from the threat model)',
  'detection.scope.path':
    'Scope: nodes on the attack routes from the attacker to the objective, ordered by the number of routes passing through them.',
  'detection.scope.all':
    'Scope: all nodes. The diagram has no route connecting an attacker to an objective, so no priority is given.',
  'detection.h.routes': 'Attack routes and segments where logs do not reach the monitoring destination',
  'detection.routes.truncated': 'Showing the {shown} lowest-cost routes out of {total} feasible routes.',
  'detection.route': 'Route {n}: {attacker} → {objective}',
  'detection.route.nodes': 'Route: {nodes}',
  'detection.route.blind': 'None of the evaluable nodes can be read as sending logs to the monitoring destination.',
  'detection.route.noGap':
    'Per the diagram inputs, there is no segment where logs fail to reach the monitoring destination (confirm the actual state separately).',
  'detection.route.gap':
    'In this segment logs do not reach the monitoring destination (whether they do is unconfirmed / not entered): {nodes}',
  'detection.h.nodes': 'Nodes to monitor',
  'detection.nodes.none': 'There are no target nodes.',
  'detection.routeHits': 'Attack routes passing through: {hits}',
  'detection.logState': 'Log delivery: {state}',
  'detection.log.forwarded': 'A log destination is entered in the diagram (confirm separately that logs actually arrive).',
  'detection.log.localOnly':
    'Logs are kept on the node, but whether they reach the monitoring destination is unconfirmed / not entered.',
  'detection.log.none': 'Logs are not collected. Logs do not reach the monitoring destination.',
  'detection.log.noneAssumed':
    'Logs do not reach the monitoring destination (whether they do is unconfirmed / not entered, so they are treated as not arriving).',
  'detection.log.notModelable': 'This type cannot express its log state in the diagram (confirm separately).',
  'detection.noRequirement': 'No detected threat matches the monitoring requirement table.',
  'detection.requirement': '{title} (threats: {threats})',
  'detection.watch': 'Behaviors to monitor:',
  'detection.logs': 'Logs needed:',
};
