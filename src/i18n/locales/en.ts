import type { TranslationKey } from './ja';

/**
 * 英語ロケール（スタブ）。英語対応は「予定」段階のため、翻訳済みキーのみを持つ。
 * 未定義キーは index.ts が ja にフォールバックするので、Partial で問題ない。
 * 翻訳が決まったキーから順次このオブジェクトへ追加していく。
 */
export const en: Partial<Record<TranslationKey, string>> = {
  'app.loading': 'Loading…',

  // ── AttackTreeModal ──
  'attackTree.title': 'Attack Path Analysis',
  'attackTree.targetMissing': 'Target (objective) not found',
  'attackTree.routesSummary': '{routes} route(s) ({combinations} channel combinations)',
  'attackTree.minCost': 'Min cost {cost}',
  'attackTree.allBlocked': 'All routes blocked',
  'attackTree.allUnevaluatedNote':
    'DREAD not scored — cost uses severity-based provisional difficulty plus hop count',
  'attackTree.legend.weakestRoute': 'Weakest route',
  'attackTree.legend.covered': 'Mitigated (covered)',
  'attackTree.legend.partial': 'Partially mitigated',
  'attackTree.legend.noEvidence': 'No known threats',
  'attackTree.residualToggle': 'Residual routes only (block covered hops)',
  'attackTree.noPath.title': 'No route connects the attacker and the target.',
  'attackTree.noPath.body':
    'Attack path analysis is built by following edges (connections) on the canvas. Create an edge to the component that serves as the attacker entry point.',
  'attackTree.truncated': 'Some routes were omitted due to depth/route limits.',
  'attackTree.footnote':
    'Difficulty prefers DREAD Exploitability (lower = easier). When unscored, severity-based provisional values are used. Edges are treated as traversable regardless of direction. A single control does not fully block a route by default — covered hops add to the cost instead (toggle "residual routes only" to treat them as blocked).',
  'attackTree.node.difficulty': 'Difficulty {value}',
  'attackTree.node.unevaluated': 'Unscored',
  'attackTree.node.softDifficulty': 'Provisional {value}',
  'attackTree.node.threatCount': '{count} threat(s)',
  'attackTree.coverage.full': 'Mitigated',
  'attackTree.coverage.partial': 'Partial',
  'attackTree.hop.channelCount': '×{count}',
  'attackTree.hop.noEvidence': 'No evidence',
  'attackTree.detail.nodeHeading': 'Detection basis ({name})',
  'attackTree.detail.hopHeading': 'Detection basis (hop)',
  'attackTree.detail.hopEndpoints': '{a} ⇔ {b}',
  'attackTree.detail.travelDirection': 'Travel on weakest route: {from} → {to}',
  'attackTree.detail.noThreats': 'No threats detected on this element',
  'attackTree.detail.chosenChannel': 'Chosen channel',
  'attackTree.detail.close': 'Clear selection',
  'attackTree.detail.formula':
    'Difficulty = 4 − max(DREAD Exploitability). With threats but no DREAD, severity-based provisional difficulty (Critical/High→1, Medium→2, Low→3). No threats → neutral 2. Partial +1 / full +8 (blocked in residual-route mode).',
  'attackTree.chokePoint.heading': 'Choke points (highest-leverage mitigation targets)',
  'attackTree.chokePoint.hits': '{hits}/{total} routes',
  'attackTree.routeTable.heading': 'Routes',
  'attackTree.routeTable.colRoute': 'Route',
  'attackTree.routeTable.colCost': 'Cost',
  'attackTree.routeTable.colWeakestHop': 'Weakest hop',
  'attackTree.routeTable.colStatus': 'Status',
  'attackTree.routeTable.blocked': 'Blocked',
  'attackTree.routeTable.statusFeasible': 'Reachable',
  'attackTree.routeTable.statusBlocked': 'Blocked',
  'threatCard.assumption.badge': 'Assumed',
  'threatCard.assumption.attackSurface':
    'Attack surface is unset; evaluation used open-by-default baselines. Set attack surface on the node for higher precision.',
  'threatCard.assumption.agentAttributes':
    'Agent attributes are unset; evaluation used worst-case defaults (Autonomous / Admin / LabelOnly). Set attributes for higher precision.',
};
