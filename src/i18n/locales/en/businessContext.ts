import type { TranslationKey } from '../ja';

/** English translation for business context (business processes a node carries and its criticality). */
export const enBusinessContext: Partial<Record<TranslationKey, string>> = {
  'businessContext.section.title': 'Business context',
  'businessContext.section.hint':
    'The business processes this node carries and its business criticality, recorded from an aggregate table (e.g. process mining) or by hand. It does not affect which threat rules fire. High adds the node to the recommended targets and raises SSVC Mission & Well-being.',
  'businessContext.criticality.label': 'Business criticality',
  'businessContext.criticality.unset': 'Not set',
  'businessContext.criticality.High': 'High',
  'businessContext.criticality.Medium': 'Medium',
  'businessContext.criticality.Low': 'Low',
  'businessContext.criticalitySource.declared': 'Stated in the table / set by hand',
  'businessContext.criticalitySource.derived': 'Derived from share of value',
  'businessContext.processes': 'Business processes',
  'businessContext.processes.empty': 'No business processes recorded (an import adds them).',
  'businessContext.process.cases': '{count} cases',
  'businessContext.source': 'Source: {product} ({at})',
  'businessContext.source.ref': 'Reference: {ref}',

  'businessContext.import.menu': 'Import business context',
  'businessContext.import.title': 'Import business context',
  'businessContext.import.hint':
    'Reads a business context table (CSV: node,process,cases,value,currency,period,criticality, or JSON) and records the business processes and criticality of each node. Criticality is the table\'s criticality, or else derived from the node\'s share of the table total (value, or cases if there is no value): 30% or more is High, 10% or more is Medium. Only nodes in the table are replaced.',
  'businessContext.import.pick': 'Table file (.csv / .json)',
  'businessContext.import.read': 'Read',
  'businessContext.import.apply': 'Apply',
  'businessContext.import.close': 'Close',
  'businessContext.import.cancel': 'Cancel',
  'businessContext.import.error.tooLarge': 'The file is too large (limit {max} MB).',
  'businessContext.import.summary':
    'Rows {rows} / nodes to apply {applied} / skipped (criticality undecidable) {skipped} / unknown references {unknown} / ambiguous references {ambiguous}',
  'businessContext.import.basis': 'Share basis: {basis}',
  'businessContext.import.basis.value': 'value',
  'businessContext.import.basis.cases': 'cases',
  'businessContext.import.basis.none': 'none',
  'businessContext.import.nodeLine': '{node}: {criticality} ({how})',
  'businessContext.import.how.derived': '{share}% share',
  'businessContext.import.how.declared': 'stated in the table',
  'businessContext.import.skippedLine': '{node}: skipped because criticality cannot be decided (the table has no criticality, value or cases)',
  'businessContext.import.unknown': 'References not in the diagram: {refs}',
  'businessContext.import.ambiguous': 'References matching several nodes (use the node ID): {refs}',
  'businessContext.import.note': 'Note: {note}',
  'businessContext.import.done': 'Applied ({count} nodes). Undo reverts it.',
  'businessContext.import.nothing': 'No nodes to apply.',
};
