import type { TranslationKey } from '../ja';

/** Analytics, compliance, attack path (English). Missing keys fall back to Japanese. */
export const enAnalytics: Partial<Record<TranslationKey, string>> = {
  'analytics.close': 'Close',

  // ── DREAD assessment form ──
  'analytics.dread.damage.label': 'D: Damage',
  'analytics.dread.damage.level1': 'Minor disruption or limited information exposure',
  'analytics.dread.damage.level2': 'Partial data leakage or tampering',
  'analytics.dread.damage.level3': 'Full data breach or complete system outage',
  'analytics.dread.reproducibility.label': 'R: Reproducibility',
  'analytics.dread.reproducibility.level1': 'Rarely reproducible under specific conditions',
  'analytics.dread.reproducibility.level2': 'Reproducible when conditions align',
  'analytics.dread.reproducibility.level3': 'Always reproducible',
  'analytics.dread.exploitability.label': 'E: Exploitability',
  'analytics.dread.exploitability.level1': 'Requires advanced skill or insider knowledge',
  'analytics.dread.exploitability.level2': 'Tools or procedures partially public',
  'analytics.dread.exploitability.level3': 'Easily exploitable with off-the-shelf tools',
  'analytics.dread.affectedUsers.label': 'A: Affected Users',
  'analytics.dread.affectedUsers.level1': 'A small subset of users',
  'analytics.dread.affectedUsers.level2': 'A significant number of users or tenants',
  'analytics.dread.affectedUsers.level3': 'All users, including administrators',
  'analytics.dread.discoverability.label': 'D: Discoverability',
  'analytics.dread.discoverability.level1': 'Hard to discover without insider knowledge',
  'analytics.dread.discoverability.level2': 'Discoverable with careful investigation',
  'analytics.dread.discoverability.level3': 'Easily discoverable from outside',
  'analytics.dread.level.low': 'Low',
  'analytics.dread.level.medium': 'Medium',
  'analytics.dread.level.high': 'High',
  'analytics.dread.heading': 'DREAD Assessment',
  'analytics.dread.totalLabel': 'Total',
  'analytics.dread.ruleSeverityTooltip': '(rule-derived: {severity})',
  'analytics.dread.scoredTooltip': 'DREAD scored (original severity: {severity})',
  'analytics.dread.clearButton': 'Clear score',
  'analytics.dread.saveButton': 'Save',

  // ── Filter bar / presets ──
  'analytics.filter.label': 'Filter',
  'analytics.filter.placeholder': 'ElementalID / name / category',
  'analytics.preset.all': 'All',
  'analytics.preset.highPlus': 'High or above',
  'analytics.preset.withMit': 'With mitigation',
  'analytics.preset.withoutMit': 'Without mitigation',

  'analytics.controlGroup.unset': 'Unset',

  'analytics.header.summary': 'Layer {layer} / {elements} elements / {threats} threats',

  'analytics.renumber.tooltip':
    'Closes gaps left by deletions and renumbers ElementalIDs from 1 across all layers',
  // Identity inventory ([[plan]] §2.40 step 2)
  'analytics.inventory.heading': 'Identity inventory ({count})',
  'analytics.inventory.note': 'Nodes in this diagram that can issue credentials, and what depends on them. Tier 1 is the components that declare this issuer (their authentication breaks if it falls), counting both the edge-side "Credential issuer" and the component-side identity dependency; Tier 2 is what is directly connected by an edge. A dependency declared in neither place is not counted, so the blast radius may be understated.',
  'analytics.inventory.tier1': 'Tier 1 dependents ({count})',
  'analytics.inventory.tier2': 'Tier 2 direct peers ({count})',
  'analytics.inventory.none': 'none',
  'analytics.renumber.button': 'Renumber IDs',
  'analytics.renumber.confirmBody':
    'Renumbers ElementalIDs (C / DF / Z) from 1 across all layers. IDs referenced in past reports may then point to different elements, and undo history will be cleared.',
  'analytics.renumber.confirmButton': 'Renumber',
  'analytics.renumber.cancelButton': 'Cancel',

  'analytics.tree.empty': 'No matching threats.',
  'analytics.tree.maxSeverityTooltip': 'Highest risk for this element',

  'analytics.countermeasures.heading': '{count} mitigations',
  'analytics.countermeasures.empty': 'No threats have a mitigation.',
  'analytics.countermeasureItem.title': '{severity} · {element}',

  'analytics.detail.empty': 'Select a threat.',
  'analytics.detail.mitigationLabel': 'Mitigation',
  'analytics.detail.riskTreatmentHeading': 'Risk Treatment',
  'analytics.detail.controlStatusHeading': 'Control Implementation Status',

  'analytics.unassigned.label': 'Threats not tied to an element',
  'analytics.unassigned.parenLabel': '(Threats not tied to an element)',

  'analytics.boundaryFallbackLabel': '{trustLevel} boundary',
  'analytics.edgeLabelWithFlow': '{base} ({flow})',

  // ── Compliance Map ──
  'analytics.compliance.standardsSummary': '{standards} standards / {total} items total',
  'analytics.compliance.itemsCount': '{count} items',
  'analytics.compliance.officialLink': 'Official reference',
  'analytics.compliance.license': 'License: {license}',
  'analytics.compliance.filterPlaceholder': 'Filter by ref / title / summary',
  'analytics.compliance.noItems': 'No matching items.',
  'analytics.compliance.selectPrompt': 'Select a standard from the list on the left.',
  'analytics.compliance.originalLinkTooltip': 'Original source link',
  'analytics.compliance.crosswalkTooltip': 'Corresponding item in another standard (crosswalk)',
};
