import type { TranslationKey } from '../ja';

/** Analytics, compliance, attack path (English). Missing keys fall back to Japanese. */
export const enAnalytics: Partial<Record<TranslationKey, string>> = {
  'analytics.close': 'Close',

  // ── Risk assessment form (Impact × Likelihood, 2 axes) ──
  'analytics.risk.damage.label': 'Damage',
  'analytics.risk.damage.level1': 'Minor disruption or limited information exposure',
  'analytics.risk.damage.level2': 'Partial data leakage or tampering',
  'analytics.risk.damage.level3': 'Full data breach or complete system outage',
  'analytics.risk.affectedUsers.label': 'Affected Users',
  'analytics.risk.affectedUsers.level1': 'A small subset of users',
  'analytics.risk.affectedUsers.level2': 'A significant number of users or tenants',
  'analytics.risk.affectedUsers.level3': 'All users, including administrators',
  'analytics.risk.reproducibility.label': 'Reproducibility',
  'analytics.risk.reproducibility.level1': 'Rarely reproducible under specific conditions',
  'analytics.risk.reproducibility.level2': 'Reproducible when conditions align',
  'analytics.risk.reproducibility.level3': 'Always reproducible',
  'analytics.risk.exploitability.label': 'Exploitability',
  'analytics.risk.exploitability.level1': 'Requires advanced skill or insider knowledge',
  'analytics.risk.exploitability.level2': 'Tools or procedures partially public',
  'analytics.risk.exploitability.level3': 'Easily exploitable with off-the-shelf tools',
  'analytics.risk.level.low': 'Low',
  'analytics.risk.level.medium': 'Medium',
  'analytics.risk.level.high': 'High',
  'analytics.risk.heading': 'Risk Assessment',
  'analytics.risk.impactHeading': 'Impact (damage, affected users)',
  'analytics.risk.likelihoodHeading': 'Likelihood (reproducibility, exploitability)',
  'analytics.risk.previewLine': 'Impact {impact} / Likelihood {likelihood} →',
  'analytics.risk.ruleSeverityTooltip': '(rule-derived: {severity})',
  'analytics.risk.scoredTooltip': 'Risk scored (original severity: {severity})',
  'analytics.risk.scoredBadge': 'Risk {impact}×{likelihood}',
  'analytics.risk.clearButton': 'Clear score',
  'analytics.risk.saveButton': 'Save',

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
