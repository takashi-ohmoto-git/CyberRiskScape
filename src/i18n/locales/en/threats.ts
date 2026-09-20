import type { TranslationKey } from '../ja';

/** Threat cards, manual threats, treatments (English). Missing keys fall back to Japanese. */
export const enThreats: Partial<Record<TranslationKey, string>> = {
  // ── ThreatCard ──
  'threats.threatCard.manualTypeRuleHint':
    'Custom rule applied to all nodes of this type. Editing or deleting it affects the entire rule.',
  'threats.threatCard.manualTypeRuleLabel': 'Type rule: {label}',
  'threats.threatCard.corroborationHint':
    'Multiple sources flag this same threat (all listed under References).',
  'threats.threatCard.corroborationSources': '{count} sources',
  'threats.threatCard.mitigationHeadingTiered': 'Mitigations (3-tier maturity)',
  'threats.threatCard.mitigationHeading': 'Mitigations',
  'threats.threatCard.complianceHeading': 'Compliance',
  'threats.threatCard.referencesHeading': 'References',
  'threats.threatCard.controlStatusHeading': 'Control implementation status',
  'threats.threatCard.riskTreatmentHeading': 'Risk treatment',
  'threats.threatCard.editButton': 'Edit',
  'threats.threatCard.deleteButton': 'Delete',

  // ── ManualThreatModal ──
  'threats.manualThreatModal.editTitle': 'Edit scenario',
  'threats.manualThreatModal.addTitle': 'Add scenario',
  'threats.manualThreatModal.close': 'Close',
  'threats.manualThreatModal.frameworkLabel': 'Framework',
  'threats.manualThreatModal.frameworkFixedHint': 'Fixed at creation time',
  'threats.manualThreatModal.categoryLabel': 'Threat category / title',
  'threats.manualThreatModal.categoryPlaceholder': 'e.g. Customer data exfiltration by an insider',
  'threats.manualThreatModal.severityLabel': 'Severity',
  'threats.manualThreatModal.targetLabel': 'Target',
  'threats.manualThreatModal.targetOptionWhole': 'Whole project (no node specified)',
  'threats.manualThreatModal.targetGroupType': 'Type: {label} (applies to all nodes of this type)',
  'threats.manualThreatModal.targetGroupNode': 'Placed nodes (this instance only)',
  'threats.manualThreatModal.targetTypeHint':
    'Choosing a type creates a project-local custom rule applied to all nodes of that type on the active layer.',
  'threats.manualThreatModal.descriptionLabel': 'Threat description',
  'threats.manualThreatModal.descriptionPlaceholder':
    'Describe the anticipated attack scenario, preconditions, and impact.',
  'threats.manualThreatModal.mitigationLabel': 'Mitigation (optional)',
  'threats.manualThreatModal.mitigationPlaceholder': 'Describe the controls or mitigations for this threat.',
  'threats.manualThreatModal.cancel': 'Cancel',

  // ── ControlStatusEditor / RiskTreatmentEditor 共通 ──
  'threats.editor.current': 'Current:',
  'threats.editor.unset': 'Not set',
  'threats.editor.reset': 'Reset',
  'threats.editor.save': 'Save',

  // ── ControlStatusEditor ──
  'threats.controlStatusEditor.notePlaceholderRequired': 'Record the reason / implementation approach (required)',
  'threats.controlStatusEditor.notePlaceholderOptional': 'Notes (optional)',
  'threats.controlStatusEditor.noteRequiredWarning': '"{label}" requires a note.',

  // ── RiskTreatmentEditor ──
  'threats.riskTreatmentEditor.notePlaceholder': 'Rationale, residual risk notes, etc. (optional)',

  // ── controlStatusStyle ──
  'threats.controlStatus.implemented': 'Implemented',
  'threats.controlStatus.required': 'Required',
  'threats.controlStatus.notApplicable': 'Not applicable',
  'threats.controlStatus.rejected': 'Rejected',

  // ── riskTreatmentStyle ──
  'threats.riskTreatment.avoid': 'Avoid',
  'threats.riskTreatment.reduce': 'Mitigate',
  'threats.riskTreatment.transfer': 'Transfer',
  'threats.riskTreatment.accepted': 'Accepted',
  'threats.riskTreatment.falsePositive': 'False positive',

  // ── ThreatListPanel ──
  'threats.list.addScenario': 'Add scenario',
  'threats.list.suppressedShow': 'Show {count} suppressed',
  'threats.list.suppressedHide': 'Hide {count} suppressed',
  'threats.list.empty': 'No threats detected',
  'threats.list.typeTarget': '{type} type (no matching node)',
  'threats.list.wholeProject': 'Whole project',
};
