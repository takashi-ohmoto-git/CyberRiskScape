import type { TranslationKey } from '../ja';

/** English translation for the security requirements list (Markdown / CSV). */
export const enRequirements: Partial<Record<TranslationKey, string>> = {
  'requirements.title': 'Security requirements (draft): {system} ({layer})',
  'requirements.disclaimer':
    'This list is a draft derived mechanically from the threat model. People decide adoption, priority, and what to request from contractors.',
  'requirements.system': 'System: {system}',
  'requirements.generated': 'Generated: {date} ({product}, from the threat model)',
  'requirements.howTo':
    'Each requirement is a mitigation of a threat, split into tiers (Foundation / Enterprise / Advanced). Choose the tiers you need at design time and carry them into your requirements document or contractor specifications.',
  'requirements.h.list': 'Requirements',
  'requirements.none': 'No detected threat has a mitigation that can be turned into a requirement.',
  'requirements.col.id': 'ID',
  'requirements.col.tier': 'Tier',
  'requirements.col.text': 'Requirement',
  'requirements.col.targets': 'Target nodes',
  'requirements.col.basis': 'Basis threats',
  'requirements.col.severity': 'Max severity',
  'requirements.col.stage': 'Stage',
  'requirements.col.csf': 'NIST CSF 2.0',
  'requirements.col.contractor': 'Request to contractors',
  'requirements.col.status': 'Status',
  'requirements.yes': 'Yes',
  'requirements.accepted': 'Risk accepted (decided not to implement)',
  'requirements.accepted.note': 'Risk accepted (decided not to implement: {note})',
  'requirements.h.contractor': 'Example requirements to request from contractors',
  'requirements.contractor.lead':
    'Only items whose triggering threats appear in the diagram are listed. Use them as a starting point for contracts and specifications.',
  'requirements.contractor.basis': 'basis: {threats}',
  'project.sidebar.exportRequirements': 'Security requirements (draft)',
};
