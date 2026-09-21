import type { TranslationKey } from '../ja';

/** Sidebar, top bar, project modals (English). Missing keys fall back to Japanese. */
export const enProject: Partial<Record<TranslationKey, string>> = {
  // ── Common ──
  'project.common.close': 'Close',
  'project.common.cancel': 'Cancel',
  'project.common.save': 'Save',
  'project.common.saving': 'Saving…',

  // ── LeftSidebar ──
  'project.sidebar.untitled': 'No project set',
  'project.sidebar.depthLayer': 'Depth layer ({layer})',
  'project.sidebar.layerDesc.L0': 'Business-logic focused (filled in by the business side)',
  'project.sidebar.layerDesc.L1': 'Detailed design (security staff, usually as far as needed)',
  'project.sidebar.layerDesc.L2': 'Extra detail for higher-confidentiality cases',
  'project.sidebar.layerDesc.L3': 'Even more rigorous detail',
  'project.sidebar.reportSummary': 'Export the currently displayed threats ({layer} / {framework} · {count} items)',
  'project.sidebar.exportCsv': 'Download CSV',
  'project.sidebar.exportJson': 'Download JSON',
  'project.sidebar.exportDcrh': 'DCRH THREAT_MODEL.md (Anthropic-compatible)',
  'project.sidebar.newProject': 'New project',
  'project.sidebar.fileMenu': 'File (Save / Open)',
  'project.sidebar.saveStateSaved': 'Saved',
  'project.sidebar.saveStateError': 'Save failed',
  'project.sidebar.usageHint1': '🔹 Select a part and connect it with "Create Link"',
  'project.sidebar.usageHint2': '🔹 Connectors can be used as waypoints',

  // ── TopControls ──
  'project.topControls.undo': 'Undo (Ctrl+Z)',
  'project.topControls.redo': 'Redo (Ctrl+Shift+Z)',
  'project.topControls.openAnalytics': 'Open Analytics (active layer analysis)',
  'project.topControls.openComplianceMap': 'Open compliance map',
  'project.topControls.zoomOut': 'Zoom out',
  'project.topControls.resetZoom': 'Reset to 100%',
  'project.topControls.zoomIn': 'Zoom in',
  'project.topControls.fitToContent': 'Fit to content',

  // ── ProjectFileModal ──
  'project.fileModal.pickFailed': 'Failed to select folder: {message}',
  'project.fileModal.permissionDenied': 'Folder access was not granted.',
  'project.fileModal.saved': 'Saved "{name}".',
  'project.fileModal.saveFailed': 'Failed to save: {message}',
  'project.fileModal.readFailed': 'Failed to load: {message}',
  'project.fileModal.title': 'File (Save / Open)',
  'project.fileModal.unsupported':
    "This browser doesn't support folder saving (File System Access API). Please use Chrome or Edge. Your work is still auto-saved in the browser (IndexedDB) and won't be lost on reload.",
  'project.fileModal.saveFolder': 'Save folder',
  'project.fileModal.notSelected': 'Not selected',
  'project.fileModal.needsReconnect': ' (reconnect needed)',
  'project.fileModal.connect': 'Connect',
  'project.fileModal.change': 'Change',
  'project.fileModal.select': 'Select',
  'project.fileModal.tabSave': 'Save (this project)',
  'project.fileModal.tabOpen': 'Open (from list)',
  'project.fileModal.filenameLabel': 'File name',
  'project.fileModal.filenamePlaceholder': 'e.g. CreditScoringAPI.json',
  'project.fileModal.overwriteWarning':
    'A file with this name already exists. Press "Overwrite" to replace it.',
  'project.fileModal.overwriteButton': 'Overwrite',
  'project.fileModal.selectFolderFirst': 'Please select a save folder first.',
  'project.fileModal.reconnectNeeded':
    'Folder access has been lost. Press "Connect" above to show the list.',
  'project.fileModal.noFiles': 'No saved projects (.json) in this folder.',

  // ── ProjectEditModal ──
  'project.editModal.nameLabel': 'Project name',
  'project.editModal.namePlaceholder': 'e.g. Credit scoring service threat model',
  'project.editModal.systemNameLabel': 'System name',
  'project.editModal.systemNamePlaceholder': 'e.g. CreditScoringAPI v2',
  'project.editModal.purposeLabel': 'System purpose',
  'project.editModal.purposePlaceholder':
    'Briefly describe the problem this system solves and the value it provides.',
  'project.editModal.businessImpactLabel': 'Business impact',
  'project.editModal.businessImpactPlaceholder':
    'Business impact if this system is disrupted or breached (cost, duration, affected customers, etc.).',
  'project.editModal.securityObjectivesLabel': 'Security objectives',
  'project.editModal.securityObjectivesPlaceholder':
    'Confidentiality, integrity, and availability goals to protect. Used as the basis for prioritizing threats.',

  // ── NewProjectModal ──
  'project.newModal.title': 'New project',
  'project.newModal.confirmMessage':
    'This will clear your current work and create a blank new project. Save the current project to a file before creating it?',
  'project.newModal.warning':
    'If you create without saving, your current diagram, manual threats, risk scores, etc. will be lost.',
  'project.newModal.createWithoutSaving': 'Create without saving',
  'project.newModal.saveAndCreate': 'Save and create',

  // ── TemplateModal ──
  'project.templateModal.defaultName': '{layer} template',
  'project.templateModal.tabExport': 'Export',
  'project.templateModal.tabImport': 'Import',
  'project.templateModal.exportIntroBefore': 'Export the diagram of the current active layer (',
  'project.templateModal.exportIntroAfter': ' · {count} items) as a template.',
  'project.templateModal.nameLabel': 'Template name',
  'project.templateModal.namePlaceholder': 'e.g. Standard 3-tier web architecture',
  'project.templateModal.download': 'Download',
  'project.templateModal.importIntro1': 'Load a template JSON and apply it to the active layer (',
  'project.templateModal.importIntro2': ') by',
  'project.templateModal.replaceWord': ' replacing it',
  'project.templateModal.importIntro3': '. You will be asked to confirm if elements already exist.',
  'project.templateModal.selectFile': 'Select JSON file',
  'project.templateModal.importedOpenQuote': '"',
  'project.templateModal.importedStats': '" — Nodes {nodes} / Edges {edges} / Boundaries {boundaries}',
  'project.templateModal.confirmReplace':
    '{layer} already has {count} elements. They will be discarded and replaced with the template. Press "Replace" to apply (you can restore with Undo).',
  'project.templateModal.replaceButton': 'Replace',
  'project.templateModal.replaceAndApply': 'Replace and apply',
  'project.templateModal.apply': 'Apply',
};
