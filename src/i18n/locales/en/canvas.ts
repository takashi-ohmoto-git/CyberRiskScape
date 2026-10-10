import type { TranslationKey } from '../ja';

/** Canvas (legend, node rendering, linking) and drawing constants (English). */
export const enCanvas: Partial<Record<TranslationKey, string>> = {
  'canvas.legend.open': 'Open legend',
  'canvas.legend.close': 'Close legend',
  'canvas.legend.title': 'Legend',
  'canvas.legend.components': 'Components',
  'canvas.legend.dataFlow': 'Data flow',
  'canvas.legend.trustBoundary': 'Trust boundary',

  'canvas.node.overflowCount': '+{count} more',

  'canvas.linking.inProgress': 'Creating a link... click another component',
  'canvas.linking.cancel': 'Cancel',

  'canvas.boundaryType.rect': 'External boundary',
  'canvas.boundaryType.dmz': 'DMZ',
  'canvas.boundaryType.macro': 'Macro segmentation',
  'canvas.boundaryType.micro': 'Micro segmentation',
  'canvas.boundaryType.blastRadius': 'Blast radius',

  'canvas.edgeNotation.plain': 'Plaintext (unencrypted)',
  'canvas.edgeNotation.encrypted': 'Encrypted (TLS / E2EE)',
  'canvas.edgeNotation.highRisk': 'High-risk path (unauthenticated × Internet)',
  'canvas.edgeNotation.crossing': 'Trust boundary crossing',
  'canvas.edgeNotation.crossingAuthNone': 'Crossing: unauthenticated',
  'canvas.edgeNotation.crossingAuthPassword': 'Crossing: password (ZTMM Traditional)',
  'canvas.edgeNotation.crossingAuthApiKey': 'Crossing: API key (ZTMM Traditional)',
  'canvas.edgeNotation.crossingAuthToken': 'Crossing: token (ZTMM Initial)',
  'canvas.edgeNotation.crossingAuthPasskey': 'Crossing: passkey (ZTMM Advanced)',
  'canvas.edgeNotation.crossingAuthCertificate': 'Crossing: certificate (ZTMM Advanced)',
  'canvas.edgeNotation.crossingAuthMfa': 'Crossing: MFA (ZTMM Traditional)',

  // ── Canvas annotations ──
  'canvas.annotation.defaultLabelText': 'Text label',
  'canvas.annotation.defaultCalloutText': 'Callout',
};
