import type { TranslationKey } from '../ja';

/** English translation for the SBOM cryptography check (report, CLI, button). */
export const enSbomCrypto: Partial<Record<TranslationKey, string>> = {
  'sbomCrypto.title': 'Cryptography in the SBOM',
  'sbomCrypto.h.summary': '1. Summary',
  'sbomCrypto.h.algorithms': '2. Algorithms',
  'sbomCrypto.h.protocols': '3. Protocols',
  'sbomCrypto.h.certificates': '4. Certificates',
  'sbomCrypto.h.libraries': '5. Cryptographic libraries',
  'sbomCrypto.h.compare': '6. Comparison with the diagram',
  'sbomCrypto.h.limits': '7. Limits of this check',

  'sbomCrypto.summary.source': 'SBOM: {source} (CycloneDX {version})',
  'sbomCrypto.summary.node': 'Node: {id} {label}',
  'sbomCrypto.summary.counts': '{components} components, {assets} cryptographic assets, {libraries} cryptographic libraries',
  'sbomCrypto.summary.generated': 'Generated: {date} (by {product})',

  'sbomCrypto.col.name': 'Name',
  'sbomCrypto.col.primitive': 'Primitive',
  'sbomCrypto.col.parameterSet': 'Parameter set',
  'sbomCrypto.col.curve': 'Curve',
  'sbomCrypto.col.nist': 'NIST quantum security level (declared)',
  'sbomCrypto.col.verdict': 'Verdict',
  'sbomCrypto.col.type': 'Type',
  'sbomCrypto.col.version': 'Version',
  'sbomCrypto.col.cipherSuites': 'Cipher suites',
  'sbomCrypto.col.subject': 'Subject',
  'sbomCrypto.col.issuer': 'Issuer',
  'sbomCrypto.col.notValidAfter': 'Not valid after',
  'sbomCrypto.col.signature': 'Signature algorithm',
  'sbomCrypto.col.library': 'Library',
  'sbomCrypto.col.purl': 'purl',
  'sbomCrypto.col.role': 'Role',
  'sbomCrypto.col.note': 'Note',

  'sbomCrypto.role.tls': 'TLS and other channels',
  'sbomCrypto.role.general': 'General-purpose cryptography',
  'sbomCrypto.role.jwt': 'Token signing',
  'sbomCrypto.role.pqc': 'PQC only',

  'sbomCrypto.algorithms.none':
    'This SBOM lists no cryptographic assets (algorithms). A package-only SBOM (the default output of most SBOM tools) has no algorithm information, so use the libraries in section 5 to check which algorithms are in use.',
  'sbomCrypto.protocols.none': 'No protocols are listed.',
  'sbomCrypto.certificates.none': 'No certificates are listed.',
  'sbomCrypto.libraries.none': 'No component matched the cryptographic library list.',
  'sbomCrypto.libraries.unmatched': 'Components that did not match the list: {count} (not shown here)',

  'sbomCrypto.compare.lead':
    'These are candidates found in the SBOM. Use them as a reference for what to enter in the PQC layer. The diagram has not been changed.',
  'sbomCrypto.compare.notEntered': 'not entered',
  'sbomCrypto.compare.noCandidates': 'no candidates',
  'sbomCrypto.compare.nodeSignature': 'Node signature: diagram value {entered} / candidates from the SBOM {candidates}',
  'sbomCrypto.compare.edge':
    '{id} ({peer}): protocol {protocol}, version {version}, key exchange {kex} / key-exchange candidates from the SBOM {candidates}',
  'sbomCrypto.compare.noEdges': 'No data flow is connected to this node.',

  'sbomCrypto.limits.1':
    'Being in the SBOM does not mean the algorithm is used. A package can be present without the application calling it.',
  'sbomCrypto.limits.2':
    'Configuration can disable or pin algorithms. Also check the configuration and the actual traffic to see what is really used.',
  'sbomCrypto.limits.3':
    'A package-only SBOM (the default output of most SBOM tools) carries no algorithm information. In that case only the library list is shown.',
  'sbomCrypto.limits.4':
    "Library notes are summaries. Check each library's release notes for what a given version supports.",

  'sbomCrypto.error.notJson':
    'Only CycloneDX JSON can be read. Export again as JSON instead of XML or another format (for example --format cyclonedx-json).',
  'sbomCrypto.error.notCycloneDx': 'This is not a CycloneDX SBOM (JSON whose bomFormat is CycloneDX).',
  'sbomCrypto.error.tooLarge': 'Files larger than {mb} MB cannot be read.',

  'sbomCrypto.cli.missingSbom': 'Pass a CycloneDX JSON file with --sbom.',
  'sbomCrypto.cli.missingNode': 'Pass the ID of the target node (for example C3) with --node.',
  'sbomCrypto.cli.readFailed': 'Cannot read the SBOM: {file} ({reason})',
  'sbomCrypto.cli.nodeNotFound': 'Node "{node}" is not in {layer}. Available IDs: {ids}',
  'sbomCrypto.cli.done':
    'Wrote the SBOM cryptography check ({layer}, {node}, {assets} cryptographic assets, {libraries} cryptographic libraries)',

  'sbomCrypto.ui.button': 'Check cryptography from SBOM',
  'sbomCrypto.ui.hint':
    "Choose a CycloneDX JSON file to download a Markdown report of this node's cryptography. The diagram is not changed.",
  'sbomCrypto.ui.error': 'Could not read the file: {reason}',
};
