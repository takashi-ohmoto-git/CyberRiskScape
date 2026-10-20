import { BRANDING } from '../../core/branding';
import { translate, type TranslationKey } from '../../i18n';
import { mdCell } from '../export/threatReport';
import type { SbomCryptoReport, SbomVerdict } from './buildSbomCryptoReport';

/** SBOM の暗号の確認レポートを Markdown / JSON に整形する。 */

const VERDICT_KEY: Record<SbomVerdict, TranslationKey> = {
  pqc: 'panels.crypto.class.pqc',
  transitional: 'panels.crypto.class.transitional',
  vulnerable: 'panels.crypto.class.vulnerable',
  unknown: 'panels.crypto.class.unknown',
};

export function sbomCryptoToMarkdown(report: SbomCryptoReport): string {
  const t = (key: TranslationKey, params?: Record<string, string | number>) =>
    translate(key, report.locale, params);
  const s = report.summary;
  const dash = '-';
  const cell = (v: string | number | null) => (v === null ? dash : mdCell(String(v)));
  const table = (heads: TranslationKey[], rows: (string | number | null)[][]) => [
    `| ${heads.map((h) => mdCell(t(h))).join(' | ')} |`,
    `| ${heads.map(() => '---').join(' | ')} |`,
    ...rows.map((r) => `| ${r.map(cell).join(' | ')} |`),
    '',
  ];
  const verdict = (v: SbomVerdict) => t(VERDICT_KEY[v]);
  const out: string[] = [`# ${t('sbomCrypto.title')}`, ''];

  out.push(`## ${t('sbomCrypto.h.summary')}`, '');
  out.push(`- ${t('sbomCrypto.summary.source', { source: s.sourceName, version: s.specVersion })}`);
  out.push(`- ${t('sbomCrypto.summary.node', { id: s.node.id, label: s.node.label })}`);
  out.push(
    `- ${t('sbomCrypto.summary.counts', { components: s.componentCount, assets: s.cryptoAssetCount, libraries: s.libraryCount })}`,
  );
  out.push(`- ${t('sbomCrypto.summary.generated', { date: s.generatedAt, product: BRANDING.name })}`, '');

  out.push(`## ${t('sbomCrypto.h.algorithms')}`, '');
  if (report.algorithms.length === 0) out.push(t('sbomCrypto.algorithms.none'), '');
  else {
    out.push(
      ...table(
        [
          'sbomCrypto.col.name',
          'sbomCrypto.col.primitive',
          'sbomCrypto.col.parameterSet',
          'sbomCrypto.col.curve',
          'sbomCrypto.col.nist',
          'sbomCrypto.col.verdict',
        ],
        report.algorithms.map((a) => [
          a.name,
          a.primitive,
          a.parameterSetIdentifier,
          a.curve,
          a.nistQuantumSecurityLevel,
          verdict(a.verdict),
        ]),
      ),
    );
  }

  out.push(`## ${t('sbomCrypto.h.protocols')}`, '');
  if (report.protocols.length === 0) out.push(t('sbomCrypto.protocols.none'), '');
  else {
    out.push(
      ...table(
        ['sbomCrypto.col.name', 'sbomCrypto.col.type', 'sbomCrypto.col.version', 'sbomCrypto.col.cipherSuites'],
        report.protocols.map((p) => [
          p.name,
          p.type,
          p.version,
          p.cipherSuites.length === 0 ? null : p.cipherSuites.map((c) => `${c.name}（${verdict(c.verdict)}）`).join(', '),
        ]),
      ),
    );
  }

  out.push(`## ${t('sbomCrypto.h.certificates')}`, '');
  if (report.certificates.length === 0) out.push(t('sbomCrypto.certificates.none'), '');
  else {
    out.push(
      ...table(
        [
          'sbomCrypto.col.name',
          'sbomCrypto.col.subject',
          'sbomCrypto.col.issuer',
          'sbomCrypto.col.notValidAfter',
          'sbomCrypto.col.signature',
          'sbomCrypto.col.verdict',
        ],
        report.certificates.map((c) => [
          c.name,
          c.subjectName,
          c.issuerName,
          c.notValidAfter,
          c.signatureAlgorithm,
          verdict(c.verdict),
        ]),
      ),
    );
  }

  out.push(`## ${t('sbomCrypto.h.libraries')}`, '');
  if (report.libraries.length === 0) out.push(t('sbomCrypto.libraries.none'), '');
  else {
    out.push(
      ...table(
        [
          'sbomCrypto.col.library',
          'sbomCrypto.col.name',
          'sbomCrypto.col.version',
          'sbomCrypto.col.purl',
          'sbomCrypto.col.role',
          'sbomCrypto.col.note',
        ],
        report.libraries.map((l) => [l.label, l.name, l.version, l.purl, t(`sbomCrypto.role.${l.role}`), l.note]),
      ),
    );
  }
  out.push(t('sbomCrypto.libraries.unmatched', { count: report.unmatchedPackageCount }), '');

  out.push(`## ${t('sbomCrypto.h.compare')}`, '');
  out.push(t('sbomCrypto.compare.lead'), '');
  const notEntered = t('sbomCrypto.compare.notEntered');
  const list = (xs: string[]) => (xs.length === 0 ? t('sbomCrypto.compare.noCandidates') : xs.join(', '));
  const c = report.comparison;
  out.push(
    `- ${t('sbomCrypto.compare.nodeSignature', { entered: c.nodeSignature.entered ?? notEntered, candidates: list(c.nodeSignature.candidates) })}`,
  );
  if (c.edges.length === 0) out.push('', t('sbomCrypto.compare.noEdges'));
  for (const e of c.edges) {
    out.push(
      `- ${t('sbomCrypto.compare.edge', {
        id: e.id,
        peer: e.peer,
        protocol: e.entered.protocol ?? notEntered,
        version: e.entered.version ?? notEntered,
        kex: e.entered.kex ?? notEntered,
        candidates: list(e.keyExchangeCandidates),
      })}`,
    );
  }
  out.push('');

  out.push(`## ${t('sbomCrypto.h.limits')}`, '');
  for (const k of [1, 2, 3, 4] as const) out.push(`- ${t(`sbomCrypto.limits.${k}`)}`);

  return `${out.join('\n').trimEnd()}\n`;
}

/** JSON は SbomCryptoReport をそのまま出す（キーは英語）。 */
export function sbomCryptoToJson(report: SbomCryptoReport): string {
  return JSON.stringify(report, null, 2);
}
