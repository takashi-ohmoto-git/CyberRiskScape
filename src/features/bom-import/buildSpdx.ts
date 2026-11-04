import { BRANDING } from '../../core/branding';
import type { BomComponent } from '../../core/model/types';

/**
 * 共通モデルの部品から SPDX 2.3 の JSON を作る純粋関数（docs/architecture.md §8.8）。
 * 暗号資産は SPDX 2.3 に載せる項目が無いので出さず、件数を返して文書のコメントにも書く
 * （§8.1「失うものを宣言する」）。依存関係は共通モデルに無いので出さない。
 */

export interface BuildSpdxOptions {
  name: string;
  /** ISO 8601。呼び出し側が現在時刻を渡す。 */
  created: string;
  /** 文書の名前空間（URI）。呼び出し側が一意の値を渡す。 */
  documentNamespace: string;
  toolVersion: string;
}

export interface BuildSpdxResult {
  document: Record<string, unknown>;
  packages: number;
  /** SPDX 2.3 に載らず出さなかった暗号資産の件数。 */
  omittedCrypto: number;
}

const SPDX_PURPOSES = new Set([
  'APPLICATION',
  'FRAMEWORK',
  'LIBRARY',
  'CONTAINER',
  'OPERATING-SYSTEM',
  'DEVICE',
  'FIRMWARE',
  'SOURCE',
  'ARCHIVE',
  'FILE',
  'INSTALL',
  'OTHER',
]);

const purposeOf = (c: BomComponent): string => {
  if (c.kind === 'ai-model' || c.kind === 'dataset') return 'OTHER';
  const upper = (c.sourceType ?? '').toUpperCase();
  return SPDX_PURPOSES.has(upper) ? upper : 'OTHER';
};

const KIND_COMMENT: Partial<Record<BomComponent['kind'], string>> = {
  'ai-model': 'AI model',
  dataset: 'Dataset',
};

/** 英数字・ピリオド・ハイフン以外は SPDXID に使えない。 */
const spdxIdOf = (index: number, name: string) =>
  `SPDXRef-Package-${index + 1}-${name.replace(/[^A-Za-z0-9.-]/g, '-').slice(0, 100)}`;

function externalRefsOf(c: BomComponent) {
  return c.identifiers.flatMap((id) => {
    if (id.scheme === 'purl') {
      return [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: id.value }];
    }
    if (id.scheme === 'cpe') {
      const referenceType = id.value.startsWith('cpe:2.3:') ? 'cpe23Type' : 'cpe22Type';
      return [{ referenceCategory: 'SECURITY', referenceType, referenceLocator: id.value }];
    }
    return [];
  });
}

export function buildSpdx(components: readonly BomComponent[], opts: BuildSpdxOptions): BuildSpdxResult {
  const included = components.filter((c) => c.kind !== 'crypto');
  const omittedCrypto = components.length - included.length;
  const sorted = [...included].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));

  const packages = sorted.map((c, i) => {
    const refs = externalRefsOf(c);
    const sha256 = c.identifiers.find((id) => id.scheme === 'sha-256')?.value;
    const comment = KIND_COMMENT[c.kind];
    return {
      SPDXID: spdxIdOf(i, c.name),
      name: c.name,
      ...(c.version ? { versionInfo: c.version } : {}),
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      primaryPackagePurpose: purposeOf(c),
      ...(comment ? { comment } : {}),
      ...(sha256 ? { checksums: [{ algorithm: 'SHA256', checksumValue: sha256 }] } : {}),
      ...(refs.length > 0 ? { externalRefs: refs } : {}),
    };
  });

  const notes = [
    'Generated from a threat model. Dependency relationships, licenses and suppliers are not included.',
    ...(omittedCrypto > 0 ? [`${omittedCrypto} cryptographic asset(s) omitted: SPDX 2.3 has no field for them.`] : []),
  ];

  return {
    document: {
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: opts.name,
      documentNamespace: opts.documentNamespace,
      creationInfo: {
        created: opts.created.replace(/\.\d+Z$/, 'Z'),
        creators: [`Tool: ${BRANDING.name}-${opts.toolVersion}`],
        comment: notes.join(' '),
      },
      packages,
      relationships: packages.map((p) => ({
        spdxElementId: 'SPDXRef-DOCUMENT',
        relationshipType: 'DESCRIBES',
        relatedSpdxElement: p.SPDXID,
      })),
    },
    packages: packages.length,
    omittedCrypto,
  };
}
