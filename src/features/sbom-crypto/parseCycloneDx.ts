import { z } from 'zod';
import { BUNDLED_CRYPTO_LIBRARIES } from '../../crypto-behavior/bundled';
import { matchCryptoLibrary } from '../../crypto-behavior/loader';
import type { CryptoLibrary } from '../../crypto-behavior/schema';
import { translate, type Locale } from '../../i18n';

/**
 * CycloneDX（JSON、1.6 / 1.7）の SBOM／CBOM から、暗号に関わる項目だけを取り出す純粋関数。
 *
 * - 緩く検証する（未知のキーは無視）。取り出す項目は下の型に載せたものだけ。
 *   鍵の値になりうる `relatedCryptoMaterialProperties.value` は読まない・保持しない
 *   （zod の object は未知キーを落とすので、スキーマに書かないことで保証している）。
 * - XML は読まない（JSON のみ）。
 */

export interface AlgorithmAsset {
  kind: 'algorithm';
  ref?: string;
  name: string;
  primitive?: string;
  parameterSetIdentifier?: string;
  curve?: string;
  ellipticCurve?: string;
  nistQuantumSecurityLevel?: number;
}

export interface ProtocolAsset {
  kind: 'protocol';
  ref?: string;
  name: string;
  type?: string;
  version?: string;
  cipherSuites: string[];
}

export interface CertificateAsset {
  kind: 'certificate';
  ref?: string;
  name: string;
  subjectName?: string;
  issuerName?: string;
  notValidAfter?: string;
  signatureAlgorithmRef?: string;
  subjectPublicKeyRef?: string;
}

export interface MaterialAsset {
  kind: 'material';
  ref?: string;
  name: string;
  type?: string;
  algorithmRef?: string;
  size?: number;
}

/** assetType が上の 4 つ以外（将来の種別）。名前だけ持つ。 */
export interface OtherAsset {
  kind: 'other';
  ref?: string;
  name: string;
}

export type CryptoAsset = AlgorithmAsset | ProtocolAsset | CertificateAsset | MaterialAsset | OtherAsset;

export interface SbomPackage {
  name: string;
  version?: string;
  /** 修飾子（?）とサブパス（#）を除いた purl。 */
  purl?: string;
  /** 暗号ライブラリの一覧に当たったときの id。 */
  libraryId?: string;
}

export type ParsedSbom =
  | {
      ok: true;
      specVersion: string;
      componentCount: number;
      cryptoAssets: CryptoAsset[];
      packages: SbomPackage[];
    }
  | { ok: false; error: string };

/** 型違いの項目は落とすだけで、部品ごと捨てない。 */
const str = z.string().optional().catch(undefined);
const num = z.number().optional().catch(undefined);

const ComponentSchema = z.object({
  type: str,
  name: str,
  version: str,
  purl: str,
  'bom-ref': str,
  cryptoProperties: z
    .object({
      assetType: str,
      algorithmProperties: z
        .object({
          primitive: str,
          parameterSetIdentifier: str,
          curve: str,
          ellipticCurve: str,
          nistQuantumSecurityLevel: num,
        })
        .optional()
        .catch(undefined),
      protocolProperties: z
        .object({
          type: str,
          version: str,
          cipherSuites: z
            .array(z.object({ name: str }))
            .optional()
            .catch(undefined),
        })
        .optional()
        .catch(undefined),
      certificateProperties: z
        .object({
          subjectName: str,
          issuerName: str,
          notValidAfter: str,
          signatureAlgorithmRef: str,
          subjectPublicKeyRef: str,
        })
        .optional()
        .catch(undefined),
      // value（鍵の値になりうる）は意図して書かない。
      relatedCryptoMaterialProperties: z
        .object({ type: str, algorithmRef: str, size: num })
        .optional()
        .catch(undefined),
    })
    .optional()
    .catch(undefined),
  components: z.array(z.unknown()).optional().catch(undefined),
});

const BomSchema = z.object({
  bomFormat: z.literal('CycloneDX'),
  specVersion: z.string(),
  components: z.array(z.unknown()).optional().catch(undefined),
});

/** purl から修飾子とサブパスを除く（版は残す）。 */
const stripPurl = (purl: string) => purl.replace(/[#?].*$/, '');

function toAsset(c: z.infer<typeof ComponentSchema>): CryptoAsset {
  const p = c.cryptoProperties;
  const base = { ref: c['bom-ref'], name: c.name ?? '' };
  if (p?.assetType === 'algorithm') {
    const a = p.algorithmProperties;
    return {
      kind: 'algorithm',
      ...base,
      primitive: a?.primitive,
      parameterSetIdentifier: a?.parameterSetIdentifier,
      curve: a?.curve,
      ellipticCurve: a?.ellipticCurve,
      nistQuantumSecurityLevel: a?.nistQuantumSecurityLevel,
    };
  }
  if (p?.assetType === 'protocol') {
    const a = p.protocolProperties;
    const suites = (a?.cipherSuites ?? []).flatMap((s) => (s.name ? [s.name] : []));
    return { kind: 'protocol', ...base, type: a?.type, version: a?.version, cipherSuites: suites };
  }
  if (p?.assetType === 'certificate') {
    return { kind: 'certificate', ...base, ...p.certificateProperties };
  }
  if (p?.assetType === 'related-crypto-material') {
    return { kind: 'material', ...base, ...p.relatedCryptoMaterialProperties };
  }
  return { kind: 'other', ...base };
}

/** 解析済みの JSON（`JSON.parse` の結果）を読む。 */
export function parseCycloneDx(
  input: unknown,
  libraries: readonly CryptoLibrary[] = BUNDLED_CRYPTO_LIBRARIES,
  locale: Locale = 'ja',
): ParsedSbom {
  const bom = BomSchema.safeParse(input);
  if (!bom.success) return { ok: false, error: translate('sbomCrypto.error.notCycloneDx', locale) };

  const cryptoAssets: CryptoAsset[] = [];
  const packages: SbomPackage[] = [];
  let componentCount = 0;

  const walk = (items: readonly unknown[]) => {
    for (const raw of items) {
      const parsed = ComponentSchema.safeParse(raw);
      if (!parsed.success) continue;
      const c = parsed.data;
      componentCount += 1;
      if (c.type === 'cryptographic-asset') {
        cryptoAssets.push(toAsset(c));
      } else {
        const name = c.name ?? '';
        const purl = c.purl ? stripPurl(c.purl) : undefined;
        packages.push({
          name,
          version: c.version,
          purl,
          libraryId: matchCryptoLibrary({ name, purl }, libraries)?.id,
        });
      }
      if (c.components) walk(c.components);
    }
  };
  walk(bom.data.components ?? []);

  return { ok: true, specVersion: bom.data.specVersion, componentCount, cryptoAssets, packages };
}

/** ファイルの中身（文字列）を読む。JSON でない（XML など）ときは、JSON だけ読める旨のエラーを返す。 */
export function parseSbomText(
  text: string,
  libraries: readonly CryptoLibrary[] = BUNDLED_CRYPTO_LIBRARIES,
  locale: Locale = 'ja',
): ParsedSbom {
  let json: unknown;
  try {
    json = JSON.parse(text.replace(/^\uFEFF/, ''));
  } catch {
    return { ok: false, error: translate('sbomCrypto.error.notJson', locale) };
  }
  return parseCycloneDx(json, libraries, locale);
}
