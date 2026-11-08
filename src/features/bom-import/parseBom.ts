import { z } from 'zod';
import { toIsoTimestamp } from '../../core/model/assetIdentity';
import { stripPurl } from '../../core/model/purl';
import type { BomCryptoProperties, BomFormat, BomKind, FindingIdentifier } from '../../core/model/types';

/**
 * CycloneDX（JSON）と SPDX 2.x（JSON）の BOM から、共通モデルの部品に必要な項目だけを読む。
 * DOM にも Node にも依存しない純粋関数（docs/architecture.md §8.8）。
 *
 * - 許可した項目だけを読む。暗号の鍵の値（`relatedCryptoMaterialProperties.value`）は読まない
 * - purl の修飾子は取得元の URL が入ることがあるので除く
 * - 型違いの項目は落とすだけで、部品ごと捨てない
 * - ライセンスは SPDX の ID か式だけを持つ（適否は判定しない）。CycloneDX の vulnerabilities（VEX を含む）は
 *   本文を読まず、ID・別名・評価・影響部品・状態だけを返す（指摘への変換は vulnerabilitiesToFindings.ts）
 * - 依存関係・提供元・証拠・外部参照は持たない
 */

export interface ParsedBomItem {
  externalId: string;
  identifiers: FindingIdentifier[];
  kind: BomKind;
  sourceType?: string;
  name: string;
  version?: string;
  licenses?: string[];
  crypto?: BomCryptoProperties;
}

/** CycloneDX の vulnerabilities[] の 1 件（本文類は読まない）。affects は bom-ref を部品に解決済み。 */
export interface ParsedVulnerability {
  id: string;
  /** source.name */
  source?: string;
  references: { id: string; source?: string }[];
  ratings: { score?: number; severity?: string; method?: string; vector?: string }[];
  /** analysis.state（VEX） */
  state?: string;
  affects: ParsedBomItem[];
}

export type ParsedBom =
  | { ok: true; format: BomFormat; specVersion: string; product: string; productVersion?: string; observedAt?: string; items: ParsedBomItem[]; vulnerabilities?: ParsedVulnerability[] }
  | { ok: false; error: string };

const str = z.string().max(2000).optional().catch(undefined);
const num = z.number().optional().catch(undefined);
const list = <T extends z.ZodTypeAny>(item: T) =>
  z.array(z.unknown()).optional().catch(undefined).transform((rows) =>
    (rows ?? []).flatMap((row) => {
      const parsed = item.safeParse(row);
      return parsed.success ? [parsed.data as z.output<T>] : [];
    }),
  );

const MAX_LICENSES = 10;
/** NOASSERTION・NONE は捨て、重複を除いて最大 10 件にする。 */
function normalizeLicenses(raw: readonly (string | undefined)[]): string[] {
  const out = new Set<string>();
  for (const r of raw) {
    const v = r?.trim().slice(0, 200);
    if (v && v !== 'NOASSERTION' && v !== 'NONE') out.add(v);
  }
  return [...out].slice(0, MAX_LICENSES);
}

const CycloneDxComponentSchema = z.object({
  type: str,
  licenses: list(
    z.object({
      license: z.object({ id: str, name: str }).optional().catch(undefined),
      expression: str,
    }),
  ),
  name: str,
  version: str,
  purl: str,
  cpe: str,
  'bom-ref': str,
  hashes: list(z.object({ alg: str, content: str })),
  cryptoProperties: z
    .object({
      assetType: str,
      algorithmProperties: z
        .object({ primitive: str, parameterSetIdentifier: str, curve: str, ellipticCurve: str, nistQuantumSecurityLevel: num })
        .optional()
        .catch(undefined),
      protocolProperties: z
        .object({ version: str, cipherSuites: list(z.object({ name: str })) })
        .optional()
        .catch(undefined),
      certificateProperties: z.object({ notValidAfter: str }).optional().catch(undefined),
    })
    .optional()
    .catch(undefined),
  components: z.array(z.unknown()).optional().catch(undefined),
});

const CycloneDxSchema = z.object({
  bomFormat: z.literal('CycloneDX'),
  specVersion: z.string().max(20),
  metadata: z
    .object({
      timestamp: str,
      tools: z.unknown().optional(),
    })
    .optional()
    .catch(undefined),
  components: z.array(z.unknown()).max(200_000).optional().catch(undefined),
  vulnerabilities: z.array(z.unknown()).max(200_000).optional().catch(undefined),
});

const CycloneDxVulnerabilitySchema = z.object({
  id: z.string().min(1).max(200),
  source: z.object({ name: str }).optional().catch(undefined),
  references: list(z.object({ id: z.string().min(1).max(200), source: z.object({ name: str }).optional().catch(undefined) })),
  ratings: list(z.object({ score: num, severity: str, method: str, vector: str })),
  analysis: z.object({ state: str }).optional().catch(undefined),
  affects: list(z.object({ ref: str })),
});

const ToolSchema = z.object({ name: str, version: str });
/** 1.5 以降は `tools.components`、それより前は `tools` が配列。 */
function cycloneDxTool(tools: unknown): { name?: string; version?: string } {
  const rows = Array.isArray(tools)
    ? tools
    : z.object({ components: z.array(z.unknown()) }).safeParse(tools).data?.components;
  const first = rows?.[0];
  return first ? (ToolSchema.safeParse(first).data ?? {}) : {};
}

const CYCLONEDX_KINDS: Record<string, BomKind> = {
  application: 'software',
  framework: 'software',
  library: 'software',
  container: 'software',
  platform: 'software',
  'operating-system': 'software',
  device: 'software',
  'device-driver': 'software',
  firmware: 'software',
  file: 'software',
  'machine-learning-model': 'ai-model',
  data: 'dataset',
  'cryptographic-asset': 'crypto',
};

const CRYPTO_ASSET_TYPES: Record<string, BomCryptoProperties['assetType']> = {
  algorithm: 'algorithm',
  protocol: 'protocol',
  certificate: 'certificate',
  'related-crypto-material': 'material',
};

function identifiersOf(purl?: string, cpe?: string, sha256?: string): FindingIdentifier[] {
  return [
    ...(purl ? [{ scheme: 'purl', value: stripPurl(purl) }] : []),
    ...(cpe ? [{ scheme: 'cpe', value: cpe }] : []),
    ...(sha256 && /^[0-9a-f]{64}$/i.test(sha256) ? [{ scheme: 'sha-256', value: sha256.toLowerCase() }] : []),
  ];
}

function externalIdOf(ids: readonly FindingIdentifier[], ref: string | undefined, name: string, version: string | undefined): string {
  return ids.find((i) => i.scheme === 'purl')?.value ?? ref ?? `${name}@${version ?? ''}`;
}

function cryptoOf(c: z.output<typeof CycloneDxComponentSchema>): BomCryptoProperties | undefined {
  const p = c.cryptoProperties;
  if (!p) return undefined;
  const alg = p.algorithmProperties;
  const proto = p.protocolProperties;
  const suites = (proto?.cipherSuites ?? []).flatMap((s) => (s.name ? [s.name.slice(0, 200)] : [])).slice(0, 50);
  const curve = alg?.curve ?? alg?.ellipticCurve;
  return {
    assetType: CRYPTO_ASSET_TYPES[p.assetType ?? ''] ?? 'other',
    ...(alg?.primitive ? { primitive: alg.primitive.slice(0, 50) } : {}),
    ...(alg?.parameterSetIdentifier ? { parameterSet: alg.parameterSetIdentifier.slice(0, 100) } : {}),
    ...(curve ? { curve: curve.slice(0, 100) } : {}),
    ...(alg?.nistQuantumSecurityLevel !== undefined ? { nistQuantumSecurityLevel: alg.nistQuantumSecurityLevel } : {}),
    ...(proto?.version ? { protocolVersion: proto.version.slice(0, 50) } : {}),
    ...(suites.length > 0 ? { cipherSuites: suites } : {}),
    ...(p.certificateProperties?.notValidAfter ? { notValidAfter: p.certificateProperties.notValidAfter.slice(0, 40) } : {}),
  };
}

function parseCycloneDxBom(raw: unknown): ParsedBom {
  const bom = CycloneDxSchema.safeParse(raw);
  if (!bom.success) return { ok: false, error: 'CycloneDX の形が想定と異なります。' };
  const items: ParsedBomItem[] = [];
  const byRef = new Map<string, ParsedBomItem>();
  const walk = (rows: readonly unknown[]) => {
    for (const row of rows) {
      const parsed = CycloneDxComponentSchema.safeParse(row);
      if (!parsed.success) continue;
      const c = parsed.data;
      if (c.name) {
        const sha256 = c.hashes.find((h) => h.alg === 'SHA-256')?.content;
        const identifiers = identifiersOf(c.purl, c.cpe, sha256);
        const crypto = c.type === 'cryptographic-asset' ? cryptoOf(c) : undefined;
        const licenses = normalizeLicenses(c.licenses.flatMap((l) => [l.license?.id ?? l.license?.name, l.expression]));
        const item: ParsedBomItem = {
          externalId: externalIdOf(identifiers, c['bom-ref'], c.name, c.version),
          identifiers,
          kind: CYCLONEDX_KINDS[c.type ?? ''] ?? 'other',
          ...(c.type ? { sourceType: c.type.slice(0, 50) } : {}),
          name: c.name.slice(0, 500),
          ...(c.version ? { version: c.version.slice(0, 200) } : {}),
          ...(licenses.length > 0 ? { licenses } : {}),
          ...(crypto ? { crypto } : {}),
        };
        items.push(item);
        if (c['bom-ref']) byRef.set(c['bom-ref'], item);
      }
      if (c.components) walk(c.components);
    }
  };
  walk(bom.data.components ?? []);
  const vulnerabilities = (bom.data.vulnerabilities ?? []).flatMap((row): ParsedVulnerability[] => {
    const v = CycloneDxVulnerabilitySchema.safeParse(row);
    if (!v.success) return [];
    const d = v.data;
    return [
      {
        id: d.id,
        ...(d.source?.name ? { source: d.source.name } : {}),
        references: d.references.slice(0, 10).map((r) => ({ id: r.id, ...(r.source?.name ? { source: r.source.name } : {}) })),
        ratings: d.ratings.slice(0, 20),
        ...(d.analysis?.state ? { state: d.analysis.state } : {}),
        affects: d.affects.flatMap((a) => {
          const hit = a.ref ? byRef.get(a.ref) : undefined;
          return hit ? [hit] : [];
        }),
      },
    ];
  });
  const tool = cycloneDxTool(bom.data.metadata?.tools);
  const observedAt = bom.data.metadata?.timestamp ? toIsoTimestamp(bom.data.metadata.timestamp) : undefined;
  return {
    ok: true,
    format: 'cyclonedx',
    specVersion: bom.data.specVersion,
    product: tool.name?.slice(0, 100) || 'CycloneDX',
    ...(tool.version ? { productVersion: tool.version.slice(0, 50) } : {}),
    ...(observedAt ? { observedAt } : {}),
    items,
    vulnerabilities,
  };
}

const SpdxPackageSchema = z.object({
  SPDXID: str,
  name: str,
  versionInfo: str,
  primaryPackagePurpose: str,
  licenseConcluded: str,
  licenseDeclared: str,
  checksums: list(z.object({ algorithm: str, checksumValue: str })),
  externalRefs: list(z.object({ referenceType: str, referenceLocator: str })),
});

const SpdxSchema = z.object({
  spdxVersion: z.string().regex(/^SPDX-2\.\d+$/),
  creationInfo: z
    .object({ created: str, creators: z.array(z.string().max(500)).optional().catch(undefined) })
    .optional()
    .catch(undefined),
  packages: z.array(z.unknown()).max(200_000).optional().catch(undefined),
});

/** `Tool: syft-1.0.0` の形から製品名と版を読む。 */
function spdxTool(creators: readonly string[] | undefined): { name?: string; version?: string } {
  const tool = creators?.find((c) => c.startsWith('Tool:'))?.slice(5).trim();
  if (!tool) return {};
  const m = /^(.+?)-(\d[^\s]*)$/.exec(tool);
  return m ? { name: m[1], version: m[2] } : { name: tool };
}

/** concluded が NOASSERTION・NONE なら無いものとして declared に回す。 */
const usableLicense = (v: string | undefined) => (v && v !== 'NOASSERTION' && v !== 'NONE' ? v : undefined);

function parseSpdxBom(raw: unknown): ParsedBom {
  const doc = SpdxSchema.safeParse(raw);
  if (!doc.success) return { ok: false, error: 'SPDX 2.x の JSON ではありません（SPDX 3 は未対応です）。' };
  const items = (doc.data.packages ?? []).flatMap((row): ParsedBomItem[] => {
    const parsed = SpdxPackageSchema.safeParse(row);
    if (!parsed.success || !parsed.data.name) return [];
    const p = parsed.data;
    const name = p.name as string;
    const ref = (type: string) => p.externalRefs.find((r) => r.referenceType === type)?.referenceLocator;
    const sha256 = p.checksums.find((c) => c.algorithm === 'SHA256')?.checksumValue;
    const identifiers = identifiersOf(ref('purl'), ref('cpe23Type') ?? ref('cpe22Type'), sha256);
    const licenses = normalizeLicenses([usableLicense(p.licenseConcluded) ?? p.licenseDeclared]);
    return [
      {
        externalId: externalIdOf(identifiers, p.SPDXID, name, p.versionInfo),
        identifiers,
        kind: p.primaryPackagePurpose === 'OTHER' ? 'other' : 'software',
        ...(p.primaryPackagePurpose ? { sourceType: p.primaryPackagePurpose.slice(0, 50) } : {}),
        name: name.slice(0, 500),
        ...(p.versionInfo && p.versionInfo !== 'NOASSERTION' ? { version: p.versionInfo.slice(0, 200) } : {}),
        ...(licenses.length > 0 ? { licenses } : {}),
      },
    ];
  });
  const tool = spdxTool(doc.data.creationInfo?.creators);
  const observedAt = doc.data.creationInfo?.created ? toIsoTimestamp(doc.data.creationInfo.created) : undefined;
  return {
    ok: true,
    format: 'spdx',
    specVersion: doc.data.spdxVersion,
    product: tool.name?.slice(0, 100) || 'SPDX',
    ...(tool.version ? { productVersion: tool.version.slice(0, 50) } : {}),
    ...(observedAt ? { observedAt } : {}),
    items,
  };
}

/** 中身から形式を判定して読む。 */
export function parseBom(raw: unknown): ParsedBom {
  const shape = z.object({ bomFormat: z.unknown(), spdxVersion: z.unknown() }).partial().safeParse(raw);
  if (shape.success && shape.data.bomFormat === 'CycloneDX') return parseCycloneDxBom(raw);
  if (shape.success && shape.data.spdxVersion !== undefined) return parseSpdxBom(raw);
  return { ok: false, error: 'CycloneDX または SPDX 2.x の JSON ではありません。' };
}
