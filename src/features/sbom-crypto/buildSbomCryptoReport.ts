import type { DiagramEdge, DiagramNode, EdgeCrypto } from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import { classifyAlgorithm } from '../../crypto-behavior/loader';
import type { AlgorithmClass, AlgorithmTable, CryptoLibrary } from '../../crypto-behavior/schema';
import type { Locale } from '../../i18n';
import type { AlgorithmAsset, CertificateAsset, ParsedSbom, ProtocolAsset } from './parseCycloneDx';

/**
 * 指定ノード 1 つについて、SBOM／CBOM の暗号を整理したレポートの構造を作る純粋関数。
 * 図は変更しない（入力済みの値と、SBOM から見つかった候補を並べるだけ）。
 */
export const SBOM_CRYPTO_SCHEMA_VERSION = 1 as const;
export const SBOM_CRYPTO_KIND = 'cyberriskscape-sbom-crypto-report' as const;

export type SbomVerdict = AlgorithmClass | 'unknown';

/** ノードにつながるエッジ（相手側のラベル付き）。 */
export interface SbomEdgeInput {
  id: string;
  peer: string;
  crypto?: EdgeCrypto;
}

export interface BuildSbomCryptoReportInput {
  parsed: Extract<ParsedSbom, { ok: true }>;
  node: DiagramNode;
  edges: SbomEdgeInput[];
  algorithms: AlgorithmTable;
  libraries: readonly CryptoLibrary[];
  locale: Locale;
  now: Date;
  sourceName: string;
}

export interface SbomAlgorithmRow {
  name: string;
  primitive: string | null;
  parameterSetIdentifier: string | null;
  curve: string | null;
  nistQuantumSecurityLevel: number | null;
  verdict: SbomVerdict;
}

export interface SbomCipherSuiteRow {
  name: string;
  verdict: SbomVerdict;
}

export interface SbomProtocolRow {
  name: string;
  type: string | null;
  version: string | null;
  cipherSuites: SbomCipherSuiteRow[];
}

export interface SbomCertificateRow {
  name: string;
  subjectName: string | null;
  issuerName: string | null;
  notValidAfter: string | null;
  signatureAlgorithm: string | null;
  verdict: SbomVerdict;
}

export interface SbomLibraryRow {
  libraryId: string;
  label: string;
  name: string;
  version: string | null;
  purl: string | null;
  role: CryptoLibrary['role'];
  note: string;
}

export interface SbomEdgeComparison {
  id: string;
  peer: string;
  /** 図に入力済みの値。未入力は null。 */
  entered: { protocol: string | null; version: string | null; kex: string | null };
  keyExchangeCandidates: string[];
}

export interface SbomCryptoReport {
  schemaVersion: typeof SBOM_CRYPTO_SCHEMA_VERSION;
  kind: typeof SBOM_CRYPTO_KIND;
  locale: Locale;
  summary: {
    sourceName: string;
    specVersion: string;
    componentCount: number;
    cryptoAssetCount: number;
    libraryCount: number;
    node: { id: string; label: string };
    generatedAt: string;
  };
  algorithms: SbomAlgorithmRow[];
  protocols: SbomProtocolRow[];
  certificates: SbomCertificateRow[];
  libraries: SbomLibraryRow[];
  /** 一覧に当たらなかった部品の数（中身は載せない）。 */
  unmatchedPackageCount: number;
  comparison: {
    nodeSignature: { entered: string | null; candidates: string[] };
    edges: SbomEdgeComparison[];
  };
}

const orNull = (v: string | undefined): string | null => (v && v.trim() !== '' ? v : null);
const unique = (xs: string[]) => [...new Set(xs)];

/** 名前で判定し、当たらなければ曲線でも試す。どちらも当たらなければ 'unknown'（要確認）。 */
function verdictOf(table: AlgorithmTable, name: string, curve?: string): SbomVerdict {
  return (
    classifyAlgorithm(name, table) ?? (curve ? classifyAlgorithm(curve, table) : null) ?? 'unknown'
  );
}

/** ノードのエッジ ID（`DF3`）。採番が無い旧データは内部 ID。 */
const edgeId = (e: DiagramEdge) => (e.seq != null ? formatElementalId('edge', e.seq) : e.id);
/** ノードの表示用 ID（`C3`）。採番が無い旧データは内部 ID。 */
export const nodeElementalId = (n: DiagramNode) => (n.seq != null ? formatElementalId('node', n.seq) : n.id);

/** ノードに接するエッジを、相手側のラベル付きで返す。 */
export function edgesTouchingNode(
  node: DiagramNode,
  nodes: readonly DiagramNode[],
  edges: readonly DiagramEdge[],
): SbomEdgeInput[] {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  return edges
    .filter((e) => e.source === node.id || e.target === node.id)
    .map((e) => {
      const peer = byId.get(e.source === node.id ? e.target : e.source);
      return { id: edgeId(e), peer: peer ? getNodeDisplayName(peer) : '', crypto: e.crypto };
    });
}

export function buildSbomCryptoReport(input: BuildSbomCryptoReportInput): SbomCryptoReport {
  const { parsed, node, algorithms: table, now } = input;
  const algoAssets = parsed.cryptoAssets.filter((a): a is AlgorithmAsset => a.kind === 'algorithm');
  const protoAssets = parsed.cryptoAssets.filter((a): a is ProtocolAsset => a.kind === 'protocol');
  const certAssets = parsed.cryptoAssets.filter((a): a is CertificateAsset => a.kind === 'certificate');
  const algoByRef = new Map(algoAssets.flatMap((a) => (a.ref ? [[a.ref, a] as const] : [])));

  const algorithms: SbomAlgorithmRow[] = algoAssets.map((a) => {
    const curve = a.curve ?? a.ellipticCurve;
    return {
      name: a.name,
      primitive: orNull(a.primitive),
      parameterSetIdentifier: orNull(a.parameterSetIdentifier),
      curve: orNull(curve),
      nistQuantumSecurityLevel: a.nistQuantumSecurityLevel ?? null,
      verdict: verdictOf(table, a.name, curve),
    };
  });

  const protocols: SbomProtocolRow[] = protoAssets.map((p) => ({
    name: p.name,
    type: orNull(p.type),
    version: orNull(p.version),
    cipherSuites: p.cipherSuites.map((name) => ({ name, verdict: verdictOf(table, name) })),
  }));

  const certificates: SbomCertificateRow[] = certAssets.map((c) => {
    const sig = c.signatureAlgorithmRef ? algoByRef.get(c.signatureAlgorithmRef) : undefined;
    return {
      name: c.name,
      subjectName: orNull(c.subjectName),
      issuerName: orNull(c.issuerName),
      notValidAfter: orNull(c.notValidAfter),
      signatureAlgorithm: sig ? sig.name : null,
      verdict: sig ? verdictOf(table, sig.name, sig.curve ?? sig.ellipticCurve) : 'unknown',
    };
  });

  const libraryById = new Map(input.libraries.map((l) => [l.id, l]));
  const libraries: SbomLibraryRow[] = parsed.packages.flatMap((p) => {
    const lib = p.libraryId ? libraryById.get(p.libraryId) : undefined;
    return lib
      ? [
          {
            libraryId: lib.id,
            label: lib.label,
            name: p.name,
            version: orNull(p.version),
            purl: orNull(p.purl),
            role: lib.role,
            note: lib.note,
          },
        ]
      : [];
  });

  // 図に入力する値の候補（図は変えない）。
  const signatureCandidates = unique([
    ...algoAssets.filter((a) => a.primitive === 'signature').map((a) => a.name),
    ...certificates.flatMap((c) => (c.signatureAlgorithm ? [c.signatureAlgorithm] : [])),
  ]);
  const kexCandidates = unique([
    ...algoAssets.filter((a) => a.primitive === 'kem' || a.primitive === 'key-agree').map((a) => a.name),
    // TLS 1.3 のスイート名（TLS_AES_256_GCM_SHA384 等）は鍵交換を含まないので、判定表に当たる名前だけ。
    ...protocols.flatMap((p) => p.cipherSuites.filter((s) => s.verdict !== 'unknown').map((s) => s.name)),
  ]);

  const pad = (n: number) => String(n).padStart(2, '0');
  return {
    schemaVersion: SBOM_CRYPTO_SCHEMA_VERSION,
    kind: SBOM_CRYPTO_KIND,
    locale: input.locale,
    summary: {
      sourceName: input.sourceName,
      specVersion: parsed.specVersion,
      componentCount: parsed.componentCount,
      cryptoAssetCount: parsed.cryptoAssets.length,
      libraryCount: libraries.length,
      node: { id: nodeElementalId(node), label: getNodeDisplayName(node) },
      generatedAt: `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`,
    },
    algorithms,
    protocols,
    certificates,
    libraries,
    unmatchedPackageCount: parsed.packages.length - libraries.length,
    comparison: {
      nodeSignature: { entered: orNull(node.crypto?.signature), candidates: signatureCandidates },
      edges: input.edges.map((e) => ({
        id: e.id,
        peer: e.peer,
        entered: {
          protocol: orNull(e.crypto?.protocol),
          version: orNull(e.crypto?.version),
          kex: orNull(e.crypto?.kex),
        },
        keyExchangeCandidates: kexCandidates,
      })),
    },
  };
}
