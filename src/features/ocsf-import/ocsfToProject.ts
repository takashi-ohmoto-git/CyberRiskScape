import type { Asset, Finding, FindingIdentifier } from '../../core/model/types';
import { normalizeIdentifiers } from '../../core/model/identifierSchemes';
import { capFindings, normalizeSeverity } from '../findings-import/replaceFindings';
import { lookupNode, type ImportNodeRef } from '../findings-import/resolveNode';
import { ocsfCanonicalIds, type OcsfProductMap } from './ocsfMap';
import type { OcsfFinding, OcsfResource } from './parseOcsf';

/**
 * 正規化した OCSF の検査結果を、共通モデルの指摘（FAIL だけ）とクラウドのリソースの資産（PASS も含む全件）に変換する
 * 純粋関数（plan §2.149）。リソースの ID はアカウント ID を含む完全な形で持つ（ユーザー決定）。
 * ノードへの結びつけは、リソースのタグ `crs-node`、または `nodeMap`（リソースの ID・名前 → ノード）。
 */

const TEXT_MAX = 200;
const EXTERNAL_ID_MAX = 500;

export interface OcsfConvertInput {
  findings: readonly OcsfFinding[];
  map: readonly OcsfProductMap[];
  nodes: readonly ImportNodeRef[];
  nodeMap?: Readonly<Record<string, string>>;
  scope: string;
  importedAt: string;
}

export interface OcsfConvertOutput {
  /** 製品ごとの指摘（置き換えは製品 × scope の単位）。 */
  findingsByProduct: Map<string, Finding[]>;
  truncated: number;
  assets: Asset[];
  /** 対応表に無い FAIL の検査（脅威と結ばずに残したもの）。 */
  unmappedChecks: { product: string; checkId: string; count: number }[];
}

/** リソースの ID の形から同一判定の鍵を作る。 */
export function resourceIdentifiers(uid: string | undefined, name: string | undefined): FindingIdentifier[] {
  const ids: FindingIdentifier[] = [];
  if (uid?.startsWith('arn:')) ids.push({ scheme: 'arn', value: uid });
  else if (uid && /^\/subscriptions\//i.test(uid)) ids.push({ scheme: 'azure-resource-id', value: uid });
  else if (uid) ids.push({ scheme: 'cloud-resource-id', value: uid });
  else if (name) ids.push({ scheme: 'cloud-resource-id', value: name });
  return normalizeIdentifiers(ids);
}

function subjectOf(r: OcsfResource, input: OcsfConvertInput): Finding['subject'] {
  const nodeMap = input.nodeMap ?? {};
  const ref = r.nodeTag ?? (r.uid ? nodeMap[r.uid] : undefined) ?? (r.name ? nodeMap[r.name] : undefined);
  const found = ref ? lookupNode(input.nodes, ref) : undefined;
  return found?.kind === 'found' ? { layer: found.node.layer, nodeId: found.node.id } : undefined;
}

const resourceKey = (r: OcsfResource | undefined) => (r ? (r.uid ?? r.name ?? '') : '');

function toFinding(f: OcsfFinding, r: OcsfResource | undefined, multi: boolean, input: OcsfConvertInput): Finding {
  const base = f.uid ?? `${f.checkId}:${resourceKey(r)}`;
  const externalId = (multi ? `${base}#${resourceKey(r)}` : base).slice(0, EXTERNAL_ID_MAX);
  const subject = r ? subjectOf(r, input) : undefined;
  return {
    id: `${f.product}:${input.scope}:${externalId}`.slice(0, 600),
    source: {
      format: 'ocsf',
      product: f.product,
      ...(f.productVersion ? { productVersion: f.productVersion } : {}),
      scope: input.scope,
      importedAt: input.importedAt.slice(0, 40),
    },
    externalId,
    identifiers: [{ scheme: f.product.toLowerCase() === 'prowler' ? 'prowler-check' : 'ocsf-check', value: f.checkId.slice(0, TEXT_MAX) }],
    ...(f.title ? { title: f.title } : {}),
    severity: normalizeSeverity(f.severity),
    ...(f.severity ? { sourceSeverity: f.severity } : {}),
    canonicalIds: [...ocsfCanonicalIds(f.product, f.checkId, input.map)].slice(0, 20),
    ...(subject ? { subject } : {}),
    ...(r
      ? {
          resource: {
            label: (r.name ?? r.uid ?? '(名前なし)').slice(0, TEXT_MAX),
            ...(r.type ? { type: r.type } : {}),
            ...(r.region ? { region: r.region.slice(0, 50) } : {}),
          },
        }
      : {}),
    ...(f.observedAt ? { observedAt: f.observedAt } : {}),
  };
}

const later = (a: string | undefined, b: string | undefined) => (!a ? b : !b ? a : a > b ? a : b);

export function ocsfToProject(input: OcsfConvertInput): OcsfConvertOutput {
  const byProduct = new Map<string, Finding[]>();
  const seen = new Set<string>();
  const unmapped = new Map<string, { product: string; checkId: string; count: number }>();
  const assets = new Map<string, Asset>();

  for (const f of input.findings) {
    for (const r of f.resources) {
      const key = resourceKey(r);
      if (!key) continue;
      const id = `${f.product}:${input.scope}:resource:${key}`;
      const prev = assets.get(id);
      const subject = prev?.subject ?? subjectOf(r, input);
      const observedAt = later(prev?.observedAt, f.observedAt);
      const cloud = {
        ...(r.provider ? { provider: r.provider } : {}),
        ...(r.account ? { account: r.account } : {}),
        ...(r.region ? { region: r.region } : {}),
        ...(r.type ? { type: r.type } : {}),
        ...(r.service ? { service: r.service } : {}),
        ...(r.name ? { name: r.name } : {}),
      };
      assets.set(id, {
        id,
        source: {
          format: 'ocsf',
          product: f.product,
          ...(f.productVersion ? { productVersion: f.productVersion } : {}),
          scope: input.scope,
          importedAt: input.importedAt,
        },
        externalId: `resource:${key}`,
        identifiers: resourceIdentifiers(r.uid, r.name),
        kind: 'resource',
        cloud: { ...prev?.cloud, ...cloud },
        ...(subject ? { subject } : {}),
        ...(observedAt ? { observedAt } : {}),
      });
    }

    if (f.status !== 'FAIL') continue;
    if (ocsfCanonicalIds(f.product, f.checkId, input.map).length === 0) {
      const k = `${f.product}\u0000${f.checkId}`;
      const u = unmapped.get(k) ?? { product: f.product, checkId: f.checkId, count: 0 };
      u.count += 1;
      unmapped.set(k, u);
    }
    const list = byProduct.get(f.product) ?? [];
    const targets: (OcsfResource | undefined)[] = f.resources.length > 0 ? f.resources : [undefined];
    for (const r of targets) {
      let finding = toFinding(f, r, f.resources.length > 1, input);
      // 製品側の ID が別のリソースと重なったら、リソースで区別して残す（黙って捨てない）
      if (seen.has(finding.id) && r) finding = toFinding(f, r, true, input);
      if (seen.has(finding.id)) continue;
      seen.add(finding.id);
      list.push(finding);
    }
    byProduct.set(f.product, list);
  }

  let truncated = 0;
  for (const [product, list] of byProduct) {
    const capped = capFindings(list);
    truncated += capped.truncated;
    byProduct.set(product, capped.findings);
  }
  return {
    findingsByProduct: byProduct,
    truncated,
    assets: [...assets.values()],
    unmappedChecks: [...unmapped.values()].sort((a, b) => b.count - a.count || a.checkId.localeCompare(b.checkId)),
  };
}
