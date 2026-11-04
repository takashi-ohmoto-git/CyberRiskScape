import { resolveProject } from './analyze';
import { LAYER_KEYS, MAX_ASSETS, type Asset, type LayerKey } from '../core/model/types';
import { deserializeProject } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import { assetIdentifiers } from '../core/model/assetIdentity';
import { lookupNode, type ImportNodeRef } from '../features/findings-import/resolveNode';
import type { ArtexEndpointRecord, ArtexServiceRecord } from '../features/asset-import/artexAssets';

/**
 * CLI `import-artex-assets`：ARTEX の資産（サービス・エンドポイント）をプロジェクト JSON に保存する。
 * 取り込み直しは製品 × scope の単位で置き換える。ホストとノードの対応は引数で受け、推測しない。
 * ファイル I/O は呼び出し側（main.ts）。docs/architecture.md §8.7。
 */

const PRODUCT = 'ARTEX';
const MAX_IDENTIFIERS = 20;

/** 同一判定の鍵に ARTEX の資産 ID を足す（まとめた行の分も残す）。 */
const identifiersOf = (base: Asset['identifiers'], prev: Asset['identifiers'] | undefined, artexId: string | undefined) => {
  const artex = (prev ?? []).filter((i) => i.scheme === 'artex-asset-id');
  const ids = artexId && !artex.some((i) => i.value === artexId) ? [...artex, { scheme: 'artex-asset-id', value: artexId }] : artex;
  return [...base, ...ids].slice(0, MAX_IDENTIFIERS);
};

export interface ImportArtexAssetsInput {
  services: readonly ArtexServiceRecord[];
  endpoints: readonly ArtexEndpointRecord[];
  /** `task_source` が agent 以外で読まなかった件数（報告用）。 */
  skippedBySource: number;
}

export interface ImportArtexAssetsOptions {
  scope: string;
  /** ホスト → ノード（C 番号または ID）。 */
  nodeMap?: Record<string, string>;
  /** 対応表に無いホストを結びつけるノード。 */
  node?: string;
  importedAt?: string;
}

export interface ImportArtexAssetsOutput {
  project: PersistedProject;
  scope: string;
  services: number;
  endpoints: number;
  skippedBySource: number;
  /** どのノードにも結びつかなかったホスト。 */
  unlinkedHosts: string[];
  /** 図に無い、または C 番号が複数のレイヤーに該当するノードの指定。 */
  badNodeRefs: string[];
}

const latest = (a: string | undefined, b: string | undefined) => (a && b ? (a > b ? a : b) : (a ?? b));

export function importArtexAssets(
  rawProject: unknown,
  input: ImportArtexAssetsInput,
  options: ImportArtexAssetsOptions,
): ImportArtexAssetsOutput {
  const resolved = resolveProject(rawProject);
  const loaded = deserializeProject(rawProject);
  if (!loaded) throw new Error('プロジェクト JSON の形式が不正です。');

  const nodes: ImportNodeRef[] = LAYER_KEYS.flatMap((layer: LayerKey) =>
    resolved.layers[layer].nodes.map((n) => ({ id: n.id, layer, seq: n.seq, type: n.type, label: n.label })),
  );
  const importedAt = options.importedAt ?? new Date().toISOString();
  const source = { format: 'artex-assets' as const, product: PRODUCT, scope: options.scope, importedAt };
  const unlinkedHosts = new Set<string>();
  const badNodeRefs = new Set<string>();

  const subjectOf = (...hosts: (string | undefined)[]) => {
    const map = options.nodeMap ?? {};
    const hit = hosts.find((h): h is string => h !== undefined && map[h] !== undefined);
    const ref = hit !== undefined ? map[hit] : options.node;
    const host = hosts.find((h) => h !== undefined) ?? '';
    if (ref === undefined) {
      unlinkedHosts.add(host);
      return undefined;
    }
    const lookup = lookupNode(nodes, ref);
    if (lookup.kind !== 'found') {
      badNodeRefs.add(ref);
      unlinkedHosts.add(host);
      return undefined;
    }
    return { layer: lookup.node.layer, nodeId: lookup.node.id };
  };

  // 同じサービスはパス付きの URL ごとに別の行で来るので、ホスト・ポート・サービス名で 1 件にまとめる
  const services = new Map<string, Asset>();
  for (const s of input.services) {
    const externalId = `service:${s.ip ?? s.host}:${s.port ?? ''}:${s.serviceName ?? ''}`;
    const id = `${PRODUCT}:${options.scope}:${externalId}`;
    const prev = services.get(id);
    const subject = subjectOf(s.ip, s.domain, s.host);
    const observedAt = latest(prev?.observedAt, s.observedAt);
    const technologies = [...new Set([...(prev?.technologies ?? []), ...s.technologies])];
    const domain = prev?.domain ?? s.domain;
    const host = s.ip ?? s.host;
    services.set(id, {
      id,
      source,
      externalId,
      identifiers: identifiersOf(assetIdentifiers({ host, ip: s.ip, domain }), prev?.identifiers, s.artexId),
      kind: 'service',
      host,
      ...(s.ip ? { ip: s.ip } : {}),
      ...(domain ? { domain } : {}),
      ...(s.port ? { port: s.port } : {}),
      ...(s.serviceName ? { serviceName: s.serviceName } : {}),
      ...(technologies.length > 0 ? { technologies } : {}),
      ...((prev?.subject ?? subject) ? { subject: prev?.subject ?? subject } : {}),
      ...(observedAt ? { observedAt } : {}),
    });
  }

  const endpoints = new Map<string, Asset>();
  for (const e of input.endpoints) {
    const externalId = `endpoint:${e.method}:${e.url}`;
    const id = `${PRODUCT}:${options.scope}:${externalId}`;
    const subject = subjectOf(e.host);
    endpoints.set(id, {
      id,
      source,
      externalId,
      identifiers: identifiersOf(assetIdentifiers({ host: e.host, url: e.url }), endpoints.get(id)?.identifiers, e.artexId),
      kind: 'endpoint',
      host: e.host,
      method: e.method,
      url: e.url,
      ...(e.port ? { port: e.port } : {}),
      ...(e.params.length > 0 ? { params: e.params } : {}),
      ...(subject ? { subject } : {}),
      ...(e.observedAt ? { observedAt: e.observedAt } : {}),
    });
  }

  const others = (loaded.assets ?? []).filter(
    (a) => !(a.source.product === PRODUCT && a.source.scope === options.scope),
  );
  const assets = [...others, ...services.values(), ...endpoints.values()];
  // 上限を超えた JSON は読み込めなくなるので、書き出す前に止める
  if (assets.length > MAX_ASSETS) {
    throw new Error(`資産が上限（${MAX_ASSETS} 件）を超えます: ${assets.length} 件`);
  }

  const project: PersistedProject = { ...loaded };
  if (assets.length > 0) project.assets = assets;
  else delete project.assets;

  return {
    project,
    scope: options.scope,
    services: services.size,
    endpoints: endpoints.size,
    skippedBySource: input.skippedBySource,
    unlinkedHosts: [...unlinkedHosts].sort(),
    badNodeRefs: [...badNodeRefs].sort(),
  };
}

export function artexAssetsReportToMarkdown(out: ImportArtexAssetsOutput): string {
  const lines = [
    `# 資産の取り込みレポート（${PRODUCT}）`,
    '',
    `- scope: ${out.scope}（同じ製品・同じ scope の資産を置き換えた）`,
    `- サービス ${out.services} 件 / エンドポイント ${out.endpoints} 件`,
    `- そのタスクの観測ではない資産（task_source が agent 以外）を除いた件数 ${out.skippedBySource} 件`,
    '- パラメータの値は保存していない。内部の IP・URL はプロジェクト JSON に入るので、共有時に注意する',
    '',
    '## どのノードにも結びつかないホスト（Asset タブで「未対応」になる）',
    '',
    ...(out.unlinkedHosts.length > 0 ? out.unlinkedHosts.map((h) => `- ${h}`) : ['なし']),
    '',
    '## 図に無い、または特定できないノードの指定',
    '',
    ...(out.badNodeRefs.length > 0 ? out.badNodeRefs.map((r) => `- ${r}`) : ['なし']),
  ];
  return lines.join('\n');
}

/** 機械処理用の JSON オブジェクト（キーは英語固定）。 */
export function artexAssetsReportToJson(out: ImportArtexAssetsOutput): Record<string, unknown> {
  return {
    schemaVersion: 1,
    kind: 'cyberriskscape-artex-assets-import-report',
    product: PRODUCT,
    scope: out.scope,
    services: out.services,
    endpoints: out.endpoints,
    skippedBySource: out.skippedBySource,
    unlinkedHosts: out.unlinkedHosts,
    badNodeRefs: out.badNodeRefs,
  };
}
