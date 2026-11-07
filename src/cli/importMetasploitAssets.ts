import { resolveProject } from './analyze';
import { LAYER_KEYS, MAX_ASSETS, type Asset, type LayerKey } from '../core/model/types';
import { deserializeProject } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import { assetIdentifiers, toIsoTimestamp } from '../core/model/assetIdentity';
import { lookupNode, type ImportNodeRef } from '../features/findings-import/resolveNode';
import { msfTimeToIso, type MetasploitHost } from '../features/metasploit-import/parseMetasploit';

/**
 * CLI `import-metasploit-assets`：Metasploit の db_export のホストが持つサービス（state が open のもの）を
 * プロジェクト JSON の Asset として保存する。取り込み直しは製品 × scope の単位で置き換える。
 * ホストとノードの対応は引数で受け、推測しない。ファイル I/O は呼び出し側（main.ts）。docs/architecture.md §8.7。
 */

const PRODUCT = 'Metasploit';

export interface ImportMetasploitAssetsOptions {
  scope: string;
  /** ホスト（IP）→ ノード（C 番号または ID）。 */
  hostNodes?: Record<string, string>;
  importedAt?: string;
}

export interface ImportMetasploitAssetsOutput {
  project: PersistedProject;
  scope: string;
  hosts: number;
  services: number;
  /** state が open ではないため保存しなかったサービス数。 */
  closedServices: number;
  /** サービスが無いため飛ばしたホスト数。 */
  hostsWithoutServices: number;
  unlinkedHosts: string[];
  badNodeRefs: string[];
}

export function importMetasploitAssets(
  rawProject: unknown,
  hosts: readonly MetasploitHost[],
  options: ImportMetasploitAssetsOptions,
): ImportMetasploitAssetsOutput {
  const resolved = resolveProject(rawProject);
  const loaded = deserializeProject(rawProject);
  if (!loaded) throw new Error('プロジェクト JSON の形式が不正です。');

  const nodes: ImportNodeRef[] = LAYER_KEYS.flatMap((layer: LayerKey) =>
    resolved.layers[layer].nodes.map((n) => ({ id: n.id, layer, seq: n.seq, type: n.type, label: n.label })),
  );
  const importedAt = options.importedAt ?? new Date().toISOString();
  const source = { format: 'metasploit' as const, product: PRODUCT, scope: options.scope, importedAt };
  const unlinkedHosts = new Set<string>();
  const badNodeRefs = new Set<string>();
  const services = new Map<string, Asset>();
  let closedServices = 0;
  let hostsWithoutServices = 0;
  let hostCount = 0;

  for (const h of hosts) {
    if (h.services.length === 0) {
      hostsWithoutServices += 1;
      continue;
    }
    const open = h.services.filter((s) => s.state === 'open');
    closedServices += h.services.length - open.length;
    if (open.length === 0) continue;
    hostCount += 1;

    const ref = options.hostNodes?.[h.address];
    let subject: Asset['subject'];
    if (ref === undefined) {
      unlinkedHosts.add(h.address);
    } else {
      const found = lookupNode(nodes, ref);
      if (found.kind === 'found') subject = { layer: found.node.layer, nodeId: found.node.id };
      else {
        badNodeRefs.add(ref);
        unlinkedHosts.add(h.address);
      }
    }
    const observedAtRaw = msfTimeToIso(h.updatedAt);
    const observedAt = observedAtRaw ? toIsoTimestamp(observedAtRaw) : undefined;
    const host = h.name || h.address;

    for (const s of open) {
      const externalId = `service:${h.address}:${s.port}/${s.proto}`;
      const id = `${PRODUCT}:${options.scope}:${externalId}`;
      services.set(id, {
        id,
        source,
        externalId,
        identifiers: [...assetIdentifiers({ host, ip: h.address }), ...(s.id ? [{ scheme: 'metasploit-service', value: s.id }] : [])],
        kind: 'service',
        host,
        ip: h.address,
        port: s.port,
        ...(s.name ? { serviceName: s.name } : {}),
        ...(subject ? { subject } : {}),
        ...(observedAt ? { observedAt } : {}),
      });
    }
  }

  const others = (loaded.assets ?? []).filter((a) => !(a.source.product === PRODUCT && a.source.scope === options.scope));
  const assets = [...others, ...services.values()];
  if (assets.length > MAX_ASSETS) {
    throw new Error(`資産が上限（${MAX_ASSETS} 件）を超えます: ${assets.length} 件`);
  }
  const project: PersistedProject = { ...loaded };
  if (assets.length > 0) project.assets = assets;
  else delete project.assets;

  return {
    project,
    scope: options.scope,
    hosts: hostCount,
    services: services.size,
    closedServices,
    hostsWithoutServices,
    unlinkedHosts: [...unlinkedHosts].sort(),
    badNodeRefs: [...badNodeRefs].sort(),
  };
}

export function metasploitAssetsReportToMarkdown(out: ImportMetasploitAssetsOutput): string {
  return [
    `# 資産の取り込みレポート（${PRODUCT}）`,
    '',
    `- scope: ${out.scope}（同じ製品・同じ scope の資産を置き換えた）`,
    `- ホスト ${out.hosts} 台 / サービス ${out.services} 件（state が open のものだけ）`,
    `- open ではないため保存しなかったサービス ${out.closedServices} 件 / サービスが無く飛ばしたホスト ${out.hostsWithoutServices} 台`,
    '- 内部の IP・ホスト名はプロジェクト JSON に入るので、共有時に注意する',
    '',
    '## どのノードにも結びつかないホスト（Asset タブで「未対応」になる）',
    '',
    ...(out.unlinkedHosts.length > 0 ? out.unlinkedHosts.map((h) => `- ${h}`) : ['なし']),
    '',
    '## 図に無い、または特定できないノードの指定',
    '',
    ...(out.badNodeRefs.length > 0 ? out.badNodeRefs.map((r) => `- ${r}`) : ['なし']),
  ].join('\n');
}

/** 機械処理用の JSON オブジェクト（キーは英語固定）。 */
export function metasploitAssetsReportToJson(out: ImportMetasploitAssetsOutput): Record<string, unknown> {
  return {
    schemaVersion: 1,
    kind: 'cyberriskscape-metasploit-assets-import-report',
    product: PRODUCT,
    scope: out.scope,
    hosts: out.hosts,
    services: out.services,
    closedServices: out.closedServices,
    hostsWithoutServices: out.hostsWithoutServices,
    unlinkedHosts: out.unlinkedHosts,
    badNodeRefs: out.badNodeRefs,
  };
}
