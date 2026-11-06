import { resolveProject } from './analyze';
import { LAYER_KEYS, MAX_ASSETS, type AssetFormat, type LayerKey } from '../core/model/types';
import { deserializeProject } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import { resolveHost, type ImportNodeRef } from '../features/findings-import/resolveNode';
import { exposedServicesToAssets } from '../features/asm-import/asmToAssets';
import type { ExposedService } from '../features/asm-import/asmToLayer';

/**
 * `import-shodan` / `import-scopesentry` の `--into`：観測したサービスを資産として既存プロジェクトに保存する。
 * 取り込み直しは製品 × scope の単位で置き換える。ノードとの結合は `--map` / `--node` の明示だけ（推測しない）。
 * ファイル I/O は呼び出し側（main.ts）。docs/architecture.md §8.7。
 */

export interface ImportAsmAssetsOptions {
  format: Extract<AssetFormat, 'shodan' | 'scopesentry'>;
  product: string;
  scope: string;
  /** IP・ホスト名 → ノード（C 番号または ID）。 */
  nodeMap?: Record<string, string>;
  /** 対応表に無いサービスを結びつけるノード。 */
  node?: string;
  importedAt?: string;
}

export interface ImportAsmAssetsOutput {
  project: PersistedProject;
  services: number;
  cves: number;
  /** どのノードにも結びつかなかった IP。 */
  unlinkedHosts: string[];
  /** 図に無い、または C 番号が複数のレイヤーに該当するノードの指定。 */
  badNodeRefs: string[];
}

export function importAsmAssets(rawProject: unknown, exposed: readonly ExposedService[], options: ImportAsmAssetsOptions): ImportAsmAssetsOutput {
  const resolved = resolveProject(rawProject);
  const loaded = deserializeProject(rawProject);
  if (!loaded) throw new Error('プロジェクト JSON の形式が不正です。');

  const nodes: ImportNodeRef[] = LAYER_KEYS.flatMap((layer: LayerKey) =>
    resolved.layers[layer].nodes.map((n) => ({ id: n.id, layer, seq: n.seq, type: n.type, label: n.label })),
  );
  const importedAt = options.importedAt ?? new Date().toISOString();
  const source = { format: options.format, product: options.product, scope: options.scope, importedAt };

  const unlinked = new Set<string>();
  const badRefs = new Set<string>();
  const assets = exposedServicesToAssets(exposed, source).map((asset) => {
    const hostnames = asset.identifiers.filter((i) => i.scheme === 'fqdn' || i.scheme === 'hostname').map((i) => i.value);
    const hit = resolveHost(nodes, { hostnames, ips: [asset.host] }, options.nodeMap, options.node);
    if (hit.kind === 'found') return { ...asset, subject: { layer: hit.node.layer, nodeId: hit.node.id } };
    unlinked.add(asset.host);
    if (hit.reason !== 'none' && hit.ref) badRefs.add(hit.ref);
    return asset;
  });

  const others = (loaded.assets ?? []).filter((a) => !(a.source.product === options.product && a.source.scope === options.scope));
  const all = [...others, ...assets];
  // 上限を超えた JSON は読み込めなくなるので、書き出す前に止める
  if (all.length > MAX_ASSETS) throw new Error(`資産が上限（${MAX_ASSETS} 件）を超えます: ${all.length} 件`);

  const project: PersistedProject = { ...loaded };
  if (all.length > 0) project.assets = all;
  else delete project.assets;

  return {
    project,
    services: assets.length,
    cves: assets.reduce((n, a) => n + a.identifiers.filter((i) => i.scheme === 'cve').length, 0),
    unlinkedHosts: [...unlinked].sort(),
    badNodeRefs: [...badRefs].sort(),
  };
}
