import { LAYER_KEYS, type Asset, type DiagramNode, type LayerKey } from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';

/**
 * 図の「外部公開」の入力（attackSurface.hasGlobalIp）と、ASM（Shodan・ScopeSentry）が観測した資産の突き合わせ。
 * 判定はせず、食い違いを事実として並べる。時系列の保存はせず、--previous のファイル同士の比較だけ行う。
 * 設計の背景は docs/research/nco-advisory-2026-11-05.md §2・§3（候補 E）。
 */

export interface ReconcileLayers {
  [layer: string]: { nodes: DiagramNode[] } | undefined;
}

export interface ReconcileInput {
  layers: ReconcileLayers;
  assets?: readonly Asset[];
}

export interface ObservedLine {
  assetId: string;
  host: string;
  ip?: string;
  port?: number;
  serviceName?: string;
  product: string;
  observedAt?: string;
  /** 結びついたノードの表示名（無ければ undefined）。 */
  node?: string;
}

export interface PublicButUnseenNode {
  layer: LayerKey;
  nodeId: string;
  node: string;
}

export interface ReconcileResult {
  observedCount: number;
  unbound: ObservedLine[];
  privateButObserved: ObservedLine[];
  unsetButObserved: ObservedLine[];
  /** 観測が 1 件も無いとき null（ASM 結果が未取り込み）。 */
  publicButUnseen: PublicButUnseenNode[] | null;
  /** --previous 指定時だけ入る。 */
  diff?: { appeared: ObservedLine[]; disappeared: ObservedLine[] };
}

/** ASM が観測した資産（API 定義由来は除く）。 */
export function observedAssets(assets: readonly Asset[] | undefined): Asset[] {
  return (assets ?? []).filter((a) => (a.source.format === 'shodan' || a.source.format === 'scopesentry') && a.source.definition !== true);
}

/** 資産の同一判定の鍵（ip:port → host:port → asset.id）。 */
export function assetIdentityKey(a: Asset): string {
  if (a.port != null && a.ip) return `${a.ip}:${a.port}`;
  if (a.port != null && a.host) return `${a.host}:${a.port}`;
  return a.id;
}

function nodeName(n: DiagramNode): string {
  return `${n.seq != null ? formatElementalId('node', n.seq) : n.id} ${n.label?.trim() || n.type}`;
}

function findNode(layers: ReconcileLayers, subject: Asset['subject']): DiagramNode | undefined {
  if (!subject) return undefined;
  return layers[subject.layer]?.nodes.find((n) => n.id === subject.nodeId);
}

function line(a: Asset, node?: DiagramNode): ObservedLine {
  return {
    assetId: a.id,
    host: a.host,
    ...(a.ip ? { ip: a.ip } : {}),
    ...(a.port != null ? { port: a.port } : {}),
    ...(a.serviceName ? { serviceName: a.serviceName } : {}),
    product: a.source.product,
    ...(a.observedAt ? { observedAt: a.observedAt } : {}),
    ...(node ? { node: nodeName(node) } : {}),
  };
}

export function reconcileAsm(input: ReconcileInput, previousAssets?: readonly Asset[]): ReconcileResult {
  const observed = observedAssets(input.assets);
  const unbound: ObservedLine[] = [];
  const privateButObserved: ObservedLine[] = [];
  const unsetButObserved: ObservedLine[] = [];
  const boundKeys = new Set<string>();

  for (const a of observed) {
    const node = findNode(input.layers, a.subject);
    if (!node) {
      unbound.push(line(a));
      continue;
    }
    boundKeys.add(`${a.subject!.layer}:${node.id}`);
    const g = node.attackSurface?.hasGlobalIp;
    if (g === false) privateButObserved.push(line(a, node));
    else if (g === undefined) unsetButObserved.push(line(a, node));
  }

  let publicButUnseen: PublicButUnseenNode[] | null = null;
  if (observed.length > 0) {
    publicButUnseen = [];
    for (const layer of LAYER_KEYS) {
      for (const n of input.layers[layer]?.nodes ?? []) {
        if (n.attackSurface?.hasGlobalIp === true && !boundKeys.has(`${layer}:${n.id}`)) {
          publicButUnseen.push({ layer, nodeId: n.id, node: nodeName(n) });
        }
      }
    }
  }

  const result: ReconcileResult = { observedCount: observed.length, unbound, privateButObserved, unsetButObserved, publicButUnseen };
  if (previousAssets) {
    const prev = new Map(observedAssets(previousAssets).map((a) => [assetIdentityKey(a), a]));
    const cur = new Map(observed.map((a) => [assetIdentityKey(a), a]));
    result.diff = {
      appeared: [...cur].filter(([k]) => !prev.has(k)).map(([, a]) => line(a, findNode(input.layers, a.subject))),
      disappeared: [...prev].filter(([k]) => !cur.has(k)).map(([, a]) => line(a)),
    };
  }
  return result;
}
