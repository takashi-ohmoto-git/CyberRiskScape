import { normalizeIdentifierValue } from '../../core/model/identifierSchemes';
import { LAYER_KEYS, type Asset, type DiagramNode, type LayerKey } from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';
import { matchServiceScope, type ScopeTarget, type ServiceScopeEntry } from '../../core/model/serviceScope';

/**
 * 図の「外部公開」の入力（attackSurface.hasGlobalIp）と、ASM（Shodan・ScopeSentry）が観測した資産の突き合わせ。
 * 判定はせず、食い違いを事実として並べる。時系列の保存はせず、--previous のファイル同士の比較だけ行う。
 * 設計の背景は docs/research/nco-advisory-2026-11-05.md §2・§3（候補 E）。
 * サービスの担当範囲が入力されていれば、観測を担当範囲の中・外に分ける（docs/org-view.md §2.3）。
 */

export interface ReconcileLayers {
  [layer: string]: { nodes: DiagramNode[] } | undefined;
}

export interface ReconcileInput {
  layers: ReconcileLayers;
  assets?: readonly Asset[];
  /** サービスの担当範囲（docs/org-view.md §2.3）。空なら担当範囲での区分をしない。 */
  serviceScope?: readonly ServiceScopeEntry[];
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

/** 観測した API のエンドポイント 1 件（API 定義・手入力は除く）。 */
export interface ObservedEndpoint {
  assetId: string;
  method?: string;
  url: string;
  product: string;
  node?: string;
}

/**
 * 担当範囲での区分。担当範囲の中で図に無いもの＝このモデルの描き漏れ。担当範囲の外のもの＝このモデルの
 * 担当ではない（他のサービスの担当かもしれない）。どちらも判定はしない。
 */
export interface ScopeSplit {
  /** 担当範囲の件数。 */
  entries: number;
  unboundInScope: ObservedLine[];
  outOfScope: ObservedLine[];
  endpointsUnboundInScope: ObservedEndpoint[];
  endpointsOutOfScope: ObservedEndpoint[];
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
  /** 担当範囲が入力されているときだけ入る。 */
  scope?: ScopeSplit;
}

/** ASM が観測した資産（API 定義由来は除く）。 */
export function observedAssets(assets: readonly Asset[] | undefined): Asset[] {
  return (assets ?? []).filter((a) => (a.source.format === 'shodan' || a.source.format === 'scopesentry') && a.source.definition !== true);
}

/** 観測した API のエンドポイント（URL を持つ。API 定義由来・手入力は観測ではないので除く）。 */
export function observedEndpoints(assets: readonly Asset[] | undefined): Asset[] {
  return (assets ?? []).filter(
    (a) => a.kind === 'endpoint' && !!a.url && a.source.definition !== true && a.source.format !== 'manual',
  );
}

/** 資産の同一判定の鍵（ip:port → host:port → asset.id）。IP・ホストは表記をそろえてから鍵にする。 */
export function assetIdentityKey(a: Asset): string {
  if (a.port != null && a.ip) return `${normalizeIdentifierValue('ip', a.ip)}:${a.port}`;
  if (a.port != null && a.host) return `${normalizeIdentifierValue('fqdn', a.host)}:${a.port}`;
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
  const scope = input.serviceScope ?? [];
  if (scope.length > 0) {
    const inScope = (t: ScopeTarget) => matchServiceScope(scope, t) !== undefined;
    const split: ScopeSplit = { entries: scope.length, unboundInScope: [], outOfScope: [], endpointsUnboundInScope: [], endpointsOutOfScope: [] };
    for (const a of observed) {
      const node = findNode(input.layers, a.subject);
      if (!inScope({ host: a.host, ip: a.ip })) split.outOfScope.push(line(a, node));
      else if (!node) split.unboundInScope.push(line(a));
    }
    for (const a of observedEndpoints(input.assets)) {
      const node = findNode(input.layers, a.subject);
      const ep: ObservedEndpoint = {
        assetId: a.id,
        ...(a.method ? { method: a.method } : {}),
        url: a.url!,
        product: a.source.product,
        ...(node ? { node: nodeName(node) } : {}),
      };
      if (!inScope({ url: a.url, ip: a.ip })) split.endpointsOutOfScope.push(ep);
      else if (!node) split.endpointsUnboundInScope.push(ep);
    }
    result.scope = split;
  }
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
