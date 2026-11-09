import type {
  AuthType,
  ComponentTypeId,
  DataFlow,
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  EdgeProtocol,
  EncryptionType,
  LayerData,
  NetworkType,
  TrustLevel,
} from '../../core/model/types';
import { resolveNodeBoundaries } from '../../core/canvas/boundaryCrossing';
import { formatElementalId } from '../../core/model/elementalId';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';

/**
 * DFD LIST（構成要素一覧・データフロー一覧）の行を、1 レイヤーの図から作る純関数。
 * 既存システムの遡りレビューで使う「構成要素ごとの情報」「データフローごとの情報」の表に当たる。
 * 記録と表示のみ：脅威エンジンの結果は使わない。列挙値は生値のまま返し、訳語は画面側で付ける。
 */

export interface DfdElementRef {
  /** 表示 ID（C3 / Z1）。採番の無い旧データは内部 id。 */
  displayId: string;
  name: string;
}

export interface DfdZoneRef extends DfdElementRef {
  trustLevel: TrustLevel;
}

export interface DfdComponentRow {
  id: string;
  displayId: string;
  type: ComponentTypeId;
  name: string;
  description: string;
  /** 内包元のノード（親）。 */
  parent?: DfdElementRef;
  /** 属する信頼境界。内側から順。 */
  zones: DfdZoneRef[];
  /** 内包しているノード（子）。 */
  contains: DfdElementRef[];
}

export interface DfdFlowRow {
  id: string;
  displayId: string;
  name: string;
  /** 送信元・送信先は通信の向き（dataFlow）に合わせる。inbound は線の向きと逆。 */
  from: DfdElementRef;
  to: DfdElementRef;
  bidirectional: boolean;
  protocol?: EdgeProtocol;
  network: NetworkType;
  auth: AuthType;
  encryption: EncryptionType;
  description: string;
}

export interface DfdList {
  components: DfdComponentRow[];
  flows: DfdFlowRow[];
}

const bySeq = <T extends { id: string; seq?: number }>(a: T, b: T): number =>
  (a.seq ?? Number.MAX_SAFE_INTEGER) - (b.seq ?? Number.MAX_SAFE_INTEGER) || a.id.localeCompare(b.id);

function nodeRef(n: DiagramNode | undefined, fallbackId: string): DfdElementRef {
  if (!n) return { displayId: fallbackId, name: fallbackId };
  return { displayId: n.seq != null ? formatElementalId('node', n.seq) : n.id, name: getNodeDisplayName(n) };
}

function zoneRef(b: DiagramBoundary): DfdZoneRef {
  return {
    displayId: b.seq != null ? formatElementalId('boundary', b.seq) : b.id,
    name: b.label?.trim() ?? '',
    trustLevel: b.trustLevel,
  };
}

export function buildDfdList(layer: LayerData): DfdList {
  const nodes = [...layer.nodes].sort(bySeq);
  const byId = new Map(layer.nodes.map((n) => [n.id, n]));
  const owning = resolveNodeBoundaries(layer.nodes, layer.boundaries);

  const components = nodes.map((n): DfdComponentRow => {
    const parent = n.parentId ? byId.get(n.parentId) : undefined;
    return {
      id: n.id,
      displayId: nodeRef(n, n.id).displayId,
      type: n.type,
      name: getNodeDisplayName(n),
      description: n.description?.trim() ?? '',
      ...(parent ? { parent: nodeRef(parent, parent.id) } : {}),
      zones: (owning.get(n.id) ?? []).map(zoneRef),
      contains: nodes.filter((c) => c.parentId === n.id).map((c) => nodeRef(c, c.id)),
    };
  });

  const flows = [...layer.edges].sort(bySeq).map((e: DiagramEdge): DfdFlowRow => {
    const source = nodeRef(byId.get(e.source), e.source);
    const target = nodeRef(byId.get(e.target), e.target);
    const dir: DataFlow = e.dataFlow ?? 'outbound';
    return {
      id: e.id,
      displayId: e.seq != null ? formatElementalId('edge', e.seq) : e.id,
      name: e.dataFlowName?.trim() ?? '',
      from: dir === 'inbound' ? target : source,
      to: dir === 'inbound' ? source : target,
      bidirectional: dir === 'bidirectional',
      ...(e.protocol ? { protocol: e.protocol } : {}),
      network: e.network,
      auth: e.auth,
      encryption: e.encryption,
      description: e.description?.trim() ?? '',
    };
  });

  return { components, flows };
}

/** データフロー一覧で並べ替えできる列。 */
export type DfdFlowSortKey = 'id' | 'name' | 'from' | 'to' | 'protocol';
export type SortDirection = 'asc' | 'desc';

/**
 * データフローの行を並べ替える（元の配列は変えない）。ID は番号順（DF2 < DF10）、
 * 送信元・送信先は「C1 名前」の表示どおり。空の値は向きによらず末尾に置く。
 * プロトコルは画面の表示名で比べるため、訳語の取り出しを呼び出し側から渡す。
 */
export function sortDfdFlows(
  rows: readonly DfdFlowRow[],
  key: DfdFlowSortKey,
  direction: SortDirection,
  protocolLabel: (p: EdgeProtocol) => string,
): DfdFlowRow[] {
  const valueOf = (r: DfdFlowRow): string => {
    switch (key) {
      case 'id':
        return r.displayId;
      case 'name':
        return r.name;
      case 'from':
        return `${r.from.displayId} ${r.from.name}`;
      case 'to':
        return `${r.to.displayId} ${r.to.name}`;
      case 'protocol':
        return r.protocol ? protocolLabel(r.protocol) : '';
    }
  };
  const sign = direction === 'asc' ? 1 : -1;
  return [...rows].sort((a, b) => {
    const va = valueOf(a);
    const vb = valueOf(b);
    if (va === '' || vb === '') return (va === '' ? 1 : 0) - (vb === '' ? 1 : 0);
    return sign * va.localeCompare(vb, undefined, { numeric: true });
  });
}
