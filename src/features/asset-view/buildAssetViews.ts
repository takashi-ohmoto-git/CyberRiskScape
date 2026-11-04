import type { Asset, AssetSubject, ComponentTypeId, DiagramNode, LayerKey } from '../../core/model/types';

/**
 * 資産を Asset タブの 3 つの見方（ホスト・ドメイン／リクエスト／API）に振り分ける（docs/architecture.md §8.7）。
 * エンドポイントはリクエストか API のどちらか一方にだけ載る。URL の字面では判定しない。
 * DOM にも Node にも依存しない純粋関数。
 */

/** このノードに結びつくエンドポイントは API として扱う。 */
export const API_NODE_TYPES: ReadonlySet<ComponentTypeId> = new Set<ComponentTypeId>([
  'BACKEND_API',
  'GATEWAY',
  'CENTRAL_GATEWAY',
  'API_CONTROL_PLANE',
  'AI_GATEWAY',
  'MCP_SERVER',
]);

export type AssetViewNode = Pick<DiagramNode, 'id' | 'type'> & { layer: LayerKey };

export interface HostRow {
  host: string;
  domains: string[];
  /** `443/https` の形。ポート順。 */
  ports: string[];
  technologies: string[];
  /** 結びついたノード（無ければ空＝未対応）。 */
  subjects: AssetSubject[];
  observedAt?: string;
}

export interface ApiGroup {
  /** 結びついたノード。無ければ API 定義の出どころだけで表示する。 */
  subject?: AssetSubject;
  product: string;
  fromDefinition: boolean;
  endpoints: Asset[];
}

export interface AssetViews {
  hosts: HostRow[];
  requests: Asset[];
  apis: ApiGroup[];
}

const latest = (a: string | undefined, b: string | undefined) => (a && b ? (a > b ? a : b) : (a ?? b));

function isApi(asset: Asset, nodes: readonly AssetViewNode[]): boolean {
  if (asset.source.definition) return true;
  const node = asset.subject && nodes.find((n) => n.id === asset.subject?.nodeId);
  return !!node && API_NODE_TYPES.has(node.type);
}

function buildHosts(services: readonly Asset[]): HostRow[] {
  const byHost = new Map<string, { row: HostRow; ports: Map<number | string, string> }>();
  for (const s of services) {
    const key = s.ip ?? s.host;
    const entry = byHost.get(key) ?? {
      row: { host: key, domains: [], ports: [], technologies: [], subjects: [] },
      ports: new Map<number | string, string>(),
    };
    const row = entry.row;
    if (s.domain && !row.domains.includes(s.domain)) row.domains.push(s.domain);
    if (s.port !== undefined) {
      entry.ports.set(s.port, s.serviceName ? `${s.port}/${s.serviceName}` : String(s.port));
    } else if (s.serviceName) {
      entry.ports.set(s.serviceName, s.serviceName);
    }
    for (const t of s.technologies ?? []) if (!row.technologies.includes(t)) row.technologies.push(t);
    if (s.subject && !row.subjects.some((x) => x.nodeId === s.subject?.nodeId)) row.subjects.push(s.subject);
    row.observedAt = latest(row.observedAt, s.observedAt);
    byHost.set(key, entry);
  }
  return [...byHost.values()]
    .map(({ row, ports }) => ({
      ...row,
      ports: [...ports.entries()]
        .sort(([a], [b]) => (typeof a === 'number' && typeof b === 'number' ? a - b : String(a).localeCompare(String(b))))
        .map(([, label]) => label),
    }))
    .sort((a, b) => a.host.localeCompare(b.host, undefined, { numeric: true }));
}

const endpointOrder = (a: Asset, b: Asset) =>
  (a.url ?? '').localeCompare(b.url ?? '') || (a.method ?? '').localeCompare(b.method ?? '');

export function buildAssetViews(assets: readonly Asset[], nodes: readonly AssetViewNode[]): AssetViews {
  const endpoints = assets.filter((a) => a.kind === 'endpoint');
  const apiEndpoints = endpoints.filter((a) => isApi(a, nodes));
  const groups = new Map<string, ApiGroup>();
  for (const e of apiEndpoints) {
    const key = e.subject ? `node:${e.subject.nodeId}` : `source:${e.source.product}`;
    const group = groups.get(key) ?? {
      ...(e.subject ? { subject: e.subject } : {}),
      product: e.source.product,
      fromDefinition: false,
      endpoints: [],
    };
    group.fromDefinition ||= !!e.source.definition;
    group.endpoints.push(e);
    groups.set(key, group);
  }
  return {
    hosts: buildHosts(assets.filter((a) => a.kind === 'service')),
    requests: endpoints.filter((a) => !isApi(a, nodes)).sort(endpointOrder),
    apis: [...groups.values()].map((g) => ({ ...g, endpoints: [...g.endpoints].sort(endpointOrder) })),
  };
}
