import { parse as parseYaml, type CollectionTag, type ScalarTag, type YAMLMap } from 'yaml';
import { z } from 'zod';
import type {
  AuthType,
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  EncryptionType,
  LayerData,
  NetworkType,
  TrustLevel,
} from '../../core/model/types';
import { getLocale, translate } from '../../i18n';

/**
 * Kong AI Gateway 2.x の kongctl 宣言ファイルから、構成図の下書き（1 レイヤー分）を作る。
 *
 * 方針（`kong-import/kongToLayer.ts` と同じ）：
 * - **秘密情報を読まない。** `!secret`・`!env` は中身を読まず固定の目印に置き換える。provider の `config.auth`、
 *   auth strategy の `client_id` / `client_secret`、`config.upstream.auth` の鍵、consumer の資格情報は触れない。
 *   URL はホスト名とスキームだけを使う（userinfo・パス・クエリは捨てる）。
 * - **脅威の知識は持たない。** エンティティを図の要素（ノード型・エッジの auth / encryption）に置き換えるだけで、
 *   脅威の判定は既存の脅威ルールに任せる。
 * - 大方針「未入力＝悪い値」：auth strategy が付いていなければ認証なし、proxy_urls が無ければ平文と仮定する。
 * - 子エンティティは、トップレベル（`ai_gateway_models` 等。親は `ai_gateway:` で参照）と
 *   `ai_gateways[]` の下の入れ子の両方を読む。
 *
 * 出力はテンプレート取り込みと同じ形（`seq` なし）。
 */

// ── 独自タグ（kongctl の !secret / !env / !lookup / !ref）──────────────────

const SECRET_MARK = '(secret)';

/** `!lookup` / `!ref` の結果。name が無ければ解決不能（id 指定など）。 */
interface Lookup {
  __lookup: true;
  name?: string;
}

const isLookup = (v: unknown): v is Lookup =>
  typeof v === 'object' && v !== null && (v as Lookup).__lookup === true;

function scalarTag(tag: string, resolve: (value: string) => unknown): ScalarTag {
  return { tag, resolve: (value: string) => resolve(value) };
}
function mapTag(tag: string, resolve: (map: YAMLMap) => unknown): CollectionTag {
  return { tag, collection: 'map', resolve: (map) => resolve(map as YAMLMap) };
}

/** `!lookup name:x`（x を参照名とする）。`id:…` や他の形は解決できない。 */
const lookupFromScalar = (value: string): Lookup => {
  const m = /^name:\s*(.+)$/.exec(value.trim());
  return { __lookup: true, name: m?.[1] };
};
const lookupFromMap = (map: YAMLMap): Lookup => {
  const name = map.get('name');
  return { __lookup: true, name: typeof name === 'string' ? name : undefined };
};
/** `!ref x#id` は x という名前のリソースの id を参照する → 名前 x で引く。 */
const refFromScalar = (value: string): Lookup => {
  const name = value.split('#')[0]?.trim();
  return { __lookup: true, name: name || undefined };
};

const CUSTOM_TAGS = [
  scalarTag('!secret', () => SECRET_MARK),
  mapTag('!secret', () => SECRET_MARK),
  scalarTag('!env', () => SECRET_MARK),
  scalarTag('!lookup', lookupFromScalar),
  mapTag('!lookup', lookupFromMap),
  scalarTag('!ref', refFromScalar),
];

// ── 入力スキーマ（必要な項目だけを緩く検証。未知のキーは無視する）──────────────

const ProxyUrlSchema = z.object({
  host: z.string().optional(),
  port: z.union([z.number(), z.string()]).optional(),
  protocol: z.string().optional(),
});

const TargetSchema = z.object({
  name: z.string().optional(),
  provider: z.unknown().optional(),
});

const EntitySchema = z.object({
  name: z.string().optional(),
  id: z.string().optional(),
  display_name: z.string().optional(),
  ai_gateway: z.unknown().optional(),
  type: z.string().optional(),
  enabled: z.boolean().optional(),
  global: z.boolean().optional(),
  deployment_type: z.string().optional(),
  proxy_urls: z.array(ProxyUrlSchema).optional(),
  config: z.record(z.unknown()).optional(),
  access: z.object({ auth_strategies: z.array(z.unknown()).optional() }).optional(),
  policies: z.array(z.unknown()).optional(),
  targets: z.array(TargetSchema).optional(),
  sources: z.array(z.unknown()).optional(),
});
type Entity = z.infer<typeof EntitySchema>;

const EntityListSchema = z.array(EntitySchema);

const CHILD_KEYS = [
  'model_providers',
  'models',
  'mcp_servers',
  'agents',
  'auth_strategies',
  'policies',
  'consumers',
  'vaults',
] as const;
type ChildKey = (typeof CHILD_KEYS)[number];

// ── 分類 ────────────────────────────────────────────────────

const GUARD_POLICIES = new Set([
  'ai-prompt-guard',
  'ai-semantic-prompt-guard',
  'ai-semantic-response-guard',
  'ai-sanitizer',
  'ai-lakera-guard',
  'ai-azure-content-safety',
  'ai-aws-guardrails',
  'ai-gcp-model-armor',
  'ai-custom-guardrail',
]);

const TRANSFORMER_POLICIES = new Set(['ai-request-transformer', 'ai-response-transformer']);

/** 自組織内で動かすことが多いプロバイダ。それ以外は外部（Internet）に置く。 */
const SELF_HOSTED_PROVIDERS = new Set(['ollama', 'vllm', 'llama', 'llama2']);

const AUTH_STRATEGY_TYPE: Record<string, AuthType> = {
  'key-auth': 'ApiKey',
  'openid-connect': 'Token',
};

const WEAKNESS: Record<AuthType, number> = {
  None: 0,
  Password: 1,
  ApiKey: 1,
  Token: 2,
  MFA: 2,
  Passkey: 3,
  Certificate: 3,
};

function weakestAuth(auths: AuthType[]): AuthType {
  return auths.reduce((a, b) => (WEAKNESS[b] < WEAKNESS[a] ? b : a), auths[0] ?? 'None');
}

/** 参照（文字列・`!lookup`・`{name}`/`{id}`）から名前を取り出す。解決できなければ undefined。 */
function refName(ref: unknown): string | undefined {
  if (typeof ref === 'string') return ref === SECRET_MARK ? undefined : ref;
  if (isLookup(ref)) return ref.name;
  if (typeof ref === 'object' && ref !== null) {
    const r = ref as Record<string, unknown>;
    if (typeof r.name === 'string') return r.name;
    if (typeof r.id === 'string') return r.id;
  }
  return undefined;
}

/** 組織内のホストか（localhost・プライベート IPv4・ドットなし・社内向けサフィックス）。 */
export function isInternalHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host === 'host.docker.internal' || host === '::1') return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  if (!host.includes('.')) return true;
  return ['.internal', '.local', '.svc', '.cluster.local', '.lan', '.corp'].some((s) => host.endsWith(s));
}

/** URL からスキームとホストだけを取り出す（userinfo・パス・クエリは捨てる）。 */
function schemeAndHost(url: unknown): { scheme?: string; host?: string } {
  if (typeof url !== 'string') return {};
  try {
    const u = new URL(url);
    return { scheme: u.protocol.replace(/:$/, ''), host: u.hostname };
  } catch {
    return {};
  }
}

// ── 組み立て ────────────────────────────────────────────────

export interface KongctlImportSummary {
  gateways: number;
  models: number;
  mcpServers: number;
  agents: number;
  policies: number;
  consumers: number;
}

export type KongctlImportResult =
  | { ok: true; name: string; layer: LayerData; summary: KongctlImportSummary }
  | { ok: false; error: string };

interface GwInfo {
  key: string;
  label: string;
  data: Entity | undefined;
  children: Record<ChildKey, Entity[]>;
}

const emptyChildren = (): Record<ChildKey, Entity[]> => ({
  model_providers: [],
  models: [],
  mcp_servers: [],
  agents: [],
  auth_strategies: [],
  policies: [],
  consumers: [],
  vaults: [],
});

export function kongctlToLayer(text: string): KongctlImportResult {
  const locale = getLocale();
  const t = (key: Parameters<typeof translate>[0], params?: Record<string, string | number>) =>
    translate(key, locale, params);

  let raw: unknown;
  try {
    raw = parseYaml(text, { customTags: CUSTOM_TAGS });
  } catch (e) {
    return { ok: false, error: t('kongctl.error.parse', { message: (e as Error).message }) };
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return { ok: false, error: t('kongctl.error.noEntities') };
  }
  const root = raw as Record<string, unknown>;

  // 読むキーだけを検証する（他のリソースは無視）。
  const lists: Record<string, Entity[]> = {};
  const issues: string[] = [];
  for (const key of ['ai_gateways', ...CHILD_KEYS.map((k) => `ai_gateway_${k}`)]) {
    if (root[key] === undefined || root[key] === null) continue;
    const r = EntityListSchema.safeParse(root[key]);
    if (r.success) lists[key] = r.data;
    else issues.push(...r.error.issues.map((i) => `${key}.${i.path.join('.')}: ${i.message}`));
  }
  if (issues.length > 0) {
    return { ok: false, error: t('io.validationError', { issues: issues.join('; ') }) };
  }

  const gwEntities = lists.ai_gateways ?? [];
  const hasTopChildren = CHILD_KEYS.some((k) => (lists[`ai_gateway_${k}`] ?? []).length > 0);
  if (gwEntities.length === 0 && !hasTopChildren) {
    const hasCp = root.control_planes !== undefined && root.control_planes !== null;
    return { ok: false, error: t(hasCp ? 'kongctl.error.deckOnly' : 'kongctl.error.noEntities') };
  }

  // ゲートウェイごとに子エンティティを集める（入れ子 → トップレベルの順）。
  const gateways: GwInfo[] = gwEntities.map((g, i) => {
    // Zod は未知のキーを落とすので、入れ子の子は元のデータから読む。
    const nested = ((root.ai_gateways as unknown[])[i] ?? {}) as Record<string, unknown>;
    const children = emptyChildren();
    for (const k of CHILD_KEYS) {
      const r = EntityListSchema.safeParse(nested[k] ?? []);
      if (r.success) children[k].push(...r.data);
    }
    const key = g.name ?? g.id ?? g.display_name ?? `gateway-${i + 1}`;
    return { key, label: g.display_name ?? g.name ?? t('kongctl.node.gateway'), data: g, children };
  });
  if (gateways.length === 0) {
    gateways.push({ key: 'default', label: t('kongctl.node.gateway'), data: undefined, children: emptyChildren() });
  }
  /** 親ゲートウェイの参照を解決する。解決できなければ最初のゲートウェイ。 */
  const resolveGw = (ref: unknown): GwInfo => {
    const name = refName(ref);
    const found =
      name === undefined
        ? undefined
        : gateways.find((g) => g.data?.name === name || g.data?.id === name || g.data?.display_name === name);
    return found ?? gateways[0];
  };
  for (const k of CHILD_KEYS) {
    for (const e of lists[`ai_gateway_${k}`] ?? []) resolveGw(e.ai_gateway).children[k].push(e);
  }

  const nodes: DiagramNode[] = [];
  const edges: DiagramEdge[] = [];
  // ID は設定上の名前から決める（エンティティを足しても既存要素の ID が変わらない）。
  const addEdge = (
    source: string,
    target: string,
    auth: AuthType,
    network: NetworkType,
    encryption: EncryptionType,
    extra: Partial<DiagramEdge> = {},
  ) => {
    const id = `${source}--${target}`;
    if (edges.some((e) => e.id === id)) return;
    edges.push({ id, source, target, auth, network, encryption, ...extra });
  };

  const COL = { client: 60, gateway: 340, internal: 640, external: 940 };
  const ROW = 150;
  const TOP = 120;
  let internalRow = 0;
  let externalRow = 0;
  const internalIds: string[] = [];
  const externalIds: string[] = [];
  const gatewayIds: string[] = [];
  const supportIds: string[] = [];

  /** 組織内（true）か外部（false）かに応じて列と行を決め、境界の所属も記録する。 */
  const place = (id: string, internal: boolean) => {
    (internal ? internalIds : externalIds).push(id);
    return { x: internal ? COL.internal : COL.external, y: TOP + (internal ? internalRow++ : externalRow++) * ROW };
  };

  const client: DiagramNode = {
    id: 'kongctl-client',
    type: 'EXTERNAL_ENTITY',
    x: COL.client,
    y: TOP,
    label: t('kongctl.node.client'),
  };
  nodes.push(client);

  const vaultNames: string[] = [];
  const counts = { models: 0, mcpServers: 0, agents: 0, policies: 0, consumers: 0 };

  gateways.forEach((g, gi) => {
    const gwId = `kongctl-gw-${g.key}`;
    const c = g.children;
    counts.models += c.models.length;
    counts.mcpServers += c.mcp_servers.length;
    counts.agents += c.agents.length;
    counts.policies += c.policies.length;
    counts.consumers += c.consumers.length;
    vaultNames.push(...c.vaults.map((v) => v.name ?? v.id ?? '').filter(Boolean));

    // 参照解決用の表。
    const providerType = new Map<string, string>();
    for (const p of c.model_providers) {
      for (const k of [p.name, p.id]) if (k && p.type) providerType.set(k, p.type);
    }
    const strategyType = new Map<string, string>();
    for (const s of c.auth_strategies) {
      for (const k of [s.name, s.id]) if (k && s.type) strategyType.set(k, s.type);
    }
    const attached = new Set<string>();
    for (const e of [...c.models, ...c.mcp_servers, ...c.agents]) {
      for (const p of e.policies ?? []) {
        const n = refName(p);
        if (n) attached.add(n);
      }
    }

    /** access.auth_strategies から、公開時の認証（最も弱いもの）と表示用の名前を決める。 */
    const entityAuth = (e: Entity): { auth: AuthType; names: string[] } => {
      const refs = (e.access?.auth_strategies ?? []).map(refName);
      if (refs.length === 0) return { auth: 'None', names: [] };
      const types = refs.map((r) => (r ? strategyType.get(r) : undefined));
      // 型が分からない strategy は、付いている以上 None ではなく API キー相当（弱い側）とみなす。
      const auths = types.map((ty) => AUTH_STRATEGY_TYPE[ty ?? ''] ?? 'ApiKey');
      return { auth: weakestAuth(auths), names: types.map((ty, i) => ty ?? refs[i] ?? '-') };
    };

    const gwNode: DiagramNode = { id: gwId, type: 'AI_GATEWAY', x: COL.gateway, y: TOP + gi * ROW, label: g.label };
    gatewayIds.push(gwId);

    const publicLines: string[] = [];
    const publicAuths: AuthType[] = [];
    const publish = (label: string, e: Entity) => {
      const { auth, names } = entityAuth(e);
      publicAuths.push(auth);
      publicLines.push(`${label}: ${auth === 'None' ? t('kongctl.desc.noAuth') : names.join(' + ')}`);
    };

    /** 上流 URL とその認証から、配置・エッジの属性を決める。URL が無ければ組織内・平文と仮定する。 */
    const upstream = (e: Entity) => {
      const { scheme, host } = schemeAndHost(e.config?.url);
      const upstreamCfg = e.config?.upstream as Record<string, unknown> | undefined;
      return {
        host,
        internal: host === undefined ? true : isInternalHost(host),
        auth: (upstreamCfg?.auth !== undefined ? 'ApiKey' : 'None') as AuthType,
        enc: (scheme === 'https' ? 'TLS' : 'Plain') as EncryptionType,
      };
    };
    const connect = (from: string, to: string, u: ReturnType<typeof upstream>) =>
      addEdge(from, to, u.auth, u.internal ? 'VPC' : 'Internet', u.enc, { dataFlow: 'bidirectional' });

    const addLlm = (id: string, provider: string, model: string | undefined, description: string) => {
      const selfHosted = SELF_HOSTED_PROVIDERS.has(provider);
      nodes.push({ id, type: 'LLM', ...place(id, selfHosted), label: model ? `${provider} / ${model}` : provider, description });
      addEdge(gwId, id, selfHosted ? 'Password' : 'ApiKey', selfHosted ? 'VPC' : 'Internet', 'TLS', { dataFlow: 'bidirectional' });
    };
    const addDb = (id: string, strategy: string, description: string) => {
      nodes.push({ id, type: 'DB', ...place(id, true), label: t('kongctl.node.vectordb', { strategy }), description });
      addEdge(gwId, id, 'Password', 'VPC', 'TLS', { dataFlow: 'bidirectional' });
    };

    // モデル：ターゲットごとに LLM。公開エンティティ。
    c.models.forEach((m, mi) => {
      const mName = m.name ?? `model-${mi + 1}`;
      const paths = (m.config?.route as Record<string, unknown> | undefined)?.paths;
      const desc = t('kongctl.desc.model', {
        name: mName,
        paths: Array.isArray(paths) ? paths.filter((p) => typeof p === 'string').join(', ') || '-' : '-',
      });
      (m.targets ?? []).forEach((target, ti) => {
        const pRef = refName(target.provider);
        const provider = (pRef ? (providerType.get(pRef) ?? pRef) : undefined) ?? 'llm';
        addLlm(`kongctl-llm-${g.key}-${mName}-${ti}`, provider, target.name, desc);
      });
      publish(mName, m);
      const vdb = (m.config?.balancer as Record<string, unknown> | undefined)?.vectordb;
      if (typeof vdb === 'object' && vdb !== null) {
        const strategy = (vdb as Record<string, unknown>).strategy;
        addDb(`kongctl-db-${g.key}-${mName}`, typeof strategy === 'string' ? strategy : 'vectordb', desc);
      }
    });

    // エージェント：背後に AGENT。公開エンティティ。
    c.agents.forEach((a, ai) => {
      const aName = a.name ?? `agent-${ai + 1}`;
      const u = upstream(a);
      const id = `kongctl-agent-${g.key}-${aName}`;
      nodes.push({
        id,
        type: 'AGENT',
        ...place(id, u.internal),
        label: aName,
        description: t('kongctl.desc.entity', { kind: a.type ?? 'agent', name: aName, host: u.host ?? '-' }),
      });
      connect(gwId, id, u);
      publish(aName, a);
    });

    // MCP サーバー：type ごとに配置を変える（無効なものは無視）。
    const mcps = c.mcp_servers.filter((s) => s.enabled !== false);
    const mcpKey = (s: Entity, i: number) => s.name ?? `mcp-${i + 1}`;
    const mcpNodeId = new Map<string, string>();
    const referenced = new Set<string>();
    for (const s of mcps) {
      if (s.type !== 'listener') continue;
      for (const src of s.sources ?? []) {
        const n = refName(src);
        if (n) referenced.add(n);
      }
    }
    // 背後のノード（passthrough-listener・upstream-server は MCP_SERVER、conversion-only は BACKEND_API）。
    mcps.forEach((s, i) => {
      const name = mcpKey(s, i);
      const behind = s.type === 'passthrough-listener' || s.type === 'upstream-server' || s.type === 'conversion-only';
      if (!behind) return;
      const u = upstream(s);
      const id = `kongctl-mcp-${g.key}-${name}`;
      mcpNodeId.set(name, id);
      nodes.push({
        id,
        type: s.type === 'conversion-only' ? 'BACKEND_API' : 'MCP_SERVER',
        ...place(id, u.internal),
        label: name,
        description: t('kongctl.desc.entity', { kind: s.type ?? 'mcp', name, host: u.host ?? '-' }),
      });
      if (s.type === 'passthrough-listener') {
        connect(gwId, id, u);
        publish(name, s);
      } else if (!referenced.has(name)) {
        connect(gwId, id, u);
      }
    });
    // Kong 自身が MCP サーバーになるもの（conversion-listener・listener）。
    mcps.forEach((s, i) => {
      if (s.type !== 'conversion-listener' && s.type !== 'listener') return;
      const name = mcpKey(s, i);
      const id = `kongctl-mcp-${g.key}-${name}`;
      mcpNodeId.set(name, id);
      nodes.push({
        id,
        type: 'MCP_SERVER',
        ...place(id, true),
        label: t('kongctl.node.mcpKong', { name }),
        description: t('kongctl.desc.entity', { kind: s.type, name, host: '-' }),
      });
      addEdge(gwId, id, 'None', 'VPC', 'TLS', { dataFlow: 'bidirectional' });
      publish(name, s);
      if (s.type === 'conversion-listener') {
        const u = upstream(s);
        const backId = `${id}-backend`;
        nodes.push({
          id: backId,
          type: 'BACKEND_API',
          ...place(backId, u.internal),
          label: name,
          description: t('kongctl.desc.entity', { kind: 'REST', name, host: u.host ?? '-' }),
        });
        connect(id, backId, u);
      } else {
        for (const src of s.sources ?? []) {
          const srcName = refName(src) ?? '';
          const target = mcpNodeId.get(srcName);
          const srcEntity = mcps.find((m, mi) => mcpKey(m, mi) === srcName);
          if (target && srcEntity) connect(id, target, upstream(srcEntity));
        }
      }
    });

    // ポリシー：ガード → GUARDRAIL、transformer の config.llm → LLM、vectordb → DB（無効なものは無視）。
    const guardTypes = new Set<string>();
    c.policies
      .filter((p) => p.enabled !== false)
      .forEach((p, pi) => {
        const pName = p.name ?? `policy-${pi + 1}`;
        const type = p.type ?? '';
        const isActive = p.global === true || attached.has(pName) || (p.id !== undefined && attached.has(p.id));
        if (GUARD_POLICIES.has(type) && isActive) guardTypes.add(type);
        if (TRANSFORMER_POLICIES.has(type)) {
          const llm = p.config?.llm as Record<string, unknown> | undefined;
          const model = llm?.model as Record<string, unknown> | undefined;
          if (model) {
            const provider = typeof model.provider === 'string' ? model.provider : 'llm';
            const name = typeof model.name === 'string' ? model.name : undefined;
            addLlm(`kongctl-llm-${g.key}-xf-${pName}`, provider, name, `${type}: ${pName}`);
          }
        }
        const vdb = p.config?.vectordb;
        if (typeof vdb === 'object' && vdb !== null) {
          const strategy = (vdb as Record<string, unknown>).strategy;
          addDb(`kongctl-db-${g.key}-${pName}`, typeof strategy === 'string' ? strategy : 'vectordb', `${type}: ${pName}`);
        }
      });
    if (guardTypes.size > 0) {
      const id = `kongctl-guard-${g.key}`;
      nodes.push({ id, type: 'GUARDRAIL', x: COL.gateway, y: 0, label: [...guardTypes].sort().join(', ') });
      supportIds.push(id);
      addEdge(gwId, id, 'None', 'VPC', 'TLS', { dataFlow: 'bidirectional' });
    }

    // クライアント → ゲートウェイ（公開エンティティがあるときだけ。暗号化は proxy_urls から）。
    const proxies = g.data?.proxy_urls ?? [];
    const tls = proxies.length > 0 && proxies.every((p) => (p.protocol ?? '').toLowerCase() === 'https');
    const hosts = [...new Set(proxies.map((p) => p.host).filter((h): h is string => !!h))];
    gwNode.description =
      t('kongctl.desc.gateway', {
        deployment: g.data?.deployment_type ?? '-',
        hosts: hosts.join(', ') || '-',
        auth: publicLines.join(' / ') || '-',
      }) + (publicLines.length > 0 && !tls ? t('kongctl.desc.assumedPlain') : '');
    nodes.push(gwNode);
    if (publicLines.length > 0) {
      addEdge(client.id, gwId, weakestAuth(publicAuths), 'Internet', tls ? 'TLS' : 'Plain', { dataFlow: 'bidirectional' });
    }
  });

  // ゲートウェイの下にガードレール・Vault を並べる。
  let supportRow = gateways.length;
  for (const id of supportIds) {
    const n = nodes.find((x) => x.id === id);
    if (n) n.y = TOP + supportRow++ * ROW;
  }
  if (vaultNames.length > 0 || /\{vault:\/\//.test(text)) {
    nodes.push({
      id: 'kongctl-vault',
      type: 'SECRETS_VAULT',
      x: COL.gateway,
      y: TOP + supportRow * ROW,
      label: t('kongctl.node.vault', { prefixes: [...new Set(vaultNames)].join(', ') || 'vault://' }),
    });
    supportIds.push('kongctl-vault');
    for (const gw of gatewayIds) addEdge(gw, 'kongctl-vault', 'Password', 'VPC', 'TLS', { dataFlow: 'bidirectional' });
  }

  // 管理プレーン（Konnect は Kong 社の SaaS ＝外部）。データプレーン証明書の mTLS で接続する。
  const cpId = 'kongctl-cp';
  nodes.push({ id: cpId, type: 'API_CONTROL_PLANE', ...place(cpId, false), label: t('kongctl.node.controlPlane') });
  for (const gw of gatewayIds) addEdge(cpId, gw, 'Certificate', 'Internet', 'TLS');

  // 信頼境界：クライアント・外部サービス＝Internet（RECT）、ゲートウェイと自組織内＝Internal（ROUNDED・Security Zone）。
  const boundaries: DiagramBoundary[] = [];
  const box = (
    id: string,
    ids: string[],
    type: DiagramBoundary['type'],
    trustLevel: TrustLevel,
    extra: Partial<DiagramBoundary> = {},
  ) => {
    const members = nodes.filter((n) => ids.includes(n.id));
    if (members.length === 0) return;
    const PAD = 40;
    const x = Math.min(...members.map((n) => n.x)) - PAD;
    const y = Math.min(...members.map((n) => n.y)) - PAD - 30;
    const right = Math.max(...members.map((n) => n.x + 128)) + PAD;
    const bottom = Math.max(...members.map((n) => n.y + 96)) + PAD;
    boundaries.push({ id, type, x, y, width: right - x, height: bottom - y, trustLevel, ...extra });
  };
  box('kongctl-b-internet', [client.id], 'RECT', 'Internet');
  box('kongctl-b-internal', [...gatewayIds, ...supportIds, ...internalIds], 'ROUNDED', 'Internal', {
    macroTrust: 'Security Zone',
  });
  box('kongctl-b-external', externalIds, 'RECT', 'Internet');

  return {
    ok: true,
    name: t('kongctl.templateName'),
    layer: { nodes, edges, boundaries, annotations: [] },
    summary: { gateways: gateways.length, ...counts },
  };
}
