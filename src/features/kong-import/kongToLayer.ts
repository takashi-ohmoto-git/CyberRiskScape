import { parse as parseYaml } from 'yaml';
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
 * Kong Gateway の宣言設定（decK の `kong.yaml` / JSON）から、構成図の下書き（1 レイヤー分）を作る。
 *
 * 方針：
 * - **秘密情報を読まない。** 取り出すのはエンティティ名・プラグイン名・URL のホスト・
 *   ai-proxy のプロバイダとモデル名・Vault の prefix だけで、認証ヘッダやコンシューマーの
 *   資格情報（config.auth / keyauth_credentials 等）には触れない。
 * - **脅威の知識は持たない。** プラグインを図の要素（ノード型・エッジの auth / encryption）に
 *   置き換えるだけで、脅威の判定は既存の脅威ルールに任せる。
 * - 認証は控えめに寄せる：認証系プラグインはすべて Password（MFA かは IdP 側の設定で決まり、
 *   この設定からは分からない）。クライアント → ゲートウェイのエッジは 1 本にまとめ、
 *   ルートで到達できるサービスのうち最も弱い認証を採る。
 *
 * 出力はテンプレート取り込みと同じ形（`seq` なし）。UI は `importTemplateToActiveLayer`、
 * CLI はプロジェクト JSON への組み立てで使う。
 */

// ── 入力スキーマ（必要な項目だけを緩く検証。未知のキーは無視する）──────────────

const RefSchema = z.union([z.string(), z.object({ name: z.string().optional(), id: z.string().optional() })]);

const PluginSchema = z.object({
  name: z.string(),
  enabled: z.boolean().optional(),
  service: RefSchema.optional(),
  route: RefSchema.optional(),
  config: z.record(z.unknown()).optional(),
});

const RouteSchema = z.object({
  name: z.string().optional(),
  id: z.string().optional(),
  service: RefSchema.optional(),
  protocols: z.array(z.string()).optional(),
  plugins: z.array(PluginSchema).optional(),
});

const ServiceSchema = z.object({
  name: z.string().optional(),
  id: z.string().optional(),
  url: z.string().optional(),
  protocol: z.string().optional(),
  host: z.string().optional(),
  routes: z.array(RouteSchema).optional(),
  plugins: z.array(PluginSchema).optional(),
});

const KongConfigSchema = z.object({
  _format_version: z.string().optional(),
  services: z.array(ServiceSchema).optional(),
  routes: z.array(RouteSchema).optional(),
  plugins: z.array(PluginSchema).optional(),
  consumers: z.array(z.unknown()).optional(),
  vaults: z.array(z.object({ name: z.string().optional(), prefix: z.string().optional() })).optional(),
});

type KongPlugin = z.infer<typeof PluginSchema>;
type KongRoute = z.infer<typeof RouteSchema>;
type KongService = z.infer<typeof ServiceSchema>;

// ── プラグインの分類 ─────────────────────────────────────────────

const AUTH_PLUGINS = new Set([
  'key-auth',
  'key-auth-enc',
  'basic-auth',
  'hmac-auth',
  'jwt',
  'jwt-signer',
  'oauth2',
  'oauth2-introspection',
  'openid-connect',
  'ldap-auth',
  'ldap-auth-advanced',
  'mtls-auth',
  'ai-mcp-oauth2',
]);

const GUARD_PLUGINS = new Set([
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

const LOG_PLUGINS = new Set([
  'file-log',
  'http-log',
  'tcp-log',
  'udp-log',
  'syslog',
  'loggly',
  'datadog',
  'statsd',
  'opentelemetry',
  'kafka-log',
]);

/** 自組織内で動かすことが多いプロバイダ。それ以外は外部（Partner）に置く。 */
const SELF_HOSTED_PROVIDERS = new Set(['ollama', 'vllm', 'llama', 'llama2']);

const TLS_PROTOCOLS = new Set(['https', 'grpcs', 'tls', 'wss', 'tls_passthrough']);

// ── 組み立て ────────────────────────────────────────────────

export interface KongImportSummary {
  services: number;
  routes: number;
  plugins: number;
  consumers: number;
}

export type KongImportResult =
  | { ok: true; name: string; layer: LayerData; summary: KongImportSummary }
  | { ok: false; error: string };

interface ServiceInfo {
  svc: KongService;
  key: string;
  label: string;
  plugins: KongPlugin[];
  routes: KongRoute[];
}

function refName(ref: z.infer<typeof RefSchema> | undefined): string | undefined {
  if (ref === undefined) return undefined;
  return typeof ref === 'string' ? ref : (ref.name ?? ref.id);
}

/** URL からスキームとホストだけを取り出す（userinfo・パス・クエリは捨てる）。 */
function schemeAndHost(svc: KongService): { scheme?: string; host?: string } {
  if (svc.url) {
    try {
      const u = new URL(svc.url);
      return { scheme: u.protocol.replace(/:$/, ''), host: u.hostname };
    } catch {
      return {};
    }
  }
  return { scheme: svc.protocol, host: svc.host };
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v !== '' ? v : undefined;
}

/** ai-proxy / ai-proxy-advanced からプロバイダとモデル名の組を取り出す。 */
function llmTargets(plugin: KongPlugin): { provider: string; model?: string }[] {
  const asModel = (m: unknown) => {
    const rec = (m ?? {}) as Record<string, unknown>;
    return { provider: str(rec.provider) ?? 'llm', model: str(rec.name) };
  };
  if (plugin.name === 'ai-proxy') return [asModel(plugin.config?.model)];
  const targets = plugin.config?.targets;
  if (!Array.isArray(targets) || targets.length === 0) return [{ provider: 'llm' }];
  return targets.map((t) => asModel((t as Record<string, unknown> | null)?.model));
}

const WEAKNESS: Record<AuthType, number> = { None: 0, Password: 1, MFA: 2 };

export function kongToLayer(text: string): KongImportResult {
  const locale = getLocale();
  const t = (key: Parameters<typeof translate>[0], params?: Record<string, string | number>) =>
    translate(key, locale, params);

  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch (e) {
    return { ok: false, error: t('kong.error.parse', { message: (e as Error).message }) };
  }
  const parsed = KongConfigSchema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('; ');
    return { ok: false, error: t('io.validationError', { issues }) };
  }
  const cfg = parsed.data;
  if (!cfg.services || cfg.services.length === 0) {
    return { ok: false, error: t('kong.error.noServices') };
  }

  // サービスを名前（または id）で引けるようにし、ルートとプラグインを寄せる。
  const services: ServiceInfo[] = cfg.services.map((svc, i) => ({
    svc,
    key: svc.name ?? svc.id ?? `service-${i + 1}`,
    label: svc.name ?? svc.id ?? schemeAndHost(svc).host ?? `service-${i + 1}`,
    plugins: [...(svc.plugins ?? [])],
    routes: [...(svc.routes ?? [])],
  }));
  const byKey = new Map<string, ServiceInfo>();
  for (const s of services) {
    if (s.svc.name) byKey.set(s.svc.name, s);
    if (s.svc.id) byKey.set(s.svc.id, s);
  }
  for (const r of cfg.routes ?? []) {
    const s = byKey.get(refName(r.service) ?? '');
    if (s) s.routes.push(r);
  }
  const routeOwner = new Map<string, ServiceInfo>();
  for (const s of services) {
    for (const r of s.routes) {
      if (r.name) routeOwner.set(r.name, s);
      if (r.id) routeOwner.set(r.id, s);
      s.plugins.push(...(r.plugins ?? []));
    }
  }
  const globalPlugins: KongPlugin[] = [];
  for (const p of cfg.plugins ?? []) {
    const target = byKey.get(refName(p.service) ?? '') ?? routeOwner.get(refName(p.route) ?? '');
    if (target) target.plugins.push(p);
    else if (p.service === undefined && p.route === undefined) globalPlugins.push(p);
  }

  const enabled = (ps: KongPlugin[]) => ps.filter((p) => p.enabled !== false);
  const globals = enabled(globalPlugins);
  const pluginsOf = (s: ServiceInfo) => [...globals, ...enabled(s.plugins)];
  const isAi = (p: KongPlugin) => p.name.startsWith('ai-');

  const nodes: DiagramNode[] = [];
  const edges: DiagramEdge[] = [];
  // ID は設定上の名前から決める（サービスを足しても既存要素の ID が変わらず、`diff` で正しく突き合わせられる）。
  const addEdge = (
    source: string,
    target: string,
    auth: AuthType,
    network: NetworkType,
    encryption: EncryptionType,
    extra: Partial<DiagramEdge> = {},
  ) => {
    edges.push({ id: `${source}--${target}`, source, target, auth, network, encryption, ...extra });
  };
  const pluginList = (ps: KongPlugin[]) => [...new Set(ps.map((p) => p.name))].sort().join(', ');

  // サービスを AI 系とそれ以外に分け、それぞれを受けるゲートウェイを置く。
  const aiServices = services.filter((s) => pluginsOf(s).some(isAi));
  const apiServices = services.filter((s) => !aiServices.includes(s));
  const both = aiServices.length > 0 && apiServices.length > 0;

  const COL = { client: 60, gateway: 340, internal: 640, external: 940 };
  const ROW = 150;
  const TOP = 120;

  const client: DiagramNode = { id: 'kong-client', type: 'EXTERNAL_ENTITY', x: COL.client, y: TOP, label: t('kong.node.client') };
  nodes.push(client);

  const gateways: { node: DiagramNode; services: ServiceInfo[] }[] = [];
  if (apiServices.length > 0) {
    gateways.push({
      node: { id: 'kong-gw-api', type: 'GATEWAY', x: COL.gateway, y: 0, label: both ? t('kong.node.gatewayApi') : t('kong.node.gateway') },
      services: apiServices,
    });
  }
  if (aiServices.length > 0) {
    gateways.push({
      node: { id: 'kong-gw-ai', type: 'AI_GATEWAY', x: COL.gateway, y: 0, label: both ? t('kong.node.gatewayAi') : t('kong.node.gateway') },
      services: aiServices,
    });
  }

  let internalRow = 0;
  let externalRow = 0;
  const internalIds: string[] = [];
  const externalIds: string[] = [];

  gateways.forEach((g, gi) => {
    g.node.y = TOP + gi * ROW;
    const gwPlugins = new Set<string>();
    let weakest: AuthType = 'MFA';
    let plain = false;
    const authLines: string[] = [];
    const routed = g.services.filter((s) => s.routes.length > 0);
    const everyRouted = (names: Set<string>) =>
      routed.length > 0 && routed.every((s) => pluginsOf(s).some((p) => names.has(p.name)));

    for (const s of g.services) {
      const ps = pluginsOf(s);
      ps.forEach((p) => gwPlugins.add(p.name));
      const auth: AuthType = ps.some((p) => AUTH_PLUGINS.has(p.name)) ? 'Password' : 'None';
      if (s.routes.length > 0) {
        if (WEAKNESS[auth] < WEAKNESS[weakest]) weakest = auth;
        if (s.routes.some((r) => (r.protocols ?? ['http', 'https']).some((pr) => !TLS_PROTOCOLS.has(pr)))) plain = true;
        authLines.push(`${s.label}: ${auth === 'None' ? t('kong.desc.noAuth') : pluginList(ps.filter((p) => AUTH_PLUGINS.has(p.name)))}`);
      }

      const { scheme, host } = schemeAndHost(s.svc);
      const upstreamEnc: EncryptionType = scheme && TLS_PROTOCOLS.has(scheme) ? 'TLS' : 'Plain';
      const svcDesc = t('kong.desc.service', { name: s.label, host: host ?? '-', plugins: pluginList(ps) || '-' });

      const proxy = ps.find((p) => p.name === 'ai-proxy' || p.name === 'ai-proxy-advanced');
      const targetIds: string[] = [];
      if (proxy) {
        for (const [ti, target] of llmTargets(proxy).entries()) {
          const selfHosted = SELF_HOSTED_PROVIDERS.has(target.provider);
          const id = `kong-llm-${s.key}-${ti}`;
          const node: DiagramNode = {
            id,
            type: 'LLM',
            x: selfHosted ? COL.internal : COL.external,
            y: TOP + (selfHosted ? internalRow++ : externalRow++) * ROW,
            label: target.model ? `${target.provider} / ${target.model}` : target.provider,
            description: svcDesc,
          };
          nodes.push(node);
          (selfHosted ? internalIds : externalIds).push(id);
          targetIds.push(id);
          addEdge(g.node.id, id, 'Password', selfHosted ? 'VPC' : 'Internet', 'TLS', { dataFlow: 'bidirectional' });
        }
      } else {
        const type = ps.some((p) => p.name === 'ai-mcp-proxy')
          ? 'MCP_SERVER'
          : ps.some((p) => p.name === 'ai-a2a-proxy')
            ? 'AGENT'
            : 'BACKEND_API';
        const id = `kong-svc-${s.key}`;
        nodes.push({ id, type, x: COL.internal, y: TOP + internalRow++ * ROW, label: s.label, description: svcDesc });
        internalIds.push(id);
        targetIds.push(id);
        addEdge(g.node.id, id, 'None', 'VPC', upstreamEnc, { dataFlow: 'bidirectional' });
      }

      if (ps.some((p) => p.name === 'ai-rag-injector')) {
        const id = `kong-rag-${s.key}`;
        nodes.push({ id, type: 'DB', x: COL.internal, y: TOP + internalRow++ * ROW, label: t('kong.node.ragDb'), description: svcDesc });
        internalIds.push(id);
        for (const target of targetIds) {
          addEdge(id, target, 'Password', 'VPC', 'TLS', { semantic: 'rag_retrieval', dataFlowName: 'ai-rag-injector' });
        }
      }
    }

    // 攻撃面属性は GATEWAY でだけ入力できる。設定から確認できた項目だけ true にし、
    // 分からない項目（Global IP・管理面の制限・WAF・DDoS）は未入力（insecure baseline）のまま残す。
    if (g.node.type === 'GATEWAY') {
      const surface = {
        ...(everyRouted(AUTH_PLUGINS) ? { hasUserAuthentication: true } : {}),
        ...(everyRouted(new Set(['ip-restriction'])) ? { hasSourceIpRestriction: true } : {}),
        ...(everyRouted(LOG_PLUGINS) ? { hasAccessLog: true } : {}),
      };
      if (Object.keys(surface).length > 0) g.node.attackSurface = surface;
    }

    g.node.description = t('kong.desc.gateway', {
      plugins: [...gwPlugins].sort().join(', ') || '-',
      auth: authLines.join(' / ') || '-',
    });
    nodes.push(g.node);
    if (authLines.length > 0) {
      addEdge(client.id, g.node.id, weakest, 'Internet', plain ? 'Plain' : 'TLS', { dataFlow: 'bidirectional' });
    }
  });

  // ゲートウェイの下に、管理プレーン・シークレット管理・ガードレールを並べる。
  let supportRow = gateways.length;
  const supportIds: string[] = [];
  const addSupport = (node: Omit<DiagramNode, 'x' | 'y'>, link: (gwId: string) => void) => {
    nodes.push({ ...node, x: COL.gateway, y: TOP + supportRow++ * ROW });
    supportIds.push(node.id);
    gateways.forEach((g) => link(g.node.id));
  };

  addSupport({ id: 'kong-cp', type: 'API_CONTROL_PLANE', label: t('kong.node.controlPlane') }, (gw) =>
    addEdge('kong-cp', gw, 'Password', 'VPC', 'TLS'),
  );

  const vaultPrefixes = (cfg.vaults ?? []).map((v) => v.prefix ?? v.name).filter((v): v is string => !!v);
  if (vaultPrefixes.length > 0 || /\{vault:\/\//.test(text)) {
    addSupport(
      { id: 'kong-vault', type: 'SECRETS_VAULT', label: t('kong.node.vault', { prefixes: vaultPrefixes.join(', ') || 'vault://' }) },
      (gw) => addEdge(gw, 'kong-vault', 'Password', 'VPC', 'TLS', { dataFlow: 'bidirectional' }),
    );
  }

  const guards = new Set(
    services.flatMap((s) => pluginsOf(s)).filter((p) => GUARD_PLUGINS.has(p.name)).map((p) => p.name),
  );
  if (guards.size > 0) {
    const aiGw = gateways.find((g) => g.node.type === 'AI_GATEWAY');
    nodes.push({ id: 'kong-guard', type: 'GUARDRAIL', x: COL.gateway, y: TOP + supportRow++ * ROW, label: [...guards].sort().join(', ') });
    supportIds.push('kong-guard');
    if (aiGw) addEdge(aiGw.node.id, 'kong-guard', 'None', 'VPC', 'TLS', { dataFlow: 'bidirectional' });
  }

  // 信頼境界：クライアント＝Internet、ゲートウェイと自組織内のサービス＝Internal、外部 LLM＝Partner。
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
    // 上側は境界ラベルと脅威バッジが重ならないよう広めに空ける。
    const PAD = 40;
    const x = Math.min(...members.map((n) => n.x)) - PAD;
    const y = Math.min(...members.map((n) => n.y)) - PAD - 30;
    const right = Math.max(...members.map((n) => n.x + 128)) + PAD;
    const bottom = Math.max(...members.map((n) => n.y + 96)) + PAD;
    boundaries.push({ id, type, x, y, width: right - x, height: bottom - y, trustLevel, ...extra });
  };
  box('kong-b-internet', [client.id], 'RECT', 'Internet');
  // 自組織内はマクロセグメンテーション（Security Zone＝Internal）。RECT は「外部境界」と表示されるため使わない。
  box('kong-b-internal', [...gateways.map((g) => g.node.id), ...supportIds, ...internalIds], 'ROUNDED', 'Internal', {
    macroTrust: 'Security Zone',
  });
  box('kong-b-partner', externalIds, 'RECT_DASHED', 'Partner');

  const routeCount = services.reduce((n, s) => n + s.routes.length, 0);
  const pluginCount =
    (cfg.plugins?.length ?? 0) +
    (cfg.services ?? []).reduce(
      (n, s) => n + (s.plugins?.length ?? 0) + (s.routes ?? []).reduce((m, r) => m + (r.plugins?.length ?? 0), 0),
      0,
    ) +
    (cfg.routes ?? []).reduce((n, r) => n + (r.plugins?.length ?? 0), 0);

  return {
    ok: true,
    name: t('kong.templateName'),
    layer: { nodes, edges, boundaries, annotations: [] },
    summary: {
      services: services.length,
      routes: routeCount,
      plugins: pluginCount,
      consumers: cfg.consumers?.length ?? 0,
    },
  };
}
