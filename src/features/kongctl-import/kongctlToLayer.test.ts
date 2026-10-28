import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { kongctlToLayer, isInternalHost, type KongctlImportSummary } from './kongctlToLayer';
import { PersistedLayerDataSchema } from '../persistence/schema';
import type { LayerData } from '../../core/model/types';
import { layerToProject } from '../kong-import/toProject';
import { analyzeProject } from '../../cli/analyze';

const SECRET = 'sk-THIS-MUST-NOT-LEAK';

function ok(text: string): { layer: LayerData; summary: KongctlImportSummary } {
  const r = kongctlToLayer(text);
  if (!r.ok) throw new Error(r.error);
  return r;
}

const byType = (layer: LayerData, type: string) => layer.nodes.filter((n) => n.type === type);
const edge = (layer: LayerData, source: string, target: string) =>
  layer.edges.find((e) => e.source === source && e.target === target);
const node = (layer: LayerData, label: string) => layer.nodes.find((n) => n.label === label)!;

// ── 入れ子形式 ──
const NESTED = `
ai_gateways:
  - name: gw
    deployment_type: hybrid
    proxy_urls:
      - { host: ai.example.com, port: 443, protocol: https }
    model_providers:
      - name: p-openai
        type: openai
        config:
          auth:
            header_value: !secret
              source: !env OPENAI_KEY
      - { name: p-ollama, type: ollama }
      - { name: p-vllm, type: vllm }
    auth_strategies:
      - name: keys
        type: key-auth
      - name: sso
        type: openid-connect
        config:
          client_id: !secret { source: !env CID }
          client_secret: ${SECRET}
    models:
      - name: chat
        type: model
        targets:
          - { name: gpt-4o, provider: p-openai }
          - { name: llama3, provider: p-ollama }
          - { name: mixtral, provider: p-vllm }
        access:
          auth_strategies: [keys, sso]
    consumers:
      - username: alice
        credentials:
          - key: ${SECRET}
`;

// ── トップレベル形式（同じ内容）──
const TOP = `
ai_gateways:
  - name: gw
    deployment_type: hybrid
    proxy_urls:
      - { host: ai.example.com, port: 443, protocol: https }
ai_gateway_model_providers:
  - { name: p-openai, type: openai, ai_gateway: gw }
  - { name: p-ollama, type: ollama, ai_gateway: !lookup name:gw }
  - { name: p-vllm, type: vllm, ai_gateway: !lookup { name: gw } }
ai_gateway_auth_strategies:
  - { name: keys, type: key-auth, ai_gateway: gw }
  - { name: sso, type: openid-connect, ai_gateway: gw }
ai_gateway_models:
  - name: chat
    type: model
    ai_gateway: gw
    targets:
      - { name: gpt-4o, provider: p-openai }
      - { name: llama3, provider: p-ollama }
      - { name: mixtral, provider: p-vllm }
    access:
      auth_strategies: [keys, sso]
`;

describe('kongctlToLayer', () => {
  afterEach(() => vi.restoreAllMocks());

  it('入れ子形式とトップレベル形式の両方を読み、同じ図になる', () => {
    const nested = ok(NESTED).layer;
    const top = ok(TOP).layer;
    for (const layer of [nested, top]) {
      expect(byType(layer, 'AI_GATEWAY')).toHaveLength(1);
      expect(byType(layer, 'LLM')).toHaveLength(3);
    }
    expect(nested.nodes.map((n) => n.id).sort()).toEqual(top.nodes.map((n) => n.id).sort());
    expect(nested.edges.map((e) => e.id).sort()).toEqual(top.edges.map((e) => e.id).sort());
  });

  it('targets が複数あれば LLM が全部出る。ollama・vllm は組織内、openai は Internet', () => {
    const { layer } = ok(NESTED);
    expect(byType(layer, 'LLM').map((n) => n.label).sort()).toEqual([
      'ollama / llama3',
      'openai / gpt-4o',
      'vllm / mixtral',
    ]);
    const external = layer.boundaries.find((b) => b.id === 'kongctl-b-external')!;
    const internal = layer.boundaries.find((b) => b.id === 'kongctl-b-internal')!;
    expect(external).toMatchObject({ type: 'RECT', trustLevel: 'Internet' });
    expect(internal).toMatchObject({ type: 'ROUNDED', trustLevel: 'Internal', macroTrust: 'Security Zone' });
    const within = (b: typeof external, label: string) => {
      const n = node(layer, label);
      return n.x >= b.x && n.x <= b.x + b.width;
    };
    expect(within(external, 'openai / gpt-4o')).toBe(true);
    expect(within(external, 'ollama / llama3')).toBe(false);
    expect(within(internal, 'ollama / llama3')).toBe(true);
    expect(within(internal, 'vllm / mixtral')).toBe(true);
    const gw = 'kongctl-gw-gw';
    expect(edge(layer, gw, node(layer, 'openai / gpt-4o').id)).toMatchObject({ auth: 'ApiKey', network: 'Internet', encryption: 'TLS' });
    expect(edge(layer, gw, node(layer, 'ollama / llama3').id)).toMatchObject({ auth: 'Password', network: 'VPC', encryption: 'TLS' });
  });

  it('ゲートウェイが複数あれば AI_GATEWAY を分け、トップレベルの子は ai_gateway で振り分ける（解決できなければ最初）', () => {
    const { layer, summary } = ok(`
ai_gateways:
  - { name: a }
  - { name: b }
ai_gateway_models:
  - { name: m1, ai_gateway: b, targets: [{ name: x, provider: openai }] }
  - { name: m2, targets: [{ name: y, provider: openai }] }
  - { name: m3, ai_gateway: { id: 00000000-0000-0000-0000-000000000000 }, targets: [{ name: z, provider: openai }] }
`);
    expect(summary.gateways).toBe(2);
    expect(edge(layer, 'kongctl-gw-b', 'kongctl-llm-b-m1-0')).toBeDefined();
    expect(edge(layer, 'kongctl-gw-a', 'kongctl-llm-a-m2-0')).toBeDefined();
    expect(edge(layer, 'kongctl-gw-a', 'kongctl-llm-a-m3-0')).toBeDefined();
  });

  it('ai_gateways が無く子だけある場合は既定のゲートウェイを 1 つ作る', () => {
    const { layer } = ok(`
ai_gateway_models:
  - { name: m, targets: [{ name: x, provider: openai }] }
`);
    expect(byType(layer, 'AI_GATEWAY')).toHaveLength(1);
  });

  it('auth strategy が無ければ None、key-auth＋openid-connect の model は ApiKey（弱い方）', () => {
    const none = ok(`
ai_gateways:
  - name: gw
    models:
      - { name: m, targets: [{ name: x, provider: openai }] }
`).layer;
    expect(edge(none, 'kongctl-client', 'kongctl-gw-gw')?.auth).toBe('None');
    expect(edge(ok(NESTED).layer, 'kongctl-client', 'kongctl-gw-gw')?.auth).toBe('ApiKey');
    const oidc = ok(NESTED.replace('[keys, sso]', '[sso]')).layer;
    expect(edge(oidc, 'kongctl-client', 'kongctl-gw-gw')?.auth).toBe('Token');
  });

  it('proxy_urls が https のみなら TLS、無ければ Plain（仮定と説明に書く）', () => {
    expect(edge(ok(NESTED).layer, 'kongctl-client', 'kongctl-gw-gw')?.encryption).toBe('TLS');
    const noProxy = ok(NESTED.replace(/ {4}proxy_urls:\n {6}- \{[^\n]*\n/, '')).layer;
    expect(edge(noProxy, 'kongctl-client', 'kongctl-gw-gw')?.encryption).toBe('Plain');
    expect(node(noProxy, 'gw').description).toContain('平文');
    const mixed = ok(NESTED.replace('protocol: https }', 'protocol: http }')).layer;
    expect(edge(mixed, 'kongctl-client', 'kongctl-gw-gw')?.encryption).toBe('Plain');
  });

  it('公開エンティティが無ければクライアントからの線を引かない', () => {
    const { layer } = ok(`
ai_gateways:
  - name: gw
    policies:
      - { name: g, type: ai-prompt-guard, global: true }
`);
    expect(layer.edges.some((e) => e.source === 'kongctl-client')).toBe(false);
  });

  it('MCP の type ごとに配置する', () => {
    const { layer } = ok(`
ai_gateways:
  - name: gw
    proxy_urls: [{ host: ai.example.com, protocol: https }]
    mcp_servers:
      - { name: conv, type: conversion-listener, config: { url: "https://rest.internal/api" } }
      - { name: pass, type: passthrough-listener, config: { url: "https://mcp.vendor.example.net/mcp", upstream: { auth: { type: bearer } } } }
      - { name: only, type: conversion-only, config: { url: "http://billing.internal" } }
      - { name: up, type: upstream-server, config: { url: "http://10.0.0.5/mcp" } }
      - name: agg
        type: listener
        sources: [only, up]
      - { name: off, type: passthrough-listener, enabled: false, config: { url: "https://off.example.net" } }
`);
    // conversion-listener：Kong 側が MCP_SERVER、背後が BACKEND_API
    const conv = layer.nodes.find((n) => n.id === 'kongctl-mcp-gw-conv')!;
    expect(conv.type).toBe('MCP_SERVER');
    expect(conv.label).toContain('Kong');
    expect(layer.nodes.find((n) => n.id === 'kongctl-mcp-gw-conv-backend')?.type).toBe('BACKEND_API');
    expect(edge(layer, conv.id, 'kongctl-mcp-gw-conv-backend')).toMatchObject({ encryption: 'TLS', network: 'VPC' });
    // passthrough：背後が MCP_SERVER（外部）、upstream.auth があれば ApiKey
    expect(layer.nodes.find((n) => n.id === 'kongctl-mcp-gw-pass')?.type).toBe('MCP_SERVER');
    expect(edge(layer, 'kongctl-gw-gw', 'kongctl-mcp-gw-pass')).toMatchObject({ auth: 'ApiKey', network: 'Internet', encryption: 'TLS' });
    // conversion-only：BACKEND_API、listener（Kong 側 MCP_SERVER）から線。http は Plain
    expect(layer.nodes.find((n) => n.id === 'kongctl-mcp-gw-only')?.type).toBe('BACKEND_API');
    expect(edge(layer, 'kongctl-mcp-gw-agg', 'kongctl-mcp-gw-only')).toMatchObject({ auth: 'None', network: 'VPC', encryption: 'Plain' });
    expect(edge(layer, 'kongctl-mcp-gw-agg', 'kongctl-mcp-gw-up')).toBeDefined();
    expect(edge(layer, 'kongctl-gw-gw', 'kongctl-mcp-gw-only')).toBeUndefined();
    // enabled: false は無視
    expect(layer.nodes.some((n) => n.id === 'kongctl-mcp-gw-off')).toBe(false);
  });

  it('エージェント・ガード policy・transformer の LLM・vectordb・Vault を図の要素にし、無効な policy は無視する', () => {
    const { layer, summary } = ok(`
ai_gateways:
  - name: gw
    agents:
      - { name: bot, type: a2a, config: { url: "http://agent.corp:9000" } }
    vaults:
      - { name: env, prefix: my-env }
    models:
      - name: m
        targets: [{ name: x, provider: openai }]
        config: { balancer: { vectordb: { strategy: pgvector } } }
        policies: [attached-guard]
    policies:
      - { name: attached-guard, type: ai-prompt-guard }
      - { name: orphan-guard, type: ai-sanitizer }
      - { name: off-guard, type: ai-lakera-guard, enabled: false, global: true }
      - name: xf
        type: ai-request-transformer
        global: true
        config: { llm: { model: { provider: anthropic, name: claude } } }
      - { name: cache, type: ai-semantic-cache, config: { vectordb: { strategy: redis } } }
    consumers: [{ username: a }, { username: b }]
`);
    expect(byType(layer, 'AGENT')).toHaveLength(1);
    expect(byType(layer, 'GUARDRAIL').map((n) => n.label)).toEqual(['ai-prompt-guard']);
    expect(layer.nodes.some((n) => n.type === 'LLM' && n.label === 'anthropic / claude')).toBe(true);
    expect(byType(layer, 'DB').map((n) => n.label).sort()).toEqual(['ベクターDB（pgvector）', 'ベクターDB（redis）']);
    expect(byType(layer, 'SECRETS_VAULT')).toHaveLength(1);
    expect(byType(layer, 'API_CONTROL_PLANE')).toHaveLength(1);
    expect(edge(layer, 'kongctl-cp', 'kongctl-gw-gw')).toMatchObject({ auth: 'Certificate', network: 'Internet', encryption: 'TLS' });
    expect(summary).toEqual({ gateways: 1, models: 1, mcpServers: 0, agents: 1, policies: 5, consumers: 2 });
  });

  it('秘密（!secret・client_secret・upstream の鍵・URL の userinfo とクエリ）を出力に持ち込まない', () => {
    const { layer } = ok(`
ai_gateways:
  - name: gw
    auth_strategies:
      - name: sso
        type: openid-connect
        config:
          client_id: ${SECRET}-id
          client_secret: ${SECRET}
    model_providers:
      - name: p
        type: openai
        config: { auth: { header_value: !secret { source: !env KEY }, token: ${SECRET} } }
    models:
      - { name: m, targets: [{ name: x, provider: p }], access: { auth_strategies: [sso] } }
    mcp_servers:
      - name: pass
        type: passthrough-listener
        config:
          url: https://user:pass@mcp.example.net/mcp?token=${SECRET}
          upstream: { auth: { type: bearer, token: ${SECRET} } }
    consumers:
      - username: alice
        credentials: [{ key: ${SECRET} }]
`);
    const dump = JSON.stringify(layer);
    expect(dump).not.toContain(SECRET);
    expect(dump).not.toContain('user:pass');
    expect(dump).not.toContain('(secret)');
    expect(dump).toContain('mcp.example.net');
  });

  it('独自タグ（!secret・!env・!lookup・!ref）で console 警告が出ない', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const emit = vi.spyOn(process, 'emitWarning').mockImplementation(() => {});
    ok(`
ai_gateways:
  - name: gw
    model_providers:
      - name: p
        type: openai
        config: { auth: { header_value: !secret { source: !env KEY }, x: !env Y, y: !secret Z } }
    models:
      - { name: m, targets: [{ name: x, provider: !lookup name:p }], policies: [!ref pol#id, !lookup { name: pol }, !lookup { id: abc }] }
`);
    expect(warn).not.toHaveBeenCalled();
    expect(emit).not.toHaveBeenCalled();
  });

  it('!lookup name:x は参照名 x として解決し、{id} は解決不能として扱う', () => {
    const { layer } = ok(`
ai_gateways:
  - name: gw
    model_providers: [{ name: p, type: ollama }]
    models:
      - { name: m1, targets: [{ name: x, provider: !lookup name:p }] }
      - { name: m2, targets: [{ name: y, provider: !lookup { id: 11111111 } }] }
`);
    expect(layer.nodes.some((n) => n.label === 'ollama / x')).toBe(true);
    // 解決できないので provider は不明（外部扱い）
    expect(layer.nodes.some((n) => n.label === 'llm / y')).toBe(true);
  });

  it('ホストが組織内かを判定する', () => {
    for (const h of ['localhost', 'host.docker.internal', '10.1.2.3', '172.16.0.1', '172.31.9.9', '192.168.0.5', '127.0.0.1', 'db', 'a.internal', 'b.local', 'c.svc', 'd.cluster.local', 'e.lan', 'f.corp']) {
      expect(isInternalHost(h), h).toBe(true);
    }
    for (const h of ['api.openai.com', '172.32.0.1', '8.8.8.8', 'example.net']) {
      expect(isInternalHost(h), h).toBe(false);
    }
  });

  it('永続化スキーマに適合する', () => {
    for (const text of [NESTED, TOP]) {
      expect(PersistedLayerDataSchema.safeParse(ok(text).layer).success).toBe(true);
    }
  });

  it('要素の ID は名前から決まり、エンティティを足しても既存の ID は変わらない', () => {
    const before = ok(NESTED).layer;
    const after = ok(
      NESTED.replace(
        '    models:\n',
        '    mcp_servers:\n      - { name: added, type: passthrough-listener, config: { url: "https://added.example.net" } }\n    models:\n      - { name: first, targets: [{ name: z, provider: p-openai }] }\n',
      ),
    ).layer;
    const ids = (l: LayerData) => [...l.nodes.map((n) => n.id), ...l.edges.map((e) => e.id)];
    expect(ids(after)).toEqual(expect.arrayContaining(ids(before)));
    expect(new Set(ids(before)).size).toBe(ids(before).length);
  });

  it('control_planes だけのファイル（decK 方式）は import-kong を案内するエラーを返す', () => {
    const r = kongctlToLayer('control_planes:\n  - name: cp\n    _deck:\n      files: [kong.yaml]\n');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('import-kong');
  });

  it('AI Gateway のエンティティが無い・構文エラー・型違いはエラーを返す', () => {
    expect(kongctlToLayer('foo: bar\n').ok).toBe(false);
    expect(kongctlToLayer('ai_gateways: [').ok).toBe(false);
    expect(kongctlToLayer('ai_gateways: nope\n').ok).toBe(false);
  });

  it('同梱サンプル kong-ai-gateway-v2.yaml を取り込める（秘密はダミーの環境変数指定のみ）', () => {
    const text = readFileSync('guide/templates/kong-ai-gateway-v2.yaml', 'utf-8');
    const { layer, summary } = ok(text);
    expect(summary).toMatchObject({ gateways: 1, models: 1, mcpServers: 2, agents: 1, policies: 2, consumers: 1 });
    expect(byType(layer, 'LLM')).toHaveLength(2);
    expect(PersistedLayerDataSchema.safeParse(layer).success).toBe(true);
  });
});

describe('layerToProject（CLI 出力）', () => {
  it('analyze にそのまま渡せ、認証なしの公開経路などの脅威が出る', () => {
    const noAuth = `
ai_gateways:
  - name: gw
    models:
      - { name: m, targets: [{ name: x, provider: openai }] }
    mcp_servers:
      - { name: pass, type: passthrough-listener, config: { url: "http://mcp.example.net/mcp" } }
`;
    const project = layerToProject(ok(noAuth).layer);
    const [result] = analyzeProject(project);
    expect(result.layer).toBe('L1');
    expect(result.threats.length).toBeGreaterThan(0);
    const sample = layerToProject(ok(readFileSync('guide/templates/kong-ai-gateway-v2.yaml', 'utf-8')).layer);
    expect(analyzeProject(sample)[0].threats.length).toBeGreaterThan(0);
  });
});
