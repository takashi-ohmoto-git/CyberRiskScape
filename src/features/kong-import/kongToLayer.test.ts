import { describe, expect, it } from 'vitest';
import { kongToLayer } from './kongToLayer';
import { PersistedLayerDataSchema } from '../persistence/schema';
import type { LayerData } from '../../core/model/types';
import { layerToProject } from './toProject';
import { analyzeProject } from '../../cli/analyze';

const SECRET = 'sk-THIS-MUST-NOT-LEAK';

const KONG_YAML = `
_format_version: "3.0"
services:
  - name: orders
    url: https://user:pass@orders.internal:8443/v1?token=${SECRET}
    routes:
      - name: orders-route
        paths: ["/orders"]
        protocols: ["https"]
    plugins:
      - name: key-auth
  - name: chat
    url: https://api.openai.com
    routes:
      - name: chat-route
        paths: ["/chat"]
        protocols: ["http", "https"]
    plugins:
      - name: ai-proxy
        config:
          route_type: llm/v1/chat
          auth:
            header_name: Authorization
            header_value: Bearer ${SECRET}
          model:
            provider: openai
            name: gpt-4o
      - name: ai-prompt-guard
      - name: ai-rag-injector
  - name: multi
    url: http://placeholder
    plugins:
      - name: ai-proxy-advanced
        config:
          targets:
            - model: { provider: ollama, name: llama3 }
            - model: { provider: anthropic, name: claude }
  - name: tools
    url: http://mcp.internal
    plugins:
      - name: ai-mcp-proxy
routes:
  - name: multi-route
    service: { name: multi }
    protocols: ["https"]
plugins:
  - name: rate-limiting
  - name: openid-connect
    service: multi
consumers:
  - username: alice
    keyauth_credentials:
      - key: ${SECRET}
vaults:
  - name: env
    prefix: my-env
`;

function ok(text: string): { layer: LayerData; summary: { services: number; routes: number; plugins: number; consumers: number } } {
  const r = kongToLayer(text);
  if (!r.ok) throw new Error(r.error);
  return r;
}

const byType = (layer: LayerData, type: string) => layer.nodes.filter((n) => n.type === type);
const edge = (layer: LayerData, source: string, target: string) =>
  layer.edges.find((e) => e.source === source && e.target === target);

describe('kongToLayer', () => {
  it('秘密情報（認証ヘッダ・資格情報・URL の userinfo とクエリ）を図に持ち込まない', () => {
    const { layer } = ok(KONG_YAML);
    const dump = JSON.stringify(layer);
    expect(dump).not.toContain(SECRET);
    expect(dump).not.toContain('user:pass');
    expect(dump).toContain('orders.internal');
  });

  it('永続化スキーマに適合する（テンプレート取り込み・保存にそのまま使える）', () => {
    const { layer } = ok(KONG_YAML);
    expect(PersistedLayerDataSchema.safeParse(layer).success).toBe(true);
  });

  it('AI 系と通常のサービスでゲートウェイを分け、管理プレーンを置く', () => {
    const { layer } = ok(KONG_YAML);
    expect(byType(layer, 'GATEWAY')).toHaveLength(1);
    expect(byType(layer, 'AI_GATEWAY')).toHaveLength(1);
    expect(byType(layer, 'API_CONTROL_PLANE')).toHaveLength(1);
    expect(edge(layer, 'kong-cp', 'kong-gw-api')).toBeDefined();
    expect(edge(layer, 'kong-cp', 'kong-gw-ai')).toBeDefined();
  });

  it('サービスを型に対応させる（ai-proxy→LLM、ai-proxy-advanced→ターゲットごとの LLM、ai-mcp-proxy→MCP_SERVER、他→BACKEND_API）', () => {
    const { layer } = ok(KONG_YAML);
    expect(byType(layer, 'LLM').map((n) => n.label).sort()).toEqual([
      'anthropic / claude',
      'ollama / llama3',
      'openai / gpt-4o',
    ]);
    expect(byType(layer, 'MCP_SERVER').map((n) => n.label)).toEqual(['tools']);
    expect(byType(layer, 'BACKEND_API').map((n) => n.label)).toEqual(['orders']);
    expect(byType(layer, 'DB')).toHaveLength(1);
    expect(layer.edges.some((e) => e.semantic === 'rag_retrieval')).toBe(true);
  });

  it('クライアント→ゲートウェイは最も弱い認証と、http を許すルートがあれば平文にする', () => {
    const { layer } = ok(KONG_YAML);
    // orders は key-auth → Password
    expect(edge(layer, 'kong-client', 'kong-gw-api')).toMatchObject({ auth: 'Password', encryption: 'TLS', network: 'Internet' });
    // chat は認証なし・http 許可、multi は openid-connect → 最弱は None・平文
    expect(edge(layer, 'kong-client', 'kong-gw-ai')).toMatchObject({ auth: 'None', encryption: 'Plain' });
  });

  it('外部プロバイダの LLM は Partner 境界、自組織内（ollama）は Internal 境界に置く', () => {
    const { layer } = ok(KONG_YAML);
    const partner = layer.boundaries.find((b) => b.trustLevel === 'Partner');
    const inside = (label: string) => {
      const n = layer.nodes.find((x) => x.label === label)!;
      return !!partner && n.x >= partner.x && n.x <= partner.x + partner.width;
    };
    expect(inside('openai / gpt-4o')).toBe(true);
    expect(inside('ollama / llama3')).toBe(false);
  });

  it('ガードレール・Vault を置き、件数を集計する', () => {
    const { layer, summary } = ok(KONG_YAML);
    expect(byType(layer, 'GUARDRAIL').map((n) => n.label)).toEqual(['ai-prompt-guard']);
    expect(byType(layer, 'SECRETS_VAULT')).toHaveLength(1);
    expect(summary).toEqual({ services: 4, routes: 3, plugins: 8, consumers: 1 });
  });

  it('API ゲートウェイの攻撃面属性は設定で確認できた項目だけ埋める', () => {
    const { layer } = ok(KONG_YAML);
    expect(layer.nodes.find((n) => n.id === 'kong-gw-api')?.attackSurface).toEqual({ hasUserAuthentication: true });
    const withLog = ok(`
services:
  - name: s
    url: https://s.internal
    routes: [{ name: r }]
plugins:
  - name: http-log
  - name: ip-restriction
`).layer;
    expect(withLog.nodes.find((n) => n.id === 'kong-gw-api')?.attackSurface).toEqual({
      hasSourceIpRestriction: true,
      hasAccessLog: true,
    });
  });

  it('要素の ID はサービス名から決まり、サービスを足しても既存の ID は変わらない', () => {
    const before = ok(KONG_YAML).layer;
    const after = ok(
      KONG_YAML.replace('services:\n', 'services:\n  - name: added\n    url: https://added.internal\n'),
    ).layer;
    const ids = (l: LayerData) => [...l.nodes.map((n) => n.id), ...l.edges.map((e) => e.id)];
    expect(ids(after)).toEqual(expect.arrayContaining(ids(before)));
    expect(new Set(ids(before)).size).toBe(ids(before).length);
  });

  it('無効化したプラグインは無視する', () => {
    const { layer } = ok(`
services:
  - name: s
    url: https://s.internal
    routes: [{ name: r, protocols: [https] }]
    plugins:
      - name: key-auth
        enabled: false
`);
    expect(edge(layer, 'kong-client', 'kong-gw-api')).toMatchObject({ auth: 'None' });
  });

  it('services が無い・構文エラーはエラーを返す', () => {
    expect(kongToLayer('_format_version: "3.0"\n').ok).toBe(false);
    expect(kongToLayer('services: [').ok).toBe(false);
  });
});

describe('layerToProject（CLI 出力）', () => {
  it('analyze にそのまま渡せ、生成した図から API 基盤・AI の脅威が出る', () => {
    const project = layerToProject(ok(KONG_YAML).layer);
    const [result] = analyzeProject(project);
    expect(result.layer).toBe('L1');
    const ids = new Set(result.threats.map((t) => t.ruleId));
    expect(ids.has('api-backend-object-level-authorization-001')).toBe(true);
    expect(ids.has('api-control-plane-config-tampering-001')).toBe(true);
    expect(ids.has('zt-guardrail-probabilistic-bypass-001')).toBe(true);
  });
});
