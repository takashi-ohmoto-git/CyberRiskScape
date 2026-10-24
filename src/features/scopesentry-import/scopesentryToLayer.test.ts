import { afterEach, describe, expect, it } from 'vitest';
import { scopesentryToLayer, scopesentryRecordsToLayer } from './scopesentryToLayer';
import { PersistedLayerDataSchema } from '../persistence/schema';
import { layerToProject } from '../kong-import/toProject';
import { analyzeProject } from '../../cli/analyze';
import { setLocale } from '../../i18n';
import type { LayerData } from '../../core/model/types';

// 書き出し形式（MongoDB の項目名・port は文字列）。本文・リクエスト等の秘密はわざと混ぜてある。
const ASSET_WEB = {
  host: 'www.example.com',
  ip: '203.0.113.10',
  port: '443',
  service: 'https',
  type: 'http',
  url: 'https://user:pw@www.example.com/login?token=SECRET-QUERY',
  title: 'SECRET-TITLE',
  statuscode: 200,
  technologies: ['Nginx:1.18.0', 'jQuery'],
  webServer: 'nginx',
  cdnname: 'ExampleCDN',
  tls: true,
  transport: 'tcp',
  rootDomain: 'example.com',
  tags: ['prod'],
  time: '2026-10-01 10:00:00',
  lastScanTime: '2026-10-20 10:00:00',
  body: '<html>SECRET-BODY</html>',
  rawheaders: 'Set-Cookie: sid=SECRET-COOKIE',
  banner: 'Authorization: Bearer xyz',
  metadata: 'SECRET-METADATA',
  screenshot: 'SECRET-SHOT',
  request: 'GET / HTTP/1.1\r\nAuthorization: Bearer xyz',
  response: 'HTTP/1.1 200\r\nSet-Cookie: a=b',
  jarm: 'SECRET-JARM',
};
const ASSET_SSH = { host: '203.0.113.11', ip: '203.0.113.11', port: '22', service: 'ssh', type: 'other', transport: 'tcp' };
const ASSET_PLAIN = { host: 'old.example.com', ip: '203.0.113.12', port: '8080', service: 'http', type: 'http', url: 'http://old.example.com:8080/' };
const VULN = {
  url: 'https://www.example.com/login?x=SECRET-Q',
  vulnid: 'CVE-2024-0001',
  vulname: 'Example RCE',
  level: 'critical',
  matched: 'https://www.example.com/SECRET-MATCHED',
  request: 'POST / Authorization: Bearer xyz',
  response: 'Set-Cookie: SECRET',
};
const VULN_UNMATCHED = { url: 'http://other.example.org/', vulnid: 'CVE-2024-9999', level: 'low' };
const TAKEOVER = { input: 'blog.example.com', value: 'ExampleHosting', cname: 'blog.example-hosting.test', rootDomain: 'example.com' };

const lines = (...recs: unknown[]) => recs.map((r) => JSON.stringify(r)).join('\n');
const ALL = lines(ASSET_WEB, ASSET_SSH, ASSET_PLAIN, VULN, VULN_UNMATCHED, TAKEOVER);

function ok(text: string) {
  const r = scopesentryToLayer(text);
  if (!r.ok) throw new Error(r.error);
  return r;
}
const node = (l: LayerData, id: string) => l.nodes.find((n) => n.id === id)!;

describe('scopesentryToLayer', () => {
  afterEach(() => setLocale('ja'));

  it('書き出し形式の asset をサービスごとのノードにする（port は文字列でも読む）', () => {
    const { layer } = ok(ALL);
    const web = node(layer, 'scopesentry-203_0_113_10-443-tcp');
    expect(web).toMatchObject({ type: 'FRONT_END_SERVER', label: 'www.example.com:443 nginx', attackSurface: { hasGlobalIp: true } });
    expect(web.description).toContain('Nginx:1.18.0, jQuery');
    expect(web.description).toContain('CDN: ExampleCDN');
    expect(web.description).toContain('観測日: 2026-10-20');
    expect(node(layer, 'scopesentry-203_0_113_11-22-tcp').type).toBe('GATEWAY');
    expect(node(layer, 'scopesentry-203_0_113_12-8080-tcp').type).toBe('FRONT_END_SERVER');
    const edges = Object.fromEntries(layer.edges.map((e) => [e.id, e]));
    expect(edges['scopesentry-e-203_0_113_10-443-tcp']).toMatchObject({ source: 'scopesentry-actor', encryption: 'TLS', network: 'Internet' });
    expect(edges['scopesentry-e-203_0_113_12-8080-tcp'].encryption).toBe('Plain');
  });

  it('API/MCP の別名（domain・products・status・vulnerability・host/type）も読み、{ list } 形式を受け付ける', () => {
    const api = {
      list: [
        { domain: 'api.example.com', ip: '203.0.113.20', port: '443', products: ['Ollama:0.1'], url: 'https://api.example.com/', status: 200, body: 'SECRET' },
        { url: 'https://api.example.com/', vulnerability: 'Example Info Leak', level: 'medium' },
        { host: 'shop.example.com', value: 'ExampleHosting', type: 'shop.example-hosting.test' },
      ],
    };
    const { layer, summary } = ok(JSON.stringify(api));
    const n = node(layer, 'scopesentry-203_0_113_20-443-tcp');
    expect(n.type).toBe('LLM');
    expect(n.label).toBe('api.example.com:443 Ollama');
    expect(n.description).toContain('Example Info Leak (medium)');
    expect(node(layer, 'scopesentry-dns-example_com').description).toContain('shop.example.com → shop.example-hosting.test / ExampleHosting');
    expect(summary).toMatchObject({ services: 1, vulns: 1, unmatchedVulns: 0, takeovers: 1 });
  });

  it('JSON Lines・JSON 配列・{ list } は同じ図になる。レコード配列からも同じ', () => {
    const recs = [ASSET_WEB, ASSET_SSH, VULN, TAKEOVER];
    const expected = ok(lines(...recs)).layer;
    expect(ok(JSON.stringify(recs)).layer).toEqual(expected);
    expect(ok(JSON.stringify({ list: recs, total: 4 })).layer).toEqual(expected);
    const direct = scopesentryRecordsToLayer(recs);
    expect(direct.ok && direct.layer).toEqual(expected);
  });

  it('脆弱性は URL のホスト（またはIP）＋ポートが一致するノードに付け、既定ポートは scheme から補う。紐付かないものは数える', () => {
    const { layer, summary } = ok(ALL);
    const d = node(layer, 'scopesentry-203_0_113_10-443-tcp').description!;
    expect(d).toContain('ScopeSentry が報告した脆弱性（未検証）: CVE-2024-0001 (critical)');
    expect(node(layer, 'scopesentry-203_0_113_12-8080-tcp').description).not.toContain('CVE-2024');
    expect(JSON.stringify(layer)).not.toContain('CVE-2024-9999');
    expect(summary).toMatchObject({ vulns: 1, unmatchedVulns: 1 });
    // IP 指定の URL でも結びつく
    const byIp = ok(lines(ASSET_SSH, { url: 'http://203.0.113.11:22/', vulnid: 'X-1' }));
    expect(node(byIp.layer, 'scopesentry-203_0_113_11-22-tcp').description).toContain('X-1');
  });

  it('脆弱性は 10 件までで、超過は「他 N 件」にする', () => {
    const vs = Array.from({ length: 12 }, (_, i) => ({ url: 'https://www.example.com/', vulnid: `V-${String(i).padStart(2, '0')}` }));
    const { layer } = ok(lines(ASSET_WEB, ...vs));
    const d = node(layer, 'scopesentry-203_0_113_10-443-tcp').description!;
    expect(d).toContain('V-09 他 2 件');
    expect(d).not.toContain('V-10');
  });

  it('サブドメイン乗っ取りは根ドメインごとに DNS_ZONE を 1 つ作り、posture は未入力・線は引かない', () => {
    const { layer, summary } = ok(lines(ASSET_SSH, TAKEOVER, { input: 'a.example.com', value: 'P', cname: 'a.p.test' }, { input: 'x.example.org', value: 'Q' }));
    const zones = layer.nodes.filter((n) => n.type === 'DNS_ZONE');
    expect(zones.map((z) => z.label)).toEqual(['DNS（example.com）', 'DNS（example.org）']);
    const z = node(layer, 'scopesentry-dns-example_com');
    expect(z.description).toContain('乗っ取り可能と報告（未検証）');
    expect(z.description).toContain('blog.example.com → blog.example-hosting.test / ExampleHosting');
    expect(z.description).toContain('a.example.com → a.p.test / P');
    expect(z.posture).toBeUndefined();
    expect(layer.edges.some((e) => e.target === z.id || e.source === z.id)).toBe(false);
    expect(summary.takeovers).toBe(3);
  });

  it('乗っ取りの結果だけでも図を作る（サービス 0 件）', () => {
    const { layer, summary } = ok(lines(TAKEOVER));
    expect(layer.nodes.map((n) => n.type)).toEqual(['THREAT_ACTOR', 'DNS_ZONE']);
    expect(layer.edges).toHaveLength(0);
    expect(summary.services).toBe(0);
    expect(PersistedLayerDataSchema.safeParse(layer).success).toBe(true);
  });

  it('本文・ヘッダ・リクエスト・レスポンス・認証情報・URL のクエリ/userinfo は出力に現れない', () => {
    const dump = JSON.stringify(ok(ALL));
    for (const secret of ['SECRET', 'Bearer', 'xyz', 'Set-Cookie', 'Authorization', 'user:pw', 'token=', 'sid=']) {
      expect(dump).not.toContain(secret);
    }
  });

  it('同じ ip:port の複数ホストは 1 ノードにまとめ、最新の観測日を採る。ID は入力順に依らない', () => {
    const a = { ...ASSET_PLAIN, host: 'a.example.com', ip: '203.0.113.30', lastScanTime: '2026-01-01 00:00:00' };
    const b = { ...ASSET_PLAIN, host: 'b.example.com', ip: '203.0.113.30', lastScanTime: '2026-09-01 00:00:00' };
    const r1 = ok(lines(a, b));
    const r2 = ok(lines(b, a));
    expect(r1.layer.nodes.map((n) => n.id)).toEqual(r2.layer.nodes.map((n) => n.id));
    expect(r1.layer.nodes.filter((n) => n.type !== 'THREAT_ACTOR')).toHaveLength(1);
    expect(r1.layer.nodes[1].label).toBe('a.example.com:8080');
    expect(r1.layer.nodes[1].description).toContain('観測日: 2026-09-01');
  });

  it('壊れた行・種類を判定できないレコードは読み飛ばして数える。空はエラー', () => {
    const { summary } = ok([JSON.stringify(ASSET_SSH), '{broken', '{"foo":1}', '[1]', 'null', '{"ip":"1.2.3.4","port":"abc"}'].join('\n'));
    expect(summary.skipped).toBe(5);
    expect(scopesentryToLayer('').ok).toBe(false);
    expect(scopesentryToLayer('garbage').ok).toBe(false);
    expect(scopesentryToLayer('[]').ok).toBe(false);
  });

  it('英語ロケールでは名称・説明が英語になる', () => {
    setLocale('en');
    const r = ok(ALL);
    expect(r.name).toBe('External exposure observed by ScopeSentry');
    expect(node(r.layer, 'scopesentry-203_0_113_10-443-tcp').description).toContain('Vulnerabilities reported by ScopeSentry (unverified)');
    expect(node(r.layer, 'scopesentry-dns-example_com').label).toBe('DNS (example.com)');
  });

  it('永続化スキーマに適合し、境界は Internet と Public Area の 2 つ', () => {
    const { layer } = ok(ALL);
    expect(PersistedLayerDataSchema.safeParse(layer).success).toBe(true);
    expect(layer.boundaries.map((b) => [b.id, b.macroTrust])).toEqual([
      ['scopesentry-b-internet', undefined],
      ['scopesentry-b-exposed', 'Public Area'],
    ]);
  });

  it('生成した図で、公開 HTTP サービスの脅威と、乗っ取りの脅威が出る', () => {
    const { layer } = ok(ALL);
    const [result] = analyzeProject(layerToProject(layer));
    const on = (id: string) => result.threats.filter((t) => (t.subject?.id ?? t.nodeId) === id);
    expect(on('scopesentry-203_0_113_10-443-tcp').length).toBeGreaterThan(0);
    expect(on('scopesentry-e-203_0_113_12-8080-tcp').some((t) => t.ruleId === 'stride-edge-plain-encryption-001')).toBe(true);
    expect(result.threats.some((t) => t.ruleId === 'posture-dns-dangling-record-001' && (t.subject?.id ?? t.nodeId) === 'scopesentry-dns-example_com')).toBe(true);
  });
});
