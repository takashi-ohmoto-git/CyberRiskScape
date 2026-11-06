import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { importAsmAssets } from './importAsmAssets';
import { shodanToLayer } from '../features/shodan-import/shodanToLayer';
import { scopesentryToLayer } from '../features/scopesentry-import/scopesentryToLayer';
import { deserializeProject } from '../features/persistence/serialize';
import { buildAssetViews } from '../features/asset-view/buildAssetViews';

const AT = '2026-11-07T00:00:00.000Z';
const project = () =>
  JSON.parse(readFileSync(new URL('../features/pentest-import/__fixtures__/sample-project.json', import.meta.url), 'utf-8'));
const banner = (ip: string, port: number, extra: Record<string, unknown> = {}) =>
  JSON.stringify({ ip_str: ip, port, transport: 'tcp', hostnames: [], timestamp: '2026-09-20T00:00:00', data: 'BANNER-SECRET', ...extra });
const shodan = (...b: string[]) => {
  const r = shodanToLayer(b.join('\n'));
  if (!r.ok) throw new Error(r.error);
  return r;
};
const SS_ASSET = { host: 'www.example.com', ip: '203.0.113.10', port: '443', service: 'https', type: 'http', webServer: 'nginx', tls: true, lastScanTime: '2026-10-20 10:00:00', body: 'SECRET-BODY' };
const SS_VULN = { url: 'https://www.example.com/', vulnid: 'CVE-2024-0001', level: 'high' };
const SS_NON_CVE = { url: 'https://www.example.com/', vulnerability: 'Example Info Leak' };
const opts = (scope: string, extra: object = {}) => ({ format: 'shodan' as const, product: 'Shodan', scope, importedAt: AT, ...extra });

describe('importAsmAssets（Shodan）', () => {
  const r = shodan(
    banner('203.0.113.10', 443, {
      hostnames: ['WWW.example.com'],
      product: 'nginx',
      version: '1.18',
      vulns: { 'CVE-2024-0002': {}, 'CVE-2024-0001': {}, '!CVE-2023-9999': {} },
      _shodan: { module: 'https' },
    }),
    banner('203.0.113.11', 22),
  );

  it('サービスを資産にし、識別子・CVE・観測時刻・安定 ID を持つ（本文は保存しない）', () => {
    const out = importAsmAssets(project(), r.exposed, opts('s1'));
    const [web, ssh] = out.project.assets ?? [];
    expect(out.services).toBe(2);
    expect(out.cves).toBe(3);
    expect(web).toMatchObject({
      id: 'Shodan:s1:203.0.113.10:443/tcp',
      source: { format: 'shodan', product: 'Shodan', scope: 's1', importedAt: AT },
      kind: 'service',
      ip: '203.0.113.10',
      domain: 'www.example.com',
      port: 443,
      technologies: ['nginx 1.18'],
      observedAt: '2026-09-20T00:00:00.000Z',
    });
    expect(web.identifiers).toEqual([
      { scheme: 'ip', value: '203.0.113.10' },
      { scheme: 'fqdn', value: 'www.example.com' },
      { scheme: 'cve', value: 'CVE-2023-9999' },
      { scheme: 'cve', value: 'CVE-2024-0001' },
      { scheme: 'cve', value: 'CVE-2024-0002' },
    ]);
    expect(ssh.id).toBe('Shodan:s1:203.0.113.11:22/tcp');
    expect(JSON.stringify(out.project.assets)).not.toContain('BANNER-SECRET');
  });
  it('CVE は最大 10 件まで識別子に残す', () => {
    const vulns = Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`CVE-2024-${1000 + i}`, {}]));
    const many = shodan(banner('203.0.113.10', 443, { vulns }));
    const out = importAsmAssets(project(), many.exposed, opts('s1'));
    expect(out.project.assets?.[0].identifiers.filter((i) => i.scheme === 'cve')).toHaveLength(10);
  });
  it('指摘（findings）は作らない。プロジェクト JSON の往復でも消えない', () => {
    const out = importAsmAssets(project(), r.exposed, opts('s1'));
    expect(out.project.findings).toBeUndefined();
    const back = deserializeProject(JSON.parse(JSON.stringify(out.project)));
    expect(back?.assets).toHaveLength(2);
    expect(back?.assets?.[0].identifiers.some((i) => i.scheme === 'cve')).toBe(true);
  });
  it('取り込み直しは製品 × scope で置き換え、他の scope・他の製品は残す', () => {
    const first = importAsmAssets(project(), r.exposed, opts('s1')).project;
    const other = importAsmAssets(first, r.exposed, opts('s2')).project;
    const sentry = importAsmAssets(other, r.exposed, { ...opts('s1'), format: 'scopesentry', product: 'ScopeSentry' }).project;
    expect(sentry.assets).toHaveLength(6);
    const again = importAsmAssets(sentry, shodan(banner('203.0.113.10', 443)).exposed, opts('s1'));
    expect(again.project.assets).toHaveLength(5);
  });
  it('--map / --node で明示したノードにだけ結ぶ。指定が無ければ未対応で、図に無い指定は報告する', () => {
    const none = importAsmAssets(project(), r.exposed, opts('s1'));
    expect(none.project.assets?.every((a) => a.subject === undefined)).toBe(true);
    expect(none.unlinkedHosts).toEqual(['203.0.113.10', '203.0.113.11']);

    const mapped = importAsmAssets(project(), r.exposed, opts('s1', { nodeMap: { 'www.example.com': 'C1' } }));
    expect(mapped.project.assets?.[0].subject).toMatchObject({ nodeId: 'n-web' });
    expect(mapped.project.assets?.[1].subject).toBeUndefined();
    expect(mapped.unlinkedHosts).toEqual(['203.0.113.11']);

    const bad = importAsmAssets(project(), r.exposed, opts('s1', { node: 'C99' }));
    expect(bad.badNodeRefs).toEqual(['C99']);
    expect(bad.unlinkedHosts).toHaveLength(2);
  });
  it('Asset タブのホストの見方に出る', () => {
    const out = importAsmAssets(project(), r.exposed, opts('s1', { nodeMap: { '203.0.113.10': 'n-web' } }));
    const { hosts } = buildAssetViews(out.project.assets ?? [], [{ id: 'n-web', type: 'FRONT_END_SERVER', layer: 'L1' }]);
    expect(hosts.map((h) => h.host)).toEqual(['203.0.113.10', '203.0.113.11']);
    expect(hosts[0]).toMatchObject({ domains: ['www.example.com'], technologies: ['nginx 1.18'] });
    expect(hosts[0].subjects).toHaveLength(1);
  });
});

describe('importAsmAssets（ScopeSentry）', () => {
  const r = scopesentryToLayer([SS_ASSET, SS_VULN, SS_NON_CVE].map((x) => JSON.stringify(x)).join('\n'));
  if (!r.ok) throw new Error(r.error);

  it('CVE 形式の ID を識別子にし、そうでない脆弱性名は入れない。時刻は ISO 8601 になる', () => {
    const out = importAsmAssets(project(), r.exposed, opts('p1', { format: 'scopesentry', product: 'ScopeSentry' }));
    const [a] = out.project.assets ?? [];
    expect(a.id).toBe('ScopeSentry:p1:203.0.113.10:443/tcp');
    expect(a.source.format).toBe('scopesentry');
    expect(a.identifiers.filter((i) => i.scheme === 'cve').map((i) => i.value)).toEqual(['CVE-2024-0001']);
    expect(a.observedAt).toBe(new Date('2026-10-20T10:00:00').toISOString());
    expect(JSON.stringify(out.project.assets)).not.toContain('SECRET-BODY');
  });
});

describe('互換', () => {
  it('図の下書きの説明欄の CVE の書き方は変わらない', () => {
    const s = shodan(banner('203.0.113.10', 443, { vulns: { 'CVE-2024-0001': {} } }));
    expect(s.layer.nodes.find((n) => n.id === 'shodan-203_0_113_10-443-tcp')?.description).toContain('CVE-2024-0001');
  });
});
