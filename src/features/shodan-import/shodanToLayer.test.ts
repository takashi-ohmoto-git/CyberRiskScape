import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';
import { shodanToLayer } from './shodanToLayer';
import { PersistedLayerDataSchema } from '../persistence/schema';
import { layerToProject } from '../kong-import/toProject';
import { analyzeProject } from '../../cli/analyze';
import { setLocale } from '../../i18n';
import type { LayerData } from '../../core/model/types';

const SAMPLE = readFileSync('guide/templates/shodan-sample.json', 'utf-8');

function ok(text: string) {
  const r = shodanToLayer(text);
  if (!r.ok) throw new Error(r.error);
  return r;
}
const banner = (ip: string, port: number, extra: Record<string, unknown> = {}) =>
  JSON.stringify({ ip_str: ip, port, transport: 'tcp', hostnames: [], domains: [], timestamp: '2026-09-20T00:00:00', hash: 1, data: 'x', ...extra });
const node = (l: LayerData, id: string) => l.nodes.find((n) => n.id === id)!;
const edge = (l: LayerData, id: string) => l.edges.find((e) => e.id === id)!;

describe('shodanToLayer', () => {
  afterEach(() => setLocale('ja'));

  it('サービスの性質ごとにノード型を分ける', () => {
    const { layer } = ok(SAMPLE);
    expect(node(layer, 'shodan-203_0_113_10-443-tcp').type).toBe('FRONT_END_SERVER');
    expect(node(layer, 'shodan-203_0_113_10-22-tcp').type).toBe('GATEWAY');
    expect(node(layer, 'shodan-203_0_113_11-3389-tcp').type).toBe('GATEWAY');
    expect(node(layer, 'shodan-203_0_113_12-9200-tcp').type).toBe('DATA_STORE');
    expect(node(layer, 'shodan-203_0_113_13-11434-tcp').type).toBe('LLM');
    expect(node(layer, 'shodan-203_0_113_14-5938-tcp').type).toBe('GATEWAY');
    expect(node(layer, 'shodan-198_51_100_20-443-tcp').type).toBe('GATEWAY');
    expect(node(layer, 'shodan-actor')).toMatchObject({ type: 'THREAT_ACTOR', threatActorType: 'CyberCriminals' });
  });

  it('ics タグは IOT で、OT/ICS 未対応の注記を説明欄に書く。その他の分類（PROCESS）も確認する', () => {
    const { layer } = ok([banner('203.0.113.50', 502, { tags: ['ics'] }), banner('203.0.113.51', 1883)].join('\n'));
    expect(node(layer, 'shodan-203_0_113_50-502-tcp').type).toBe('IOT');
    expect(node(layer, 'shodan-203_0_113_50-502-tcp').description).toContain('OT/ICS');
    expect(node(layer, 'shodan-203_0_113_51-1883-tcp').type).toBe('PROCESS');
  });

  it('ssl があれば TLS、無ければ Plain の線を攻撃者から引く', () => {
    const { layer } = ok(SAMPLE);
    const https = edge(layer, 'shodan-e-203_0_113_10-443-tcp');
    expect(https).toMatchObject({ source: 'shodan-actor', network: 'Internet', encryption: 'TLS', auth: 'Password', dataFlow: 'bidirectional' });
    expect(edge(layer, 'shodan-e-203_0_113_13-11434-tcp').encryption).toBe('Plain');
    expect(edge(layer, 'shodan-e-203_0_113_11-3389-tcp').dataFlowName).toBe('RDP 3389/tcp');
  });

  it('WAF が報告されたときだけ hasWafProtection を付け、他の攻撃面は未設定のままにする', () => {
    const { layer } = ok(SAMPLE);
    const waf = node(layer, 'shodan-203_0_113_10-443-tcp').attackSurface!;
    expect(waf.hasGlobalIp).toBe(true);
    expect(waf.hasWafProtection).toBe(true);
    expect(waf.hasRemoteAccessRestriction).toBeUndefined();
    expect(waf.hasUserAuthentication).toBeUndefined();
    const plain = node(layer, 'shodan-203_0_113_10-22-tcp').attackSurface!;
    expect(plain).toEqual({ hasGlobalIp: true });
    expect(node(layer, 'shodan-203_0_113_12-9200-tcp').attackSurface).toBeUndefined();
  });

  it('CVE は ID だけを昇順で最大 10 件書き、超過は「他 N 件」にする', () => {
    const vulns = Object.fromEntries(Array.from({ length: 13 }, (_, i) => [`CVE-2020-${String(1000 + i)}`, { cvss: 9 }]));
    const { layer, summary } = ok(banner('203.0.113.60', 8080, { vulns }));
    const d = node(layer, 'shodan-203_0_113_60-8080-tcp').description!;
    expect(d).toContain('Shodan が報告した CVE（未検証）: CVE-2020-1000, CVE-2020-1001');
    expect(d).toContain('CVE-2020-1009 他 3 件');
    expect(d).not.toContain('CVE-2020-1010');
    expect(d).not.toContain('cvss');
    expect(summary.cves).toBe(13);
  });

  it('同じサービスが複数あれば timestamp が最新のバナーを採る', () => {
    const old = banner('203.0.113.70', 8080, { product: 'old', timestamp: '2026-01-01T00:00:00' });
    const recent = banner('203.0.113.70', 8080, { product: 'new', timestamp: '2026-09-01T00:00:00' });
    for (const text of [`${old}\n${recent}`, `${recent}\n${old}`]) {
      const { layer, summary } = ok(text);
      expect(layer.nodes.filter((n) => n.type !== 'THREAT_ACTOR')).toHaveLength(1);
      expect(layer.nodes[1].label).toBe('203.0.113.70:8080 new');
      expect(summary.banners).toBe(2);
    }
    expect(ok(SAMPLE).layer.nodes.find((n) => n.id === 'shodan-203_0_113_11-3389-tcp')!.description).toContain('観測日: 2026-09-25');
  });

  it('壊れた行は読み飛ばして数える（致命的にしない）。ip_str / port の無いバナーも同様', () => {
    const { summary } = ok(SAMPLE);
    expect(summary.skipped).toBe(1);
    expect(ok(`${banner('203.0.113.80', 22)}\n{"port": 22}\n[1]\nnull`).summary.skipped).toBe(3);
  });

  it('バナー本文・HTTP の内容・証明書の中身は図に載せない', () => {
    const dump = JSON.stringify(ok(SAMPLE).layer);
    expect(dump).not.toContain('SECRET-SHOULD-NOT-APPEAR');
    expect(dump).toContain('www.example.com:443 nginx');
  });

  it('JSON 配列・ホストの data 配列・JSON Lines は同じ図になる', () => {
    const lines = SAMPLE.split('\n').filter((l) => l.trim() && !l.includes('malformed'));
    const expected = ok(SAMPLE).layer;
    expect(ok(`[${lines.join(',')}]`).layer).toEqual(expected);
    expect(ok(JSON.stringify({ ip_str: '203.0.113.10', data: lines.map((l) => JSON.parse(l)) })).layer).toEqual(expected);
  });

  it('空・バナーでないものはエラーを返す', () => {
    expect(shodanToLayer('').ok).toBe(false);
    expect(shodanToLayer('garbage\nmore garbage').ok).toBe(false);
    expect(shodanToLayer('{"ip_str":"1.2.3.4"}').ok).toBe(false);
    expect(shodanToLayer('[]').ok).toBe(false);
  });

  it('入力順が変わっても、バナーが増えても既存の ID は変わらない', () => {
    const lines = SAMPLE.split('\n').filter(Boolean);
    const base = ok(lines.join('\n')).layer;
    const reversed = ok([...lines].reverse().join('\n')).layer;
    expect(reversed.nodes.map((n) => n.id)).toEqual(base.nodes.map((n) => n.id));
    const extra = ok([banner('192.0.2.1', 22), ...lines].join('\n')).layer;
    const ids = new Set(extra.nodes.map((n) => n.id));
    for (const n of base.nodes) expect(ids.has(n.id)).toBe(true);
  });

  it('件数を集計し、永続化スキーマに適合する。境界は Internet と Public Area の 2 つ', () => {
    const { layer, summary } = ok(SAMPLE);
    expect(summary).toEqual({ banners: 8, services: 7, hosts: 6, cves: 2, skipped: 1, truncated: 0 });
    expect(PersistedLayerDataSchema.safeParse(layer).success).toBe(true);
    expect(layer.boundaries.map((b) => [b.id, b.type, b.trustLevel, b.macroTrust])).toEqual([
      ['shodan-b-internet', 'RECT', 'Internet', undefined],
      ['shodan-b-exposed', 'ROUNDED', 'Internet', 'Public Area'],
    ]);
  });

  it('サービスは 300 件までで、超過分は truncated に数える', () => {
    const text = Array.from({ length: 305 }, (_, i) => banner('203.0.113.90', 1000 + i)).join('\n');
    const { layer, summary } = ok(text);
    expect(summary).toMatchObject({ services: 300, truncated: 5 });
    expect(layer.edges).toHaveLength(300);
  });

  it('生成した図で、RDP の管理面露出・Ollama の平文通信・Elasticsearch の脅威が出る', () => {
    const { layer } = ok(SAMPLE);
    const [result] = analyzeProject(layerToProject(layer));
    const hits = (ruleId: string) => result.threats.filter((t) => t.ruleId === ruleId).map((t) => t.subject?.id ?? t.nodeId);
    expect(hits('stride-web-remote-mgmt-exposed-001')).toContain('shodan-203_0_113_11-3389-tcp');
    expect(hits('stride-edge-plain-encryption-001')).toContain('shodan-e-203_0_113_13-11434-tcp');
    expect(result.threats.some((t) => (t.subject?.id ?? t.nodeId) === 'shodan-203_0_113_12-9200-tcp')).toBe(true);
  });

  it('英語ロケールでは名称・説明が英語になる', () => {
    setLocale('en');
    const r = ok(SAMPLE);
    expect(r.name).toBe('External exposure observed by Shodan');
    expect(node(r.layer, 'shodan-actor').label).toBe('Attacker on the internet');
    expect(node(r.layer, 'shodan-203_0_113_10-443-tcp').description).toContain('CVEs reported by Shodan (unverified)');
  });
});
