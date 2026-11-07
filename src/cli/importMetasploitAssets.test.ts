import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { importMetasploitAssets, metasploitAssetsReportToJson, metasploitAssetsReportToMarkdown } from './importMetasploitAssets';
import { parseMetasploit } from '../features/metasploit-import/parseMetasploit';
import { deserializeProject } from '../features/persistence/serialize';

const AT = '2026-11-05T00:00:00.000Z';
const xml = readFileSync(new URL('../features/metasploit-import/__fixtures__/metasploit-export.xml', import.meta.url), 'utf-8');
const parsed = parseMetasploit(xml);
if (!parsed.ok) throw new Error(parsed.error);
const project = () =>
  JSON.parse(readFileSync(new URL('../features/pentest-import/__fixtures__/sample-project.json', import.meta.url), 'utf-8'));
const roundTrip = (p: unknown) => JSON.parse(JSON.stringify(p));

describe('importMetasploitAssets', () => {
  it('open のサービスだけを Asset にし、closed とサービスの無いホストは数える', () => {
    const out = importMetasploitAssets(project(), parsed.hosts, { scope: 'msf-1', importedAt: AT });
    expect(out).toMatchObject({ hosts: 1, services: 2, closedServices: 1, hostsWithoutServices: 1 });
    const assets = out.project.assets ?? [];
    expect(assets.map((a) => a.externalId)).toEqual(['service:192.0.2.10:445/tcp', 'service:192.0.2.10:80/tcp']);
    expect(assets[0]).toMatchObject({
      kind: 'service',
      host: 'web01.example.test',
      ip: '192.0.2.10',
      port: 445,
      serviceName: 'smb',
      source: { format: 'metasploit', product: 'Metasploit', scope: 'msf-1' },
      observedAt: '2026-11-05T03:05:00.000Z',
    });
    expect(assets[0].identifiers).toEqual(expect.arrayContaining([{ scheme: 'ip', value: '192.0.2.10' }, { scheme: 'metasploit-service', value: '11' }]));
  });

  it('--host-node のホストはノードに結びつき、プロジェクト JSON の往復でも消えない。無いホストは未対応', () => {
    const none = importMetasploitAssets(project(), parsed.hosts, { scope: 'msf-1', importedAt: AT });
    expect(none.unlinkedHosts).toEqual(['192.0.2.10']);
    const out = importMetasploitAssets(project(), parsed.hosts, { scope: 'msf-1', hostNodes: { '192.0.2.10': 'C1' }, importedAt: AT });
    expect(out.unlinkedHosts).toEqual([]);
    const assets = deserializeProject(roundTrip(out.project))?.assets ?? [];
    expect(assets).toHaveLength(2);
    expect(assets.every((a) => a.subject?.nodeId !== undefined && a.source.format === 'metasploit')).toBe(true);
  });

  it('図に無いノードの指定は報告し、未対応にする', () => {
    const out = importMetasploitAssets(project(), parsed.hosts, { scope: 'msf-1', hostNodes: { '192.0.2.10': 'C999' }, importedAt: AT });
    expect(out.badNodeRefs).toEqual(['C999']);
    expect(out.unlinkedHosts).toEqual(['192.0.2.10']);
  });

  it('取り込み直しは製品 × scope で置き換え、他の scope は残す', () => {
    const first = importMetasploitAssets(project(), parsed.hosts, { scope: 'msf-1', importedAt: AT });
    const other = importMetasploitAssets(first.project, parsed.hosts, { scope: 'msf-2', importedAt: AT });
    expect(other.project.assets).toHaveLength(4);
    const again = importMetasploitAssets(other.project, parsed.hosts.slice(0, 1), { scope: 'msf-1', importedAt: AT });
    expect(again.project.assets).toHaveLength(4);
    const empty = importMetasploitAssets(again.project, [], { scope: 'msf-1', importedAt: AT });
    expect(empty.project.assets?.filter((a) => a.source.scope === 'msf-1')).toHaveLength(0);
    expect(empty.project.assets?.filter((a) => a.source.scope === 'msf-2')).toHaveLength(2);
  });

  it('秘密のマーカーは保存した資産にもレポートにも出ない', () => {
    const out = importMetasploitAssets(project(), parsed.hosts, { scope: 'msf-1', importedAt: AT });
    const all = JSON.stringify(out.project) + metasploitAssetsReportToMarkdown(out) + JSON.stringify(metasploitAssetsReportToJson(out));
    expect(all).not.toContain('MSF-SECRET-MARKER');
  });

  it('レポートに件数が入る', () => {
    const out = importMetasploitAssets(project(), parsed.hosts, { scope: 'msf-1', importedAt: AT });
    expect(metasploitAssetsReportToJson(out)).toMatchObject({ services: 2, closedServices: 1, unlinkedHosts: ['192.0.2.10'] });
    expect(metasploitAssetsReportToMarkdown(out)).toContain('サービス 2 件');
  });
});
