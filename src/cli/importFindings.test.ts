import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { findingsReportToJson, findingsReportToMarkdown, importFindings } from './importFindings';
import { parseScap, type ScapFormat, type ScapHost } from '../features/scap-import/parseScap';
import { deserializeProject } from '../features/persistence/serialize';
import { analyzeProject } from './analyze';
import { toSarif } from './sarif';

const AT = '2026-10-31T00:00:00.000Z';
const fixture = (dir: string, name: string) => readFileSync(new URL(`../features/${dir}/__fixtures__/${name}`, import.meta.url), 'utf-8');
const project = JSON.parse(fixture('prowler-import', 'sample-project.json'));

function parsed(name: string): { format: ScapFormat; hosts: ScapHost[] } {
  const r = parseScap(fixture('scap-import', name));
  if (!r.ok) throw new Error(r.error);
  return r;
}

describe('importFindings', () => {
  it('--node で全ホストを結びつけ、保存した JSON が読み込める', () => {
    const out = importFindings(project, parsed('xccdf-results.xml'), { nodeRef: 'C1', importedAt: AT });
    expect(out.stored).toBe(3);
    const loaded = deserializeProject(JSON.parse(JSON.stringify(out.project)));
    expect(loaded?.findings).toHaveLength(3);
    expect(loaded?.findings?.[0].subject).toEqual({ layer: 'L1', nodeId: 'n-web' });
    expect(out.hosts[0]).toMatchObject({ scope: 'web01.example.internal', added: 3, resolved: 0, continued: 0 });
    expect(out.hosts[0].linked).toContain('C1');
  });

  it('ホストごとに置き換える：別ホストを続けて取り込んでも両方残り、同じホストの再取り込みは継続', () => {
    const a = importFindings(project, parsed('xccdf-results.xml'), { nodeRef: 'C1', importedAt: AT });
    const b = importFindings(JSON.parse(JSON.stringify(a.project)), parsed('oval-results.xml'), { nodeMap: { '192.0.2.20': 'C2' }, importedAt: AT });
    const scopes = new Set((b.project.findings ?? []).map((f) => f.source.scope));
    expect(scopes).toEqual(new Set(['web01.example.internal', 'db01.example.internal']));
    expect(b.project.findings).toHaveLength(5);
    const again = importFindings(JSON.parse(JSON.stringify(b.project)), parsed('xccdf-results.xml'), { nodeRef: 'C1', importedAt: AT });
    expect(again.hosts[0]).toMatchObject({ added: 0, resolved: 0, continued: 3 });
    expect(again.project.findings).toHaveLength(5);
  });

  it('未結合のホストは subject なしで報告に出る。md と json の基本形', () => {
    const out = importFindings(project, parsed('arf.xml'), { importedAt: AT });
    expect(out.project.findings?.every((f) => f.subject === undefined)).toBe(true);
    const md = findingsReportToMarkdown(out);
    expect(md).toContain('# SCAP 取り込みレポート（ARF）');
    expect(md).toContain('未結合');
    expect(md).toContain('analyze --format sarif --with-findings');
    const json = findingsReportToJson(out);
    expect(json).toMatchObject({ schemaVersion: 1, kind: 'cyberriskscape-findings-import-report', format: 'arf', stored: 2 });
  });

  it('入力が同じなら出力も同じ', () => {
    const a = findingsReportToJson(importFindings(project, parsed('arf.xml'), { nodeRef: 'C1', importedAt: AT }));
    const b = findingsReportToJson(importFindings(project, parsed('arf.xml'), { nodeRef: 'C1', importedAt: AT }));
    expect(a).toEqual(b);
  });

  it('保存した指摘を SARIF に書き出すと OpenSCAP の run ができ、ruleId は xccdf の idref', () => {
    const out = importFindings(project, parsed('xccdf-results.xml'), { nodeRef: 'C1', importedAt: AT });
    const results = analyzeProject(JSON.parse(JSON.stringify(out.project)));
    const sarif = toSarif(results, { artifactUri: 'p.json', findings: out.project.findings }) as {
      runs: { tool: { driver: { name: string } }; results: { ruleId: string }[]; properties?: { lostInConversion: string[] } }[];
    };
    const run = sarif.runs.find((r) => r.tool.driver.name === 'OpenSCAP');
    expect(run?.results[0].ruleId).toBe('xccdf_org.ssgproject.content_rule_sshd_disable_root_login');
    expect(run?.properties?.lostInConversion).toContain('target facts');
  });
});
