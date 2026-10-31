import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyzeProject } from './analyze';
import { collectModelThreats, countNodeMatches, findingsReportToJson, findingsReportToMarkdown } from './findingsReport';
import { buildFindingsReport, evaluateFindingsGate } from '../features/findings-report/buildFindingsReport';
import { BUNDLED_AITECH_MAP, BUNDLED_FINDING_MAP } from '../features/findings-report/findingMap';
import { parseMcpScannerFindings } from '../features/findings-report/parseMcpScanner';
import { parseSkillScannerFindings } from '../features/findings-report/parseSkillScanner';
import { parseVeracodeFindings } from '../features/findings-report/parseVeracode';
import { setLocale } from '../i18n';

function run() {
  const project = JSON.parse(readFileSync(new URL('./__fixtures__/sample-project.json', import.meta.url), 'utf-8'));
  const veracode = JSON.parse(
    readFileSync(new URL('../features/findings-report/__fixtures__/findings-api.json', import.meta.url), 'utf-8'),
  );
  const parsed = parseVeracodeFindings(veracode);
  if (!parsed.ok) throw new Error(parsed.error);
  const threats = collectModelThreats(analyzeProject(project));
  return { threats, report: buildFindingsReport({ ...parsed, threats, map: BUNDLED_FINDING_MAP }) };
}

describe('findings-report（サンプル構成図 × Findings API の例）', () => {
  it('検出脅威を集め、md / json にできる', () => {
    const { threats, report } = run();
    expect(threats.length).toBeGreaterThan(0);
    expect(report.summary.openFindings).toBe(3);
    expect(report.summary.excludedSca).toBe(1);

    setLocale('ja');
    expect(findingsReportToMarkdown(report)).toContain('# 脆弱性スキャン結果と脅威モデルの突き合わせ');
    setLocale('en');
    expect(findingsReportToMarkdown(report)).toContain('# Scan findings vs. threat model');
    setLocale('ja');

    const json = findingsReportToJson(report);
    expect(json.kind).toBe('cyberriskscape-findings-report');
    expect(Object.keys(json)).toEqual([
      'schemaVersion',
      'kind',
      'summary',
      'confirmed',
      'notInModel',
      'unmapped',
      'priority',
      'gate',
    ]);
  });
});

describe('記録済みの判断の表示', () => {
  it('受容・実装済みの脅威に指摘が当たったら、その判断を併記する', () => {
    const threats = [
      {
        layer: 'L1' as const,
        canonicalId: 'plaintext-transmission',
        name: 'Eavesdropping',
        severity: 'High' as const,
        asset: 'DF2',
        riskTreatment: 'accepted' as const,
        controlStatus: 'implemented' as const,
      },
    ];
    const report = buildFindingsReport({
      findings: [{ id: '1', scanType: 'STATIC', cwe: 319, severity: 4, title: 'x', status: 'open' }],
      threats,
      excluded: { sca: 0, closed: 0 },
      map: BUNDLED_FINDING_MAP,
    });
    setLocale('ja');
    expect(findingsReportToMarkdown(report)).toContain('記録済みの判断: 受容・実装済み');
  });
});

describe('ゲート判定の出力', () => {
  const threats = [
    { layer: 'L1' as const, canonicalId: 'plaintext-transmission', name: 'E', severity: 'High' as const, asset: 'DF2' },
  ];
  const input = {
    findings: [{ id: '7', scanType: 'STATIC' as const, cwe: 319, severity: 4, title: 'send', status: 'open' as const }],
    threats,
    excluded: { sca: 0, closed: 0 },
    map: BUNDLED_FINDING_MAP,
  };
  const report = buildFindingsReport(input);

  it('未設定・PASS・FAIL を md と json に出す', () => {
    setLocale('ja');
    expect(findingsReportToMarkdown(report)).toContain('未設定（--fail-on 省略）');
    expect(findingsReportToJson(report).gate).toBeNull();

    const pass = { failOn: 'Critical' as const, offenders: evaluateFindingsGate(input, 'Critical') };
    expect(findingsReportToMarkdown(report, pass)).toContain('## ゲート判定\n\nPASS');
    expect(findingsReportToJson(report, pass).gate).toEqual({ failOn: 'Critical', passed: true, offenders: [] });

    const fail = { failOn: 'High' as const, offenders: evaluateFindingsGate(input, 'High') };
    const md = findingsReportToMarkdown(report, fail);
    expect(md).toContain('FAIL（High 以上の未抑制の脅威に当たる指摘が 1 件）');
    expect(md).toContain('- #7 [STATIC] S4 CWE-319 send');
    expect(findingsReportToJson(report, fail).gate).toEqual({ failOn: 'High', passed: false, offenders: ['7'] });

    setLocale('en');
    expect(findingsReportToMarkdown(report, fail)).toContain('FAIL (1 finding(s)');
    setLocale('ja');
  });
});

describe('findings-report（skill-scanner / mcp-scanner × AGENT・AGENT_SKILL・MCP_SERVER の図）', () => {
  const fx = (name: string) =>
    JSON.parse(readFileSync(new URL(`../features/findings-report/__fixtures__/${name}`, import.meta.url), 'utf-8'));
  const results = analyzeProject(fx('cisco-sample-project.json'));
  const parse = (kind: 'skill' | 'mcp', name: string) => {
    const p = kind === 'skill' ? parseSkillScannerFindings(fx(name)) : parseMcpScannerFindings(fx(name));
    if (!p.ok) throw new Error(p.error);
    return p;
  };
  const input = (kind: 'skill' | 'mcp', name: string, node?: string) => {
    const p = parse(kind, name);
    return {
      findings: p.findings,
      threats: collectModelThreats(results, node),
      excluded: p.excluded,
      map: BUNDLED_FINDING_MAP,
      aitechMap: BUNDLED_AITECH_MAP,
      incompleteItems: p.incompleteItems,
    };
  };

  it('skill-scanner: confirmed / unmapped に振り分ける（AISubtech が表に無ければ AITech で引く）', () => {
    const report = buildFindingsReport(input('skill', 'skill-scanner-single.json'));
    expect(report.confirmed.map((c) => c.canonicalId)).toEqual(
      expect.arrayContaining(['direct-prompt-injection', 'tool-descriptor-poisoning', 'excessive-agency']),
    );
    expect(report.summary).toMatchObject({ openFindings: 4, confirmedFindings: 2, unmappedFindings: 2 });
    expect(report.unmapped.map((u) => u.aisubtech ?? u.aitech)).toEqual(['AISubtech-15.1.9', undefined]);
    expect(report.summary.incompleteItems).toBeUndefined();
  });

  it('mcp-scanner: 古い AISubtech-12.1.5 は AITech-12.1 の行で受け止まり、incompleteItems を数える', () => {
    const report = buildFindingsReport(input('mcp', 'mcp-scanner-envelope.json'));
    const ids = report.confirmed.flatMap((c) => c.findings.findings.map((f) => f.aisubtech));
    expect(ids).toContain('AISubtech-12.1.5');
    expect(report.summary.incompleteItems).toBe(1);
    expect(report.unmapped.map((u) => u.aisubtech)).toEqual(['AISubtech-15.1.9']);
  });

  it('対応表にあるが図に脅威が無い指摘は notInModel に出る', () => {
    const report = buildFindingsReport({ ...input('skill', 'skill-scanner-multi.json'), threats: [] });
    expect(report.notInModel.length).toBeGreaterThan(0);
    expect(report.confirmed).toEqual([]);
  });

  it('--node: 対象ノード・接する線・線の先・内包の親子の脅威だけに絞る', () => {
    const subjects = (node?: string) => new Set(collectModelThreats(results, node).map((t) => t.asset.split(' ')[0]));
    // C2（スキル）: C2・DF1・C1 だけ。C3（MCP）や DF2 は含まない
    const s2 = subjects('C2');
    expect(s2.has('C2')).toBe(true);
    expect(s2.has('C3')).toBe(false);
    expect(s2.has('DF2')).toBe(false);
    // C3（MCP）: 線の先の C1 と C4 を含み、C2 は含まない
    const s3 = subjects('c3');
    expect(s3.has('C3')).toBe(true);
    expect(s3.has('C1')).toBe(true);
    expect(s3.has('C2')).toBe(false);
    expect(collectModelThreats(results, 'C9')).toEqual([]);
    expect(countNodeMatches(results, 'C3')).toBe(1);
    expect(countNodeMatches(results, 'C9')).toBe(0);
  });

  it('--node で絞ると、図全体より confirmed の脅威が減る', () => {
    const all = buildFindingsReport(input('mcp', 'mcp-scanner-envelope.json'));
    const scoped = buildFindingsReport(input('mcp', 'mcp-scanner-envelope.json', 'C2'));
    expect(scoped.summary.confirmedThreats).toBeLessThan(all.summary.confirmedThreats);
  });

  it('--fail-on: 裏付けられた未抑制の脅威が閾値以上なら違反、絞り込みで外れれば違反なし', () => {
    const i = input('skill', 'skill-scanner-single.json');
    expect(evaluateFindingsGate(i, 'Critical').length).toBeGreaterThan(0);
    const none = { ...i, threats: [] };
    expect(evaluateFindingsGate(none, 'Low')).toEqual([]);
  });

  it('md / json: ソース名・ラベル表示・対象ノード・検査未完了。秘密は出ない', () => {
    setLocale('ja');
    const i = input('mcp', 'mcp-scanner-envelope.json', 'C3');
    const report = buildFindingsReport(i);
    const opts = { source: 'mcp-scanner' as const, node: 'C3' };
    const md = findingsReportToMarkdown(report, undefined, opts);
    expect(md).toContain('mcp-scanner の指摘を、AITech 分類の対応表を介して');
    expect(md).toContain('対象ノード: C3');
    expect(md).toContain('検査が完了していない項目: 1 件');
    expect(md).toContain('[HIGH]');
    expect(md).not.toContain('Veracode');
    expect(md).not.toContain('集計から除外');
    const json = JSON.stringify(findingsReportToJson(report, undefined, opts));
    expect(JSON.parse(json)).toMatchObject({ source: 'mcp-scanner', node: 'C3' });
    for (const text of [md, json]) {
      for (const s of ['sk-live-XXXX', 'SECRET123', 'some-mcp-server', 'secret-dir']) expect(text).not.toContain(s);
    }
    const unmapped = JSON.parse(json).unmapped[0];
    expect(unmapped).toMatchObject({ aisubtech: 'AISubtech-15.1.9', aisubtechName: 'Hate Speech' });
    setLocale('en');
    expect(findingsReportToMarkdown(report, undefined, opts)).toContain('mcp-scanner findings cross-referenced');
    setLocale('ja');
  });

  it('skill-scanner の md / json にも秘密・絶対パスは出ない。Veracode の JSON に Cisco 系のキーは出ない', () => {
    const report = buildFindingsReport(input('skill', 'skill-scanner-single.json'));
    const opts = { source: 'skill-scanner' as const };
    const text = findingsReportToMarkdown(report, undefined, opts) + JSON.stringify(findingsReportToJson(report, undefined, opts));
    for (const s of ['sk-live-XXXX', 'SECRET123', 'secret-dir', 'subprocess']) expect(text).not.toContain(s);

    const v = run().report;
    const vjson = JSON.stringify(findingsReportToJson(v));
    expect(vjson).not.toMatch(/"(source|node|aitech|aisubtech|incompleteItems|origin)"/);
  });
});
