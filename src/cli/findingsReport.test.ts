import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyzeProject } from './analyze';
import { collectModelThreats, findingsReportToJson, findingsReportToMarkdown } from './findingsReport';
import { buildFindingsReport, evaluateFindingsGate } from '../features/findings-report/buildFindingsReport';
import { BUNDLED_FINDING_MAP } from '../features/findings-report/findingMap';
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
