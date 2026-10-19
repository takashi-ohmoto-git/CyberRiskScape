import { describe, expect, it } from 'vitest';
import { buildFindingsReport, type ModelThreat } from './buildFindingsReport';
import type { FindingMapping } from './findingMap';
import type { NormalizedFinding } from './parseVeracode';

const map: FindingMapping[] = [
  { cwe: [89], canonicalIds: ['sqli'] },
  { cwe: [78], canonicalIds: ['exec', 'sqli'] },
  { cwe: [918], canonicalIds: ['ssrf'] },
];

const f = (
  id: string,
  cwe: number | undefined,
  severity: number,
  extra: Partial<NormalizedFinding> = {},
): NormalizedFinding => ({
  id,
  scanType: 'STATIC',
  cwe,
  severity,
  title: `t${id}`,
  status: 'open',
  ...extra,
});

const threat = (canonicalId: string, severity: ModelThreat['severity']): ModelThreat => ({
  layer: 'L1',
  canonicalId,
  name: `n-${canonicalId}`,
  severity,
  asset: 'C1 API',
});

describe('buildFindingsReport', () => {
  const report = buildFindingsReport({
    findings: [
      f('1', 89, 3),
      f('2', 78, 5),
      f('3', 918, 4),
      f('4', 79, 4),
      f('5', undefined, 1),
      f('6', 20, 2, { scanType: 'MANUAL', capec: 'CAPEC-1' }),
      f('7', 89, 5),
    ],
    threats: [threat('sqli', 'Medium'), threat('exec', 'Critical')],
    excluded: { sca: 2, closed: 1 },
    map,
  });

  it('confirmed: 構成図にも指摘にもある canonicalId だけを、構成図側の重大度順に出す', () => {
    expect(report.confirmed.map((c) => c.canonicalId)).toEqual(['exec', 'sqli']);
    const sqli = report.confirmed.find((c) => c.canonicalId === 'sqli');
    expect(sqli?.findings).toMatchObject({ count: 3, maxSeverity: 5 });
    expect(sqli?.findings.findings.map((x) => x.id)).toEqual(['2', '7', '1']);
  });

  it('notInModel: 構成図に該当脅威が無い指摘', () => {
    expect(report.notInModel.map((n) => n.canonicalId)).toEqual(['ssrf']);
  });

  it('unmapped: CWE 無し・対応表に無い指摘を CWE ごとにまとめ、capec をそのまま残す', () => {
    expect(report.unmapped.map((u) => u.cwe)).toEqual([79, 20, undefined]);
    expect(report.unmapped.find((u) => u.cwe === 20)?.capec).toEqual(['CAPEC-1']);
  });

  it('priority: 構成図の重大度 → Veracode の重大度 → id の順', () => {
    expect(report.priority.map((p) => p.finding.id)).toEqual(['2', '7', '1']);
    expect(report.priority[0]).toMatchObject({ modelSeverity: 'Critical', canonicalIds: ['exec', 'sqli'] });
  });

  it('summary と除外件数', () => {
    expect(report.summary).toEqual({
      openFindings: 7,
      confirmedFindings: 3,
      notInModelFindings: 1,
      unmappedFindings: 3,
      confirmedThreats: 2,
      excludedSca: 2,
      excludedClosed: 1,
    });
  });
});
