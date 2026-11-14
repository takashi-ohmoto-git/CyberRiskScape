import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyzeProject } from './analyze';
import { projectIndicators } from './indicators';

const FIXTURE_PATH = new URL('./__fixtures__/sample-project.json', import.meta.url);
const raw = () => JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as Record<string, unknown>;

describe('projectIndicators', () => {
  it('判断を外した図では 3 つの指標が 0 で、対象の件数は全フレームワークの脅威の数', () => {
    const base = { ...raw(), suppressions: {}, riskScores: {}, controlStatuses: {} };
    const report = projectIndicators(base);
    const all = analyzeProject(base, { framework: 'ALL' }).flatMap((r) => r.threats);
    expect(report.schemaVersion).toBe(1);
    expect(report.indicators.total).toBe(all.length);
    expect(report.indicators.total).toBeGreaterThan(0);
    expect(report.indicators).toMatchObject({ controlSetRate: 0, treatmentSetRate: 0, implementedRate: 0, value: 0 });
    expect(report.weights.severity.Critical).toBe(8);
  });

  it('すべての脅威を実装済み・低減にすると 3 つとも 1 になる', () => {
    const base = { ...raw(), suppressions: {}, riskScores: {}, controlStatuses: {} };
    const ids = analyzeProject(base, { framework: 'ALL' }).flatMap((r) => r.threats.map((t) => t.id));
    const report = projectIndicators({
      ...base,
      controlStatuses: Object.fromEntries(ids.map((id) => [id, { status: 'implemented', at: 1 }])),
      suppressions: Object.fromEntries(ids.map((id) => [id, { status: 'reduce', at: 1 }])),
    });
    expect(report.indicators).toMatchObject({ controlSetRate: 1, treatmentSetRate: 1, implementedRate: 1, value: 1 });
  });

  it('プロジェクトの ID と組織上の属性を添える（無い項目は出さない）', () => {
    const report = projectIndicators({
      ...raw(),
      projectId: '11111111-1111-4111-8111-111111111111',
      projectMeta: {
        ...((raw().projectMeta as Record<string, unknown> | undefined) ?? {}),
        name: 'Sample',
        organizationCode: 'ORG-1',
        criticality: 'High',
        lifecycle: 'production',
      },
    });
    expect(report).toMatchObject({
      projectId: '11111111-1111-4111-8111-111111111111',
      projectName: 'Sample',
      organizationCode: 'ORG-1',
      criticality: 'High',
      lifecycle: 'production',
    });
    expect('organizationName' in report).toBe(false);
  });

  it('形式が不正なら例外', () => {
    expect(() => projectIndicators({ nope: true })).toThrow();
  });
});
