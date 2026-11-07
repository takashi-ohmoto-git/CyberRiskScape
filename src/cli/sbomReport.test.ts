import { describe, expect, it } from 'vitest';
import { sbomReport, sbomReportToJson, sbomReportToMarkdown } from './sbomReport';
import { cveFinding, makeProject } from './__fixtures__/findingsPriorityProject';

const comp = (name: string, extra: object = {}) => ({
  id: `c:${name}`,
  source: { format: 'cyclonedx', product: 'vendor-sbom', scope: 'app1', importedAt: '2026-11-01T00:00:00Z' },
  externalId: name,
  identifiers: [],
  kind: 'software',
  name,
  version: '1.0.0',
  observedAt: '2026-01-01T00:00:00Z',
  ...extra,
});
const project = () => ({
  ...(makeProject([cveFinding('f1', 'web', 'High', 'CVE-2099-0001', { kev: { dateAdded: '2099-01-01' } })]) as object),
  bomComponents: [comp('libfoo', { subject: { layer: 'L1', nodeId: 'pii' }, licenses: ['MIT'] }), comp('libbar')],
});
const now = new Date('2026-11-07T00:00:00Z');

describe('sbomReport', () => {
  it('md：SBOM の無いノード・古い取り込み・未結合・脆弱性・ライセンス欄の空を出し、判定はしない', () => {
    const md = sbomReportToMarkdown(sbomReport(project(), { now }));
    expect(md).toContain('合否は判定しない');
    expect(md).toContain('## SBOM の無いノード（1 件）');
    expect(md).toContain('- C2 公開サーバー');
    expect(md).toContain('90 日より古い');
    expect(md).toContain('libbar@1.0.0');
    expect(md).toContain('| C2 公開サーバー | 0 | 1 | 0 | 0 | 1 |');
    expect(md).toContain('ライセンス欄が空の部品 1 件');
  });

  it('--max-age-days を大きくする → stale にならない。json は kind を持つ', () => {
    const j = sbomReportToJson(sbomReport(project(), { now, maxAgeDays: 365 })) as {
      kind: string;
      perSource: { stale: boolean }[];
    };
    expect(j.kind).toBe('cyberriskscape-sbom-report');
    expect(j.perSource[0].stale).toBe(false);
  });
});
