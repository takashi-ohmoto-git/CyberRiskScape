import { describe, expect, it } from 'vitest';
import { importKev, kevReportToJson, kevReportToMarkdown } from './importKev';
import { parseKevCatalog } from '../features/kev-import/applyKev';
import { deserializeProject } from '../features/persistence/serialize';
import { replaceFindings } from '../features/findings-import/replaceFindings';
import { cveFinding, makeProject } from './__fixtures__/findingsPriorityProject';

function catalog(ids: string[]) {
  const r = parseKevCatalog({
    catalogVersion: '2099.01.01',
    vulnerabilities: ids.map((cveID) => ({ cveID, dateAdded: '2099-01-01', dueDate: '2099-01-22', knownRansomwareCampaignUse: 'Known' })),
  });
  if (!r.ok) throw new Error(r.error);
  return r.catalog;
}

describe('importKev', () => {
  const project = makeProject([cveFinding('f1', 'web', 'Medium', 'CVE-2099-0001'), cveFinding('f2', 'mid', 'Low', 'CVE-2099-0002')]);

  it('照合して保存でき、読み直しても kev が残る。ノード別に数える', () => {
    const out = importKev(project, catalog(['cve-2099-0001']));
    expect(out).toMatchObject({ checked: 2, marked: 1, cleared: 0, catalogVersion: '2099.01.01' });
    expect(out.byNode).toEqual([{ node: 'C2 公開サーバー', count: 1 }]);
    const loaded = deserializeProject(JSON.parse(JSON.stringify(out.project)));
    expect(loaded?.findings?.find((f) => f.id === 'f1')?.kev).toMatchObject({ dateAdded: '2099-01-01', ransomware: true });
    expect(loaded?.findings?.find((f) => f.id === 'f2')?.kev).toBeUndefined();
  });

  it('取り込み直しでカタログから消えた指摘の印を外す', () => {
    const first = importKev(project, catalog(['CVE-2099-0001']));
    const second = importKev(JSON.parse(JSON.stringify(first.project)), catalog(['CVE-2099-0002']));
    expect(second).toMatchObject({ marked: 1, cleared: 1 });
    expect(second.project.findings?.find((f) => f.id === 'f1')?.kev).toBeUndefined();
  });

  it('照合の結果を CVE ごとに記録し、指摘を取り込み直しても読み込み時に印が戻る', () => {
    const marked = importKev(project, catalog(['CVE-2099-0001']));
    expect(marked.project.vulnIntel).toEqual({
      'CVE-2099-0001': { kev: { dateAdded: '2099-01-01', dueDate: '2099-01-22', ransomware: true, catalogVersion: '2099.01.01' } },
    });

    // 診断ツールの結果を取り込み直す：同じ製品の指摘が丸ごと置き換わり、kev の付いていない指摘になる
    const saved = JSON.parse(JSON.stringify(marked.project)) as typeof marked.project;
    const fresh = (saved.findings ?? []).map(({ kev: _kev, ...rest }) => rest);
    const product = fresh[0].source.product;
    const replaced = replaceFindings(saved.findings, fresh, product, fresh[0].source.scope);
    expect(replaced.findings.some((f) => f.kev)).toBe(false);

    const reloaded = deserializeProject(JSON.parse(JSON.stringify({ ...saved, findings: replaced.findings })));
    expect(reloaded?.findings?.find((f) => f.id === 'f1')?.kev).toMatchObject({ dateAdded: '2099-01-01', ransomware: true });
    expect(reloaded?.findings?.find((f) => f.id === 'f2')?.kev).toBeUndefined();
  });

  it('カタログから消えた CVE は記録からも消え、読み込み直しても印は戻らない', () => {
    const first = importKev(project, catalog(['CVE-2099-0001']));
    const second = importKev(JSON.parse(JSON.stringify(first.project)), catalog([]));
    expect(second.project.vulnIntel).toBeUndefined();
    const reloaded = deserializeProject(JSON.parse(JSON.stringify(second.project)));
    expect(reloaded?.findings?.some((f) => f.kev)).toBe(false);
  });

  it('報告：md の見出しと json の形', () => {
    const out = importKev(project, catalog(['CVE-2099-0001']));
    const md = kevReportToMarkdown(out);
    expect(md).toContain('# KEV 照合レポート');
    expect(md).toContain('## ノード別');
    expect(kevReportToJson(out)).toMatchObject({ kind: 'cyberriskscape-kev-import-report', checked: 2, marked: 1, cleared: 0 });
  });
});
