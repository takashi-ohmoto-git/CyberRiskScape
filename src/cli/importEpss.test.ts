import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { epssReportToJson, epssReportToMarkdown, importEpss } from './importEpss';
import { parseEpssCsv } from '../features/epss-import/applyEpss';
import { deserializeProject } from '../features/persistence/serialize';
import { cveFinding, makeProject } from './__fixtures__/findingsPriorityProject';

function epss(csv?: string) {
  const r = parseEpssCsv(csv ?? readFileSync(new URL('../features/epss-import/__fixtures__/epss_scores.csv', import.meta.url), 'utf-8'));
  if (!r.ok) throw new Error(r.error);
  return r;
}

describe('importEpss', () => {
  const project = makeProject([cveFinding('f1', 'web', 'Medium', 'CVE-2099-0001'), cveFinding('f2', 'mid', 'Low', 'CVE-2099-7777')]);

  it('照合して保存でき、読み直しても epss が残る。ノード別に数える', () => {
    const out = importEpss(project, epss());
    expect(out).toMatchObject({ checked: 2, matched: 1, removed: 0, invalid: 0, date: '2099-01-02T00:00:00+0000' });
    expect(out.byNode).toEqual([{ node: 'C2 公開サーバー', count: 1 }]);
    const loaded = deserializeProject(JSON.parse(JSON.stringify(out.project)));
    expect(loaded?.findings?.find((f) => f.id === 'f1')?.epss).toEqual({ score: 0.5, percentile: 0.97, date: '2099-01-02T00:00:00+0000' });
    expect(loaded?.findings?.find((f) => f.id === 'f2')?.epss).toBeUndefined();
  });

  it('取り込み直しで一覧から消えた CVE の epss を外す', () => {
    const first = importEpss(project, epss());
    const second = importEpss(JSON.parse(JSON.stringify(first.project)), epss('cve,epss,percentile\nCVE-2099-7777,0.2,0.3\n'));
    expect(second).toMatchObject({ matched: 1, removed: 1 });
    expect(second.project.findings?.find((f) => f.id === 'f1')?.epss).toBeUndefined();
  });

  it('epss の範囲外の値（score は 0〜1）→ プロジェクト全体を不正として読まない（kev と同じ厳しさ）', () => {
    const bad = makeProject([cveFinding('f1', 'web', 'Low', 'CVE-2099-0001', { epss: { score: 7.5 } })]);
    expect(deserializeProject(JSON.parse(JSON.stringify(bad)))).toBeNull();
  });

  it('報告：md の見出しと json の形', () => {
    const out = importEpss(project, epss('cve,epss,percentile\nCVE-2099-0001,0.5,0.9\nbad,x,y\n'));
    const md = epssReportToMarkdown(out);
    expect(md).toContain('# EPSS 照合レポート');
    expect(md).toContain('悪用の事実ではない');
    expect(md).toContain('## ノード別');
    expect(epssReportToJson(out)).toMatchObject({ kind: 'cyberriskscape-epss-import-report', checked: 2, matched: 1, removed: 0, invalidRows: 1 });
  });
});
