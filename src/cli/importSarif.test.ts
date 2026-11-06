import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { importSarif, sarifReportToJson, sarifReportToMarkdown } from './importSarif';
import { parseSarif } from '../features/sarif-import/parseSarif';
import { scrubUri } from '../features/sarif-import/sarifToFindings';
import { deserializeProject } from '../features/persistence/serialize';

const AT = '2026-11-07T00:00:00.000Z';
const read = (dir: string, name: string) => JSON.parse(readFileSync(new URL(`../features/${dir}/__fixtures__/${name}`, import.meta.url), 'utf-8'));
const project = read('prowler-import', 'sample-project.json');
const sarif = (() => {
  const r = parseSarif(read('sarif-import', 'sample.sarif.json'));
  if (!r.ok) throw new Error(r.error);
  return r;
})();

describe('importSarif', () => {
  it('結果を指摘に変換し、除外（抑制・absent・pass・状態なしの抑制）を数える', () => {
    const out = importSarif(project, sarif, { scope: 'repo-a', importedAt: AT });
    expect(out.stored).toBe(6);
    expect(out.runs[0]).toMatchObject({ product: 'ExampleQL', productVersion: '2.15.0', results: 5, stored: 3, excluded: { suppressed: 1, absent: 1, kind: 0 } });
    expect(out.runs[1]).toMatchObject({ product: 'ExampleGrep', productVersion: '1.50.0', stored: 3, excluded: { suppressed: 1, absent: 0, kind: 1 } });
    const loaded = deserializeProject(JSON.parse(JSON.stringify(out.project)));
    expect(loaded?.findings).toHaveLength(6);
    expect(loaded?.findings?.every((f) => f.source.format === 'sarif' && f.source.scope === 'repo-a')).toBe(true);
  });

  it('CodeQL 風：security-severity の帯・CWE の識別子・canonicalId・externalId（指紋）', () => {
    const f = importSarif(project, sarif, { scope: 's', importedAt: AT }).project.findings ?? [];
    const sqli = f.find((x) => x.identifiers.some((i) => i.value === 'js/sql-injection'));
    expect(sqli).toMatchObject({ severity: 'Critical', sourceSeverity: '9.8', externalId: 'fp-sqli-1', title: 'SQL query built from user-controlled sources' });
    expect(sqli?.identifiers).toEqual([
      { scheme: 'rule', value: 'js/sql-injection' },
      { scheme: 'cwe', value: '89' },
    ]);
    expect(sqli?.canonicalIds).toContain('api-query-injection');
    const xss = f.find((x) => x.identifiers.some((i) => i.value === 'js/xss'));
    expect(xss).toMatchObject({ severity: 'Medium', externalId: 'js/xss:src/web/render.js:7' });
    expect(xss?.identifiers).toContainEqual({ scheme: 'cwe', value: '79' });
    const weak = f.find((x) => x.identifiers.some((i) => i.value === 'js/weak-thing'));
    expect(weak).toMatchObject({ severity: 'Low', canonicalIds: [] });
  });

  it('Semgrep 風：level だけで深刻度を決め、title は message の先頭 120 文字', () => {
    const f = importSarif(project, sarif, { scope: 's', importedAt: AT }).project.findings ?? [];
    const dbg = f.find((x) => x.identifiers.some((i) => i.value === 'python.flask.debug-enabled'));
    expect(dbg).toMatchObject({ severity: 'High', sourceSeverity: 'error' });
    expect(dbg?.title).toHaveLength(120);
    expect(f.find((x) => x.identifiers.some((i) => i.value === 'python.lang.note'))?.severity).toBe('Low');
    expect(f.find((x) => x.identifiers.some((i) => i.value === 'python.lang.rejected'))?.severity).toBe('Medium');
  });

  it('CWE が辞書に無い指摘を数え、message 本文・snippet は保存しない', () => {
    const out = importSarif(project, sarif, { scope: 's', importedAt: AT });
    expect(out.runs[0].cweUnmapped).toBe(2); // CWE-79 と CWE-9999
    const text = JSON.stringify(out.project);
    expect(text).not.toContain('secret-query-body');
    expect(text).not.toContain('SELECT *');
  });

  it('場所は相対的な表記に落とす（ドライブ・ユーザー名を持ち帰らない）', () => {
    const out = importSarif(project, sarif, { scope: 's', importedAt: AT });
    const labels = (out.project.findings ?? []).map((f) => f.resource?.label);
    expect(labels).toContain('work/app/src/db.js:42');
    expect(labels).toContain('proj/app.py:12');
    const text = JSON.stringify(out.project);
    expect(text).not.toContain('alice');
    expect(text).not.toContain('bob');
  });

  it.each([
    ['file:///C:/Users/alice/x/a.js', 'x/a.js'],
    ['file:///home/bob/x/a.js', 'x/a.js'],
    ['C:\\Users\\alice\\x\\a.js', 'x/a.js'],
    ['/Users/carol/x/a.js', 'x/a.js'],
    ['/var/app/a.js', 'var/app/a.js'],
    ['src/a.js', 'src/a.js'],
  ])('scrubUri: %s → %s', (input, expected) => {
    expect(scrubUri(input)).toBe(expected);
  });

  it('--node で結びつけ、見つからないときは未結合と理由', () => {
    const linked = importSarif(project, sarif, { scope: 's', node: 'C1', importedAt: AT });
    expect(linked.linked).toContain('C1');
    expect(linked.project.findings?.every((f) => f.subject?.nodeId === 'n-web')).toBe(true);
    const none = importSarif(project, sarif, { scope: 's', node: 'C99', importedAt: AT });
    expect(none.unlinkedReason).toBe('unknownNode');
    expect(none.project.findings?.every((f) => f.subject === undefined)).toBe(true);
  });

  it('取り込み直しは製品 × scope で置き換える：別 scope は残り、同じ scope は継続', () => {
    const a = importSarif(project, sarif, { scope: 'repo-a', importedAt: AT });
    const b = importSarif(JSON.parse(JSON.stringify(a.project)), sarif, { scope: 'repo-b', importedAt: AT });
    expect(b.project.findings).toHaveLength(12);
    const again = importSarif(JSON.parse(JSON.stringify(b.project)), sarif, { scope: 'repo-a', importedAt: AT });
    expect(again.replaced).toEqual([
      { product: 'ExampleQL', added: 0, resolved: 0, continued: 3 },
      { product: 'ExampleGrep', added: 0, resolved: 0, continued: 3 },
    ]);
    expect(again.project.findings).toHaveLength(12);
  });

  it('SARIF でない入力・版違いは拒否する', () => {
    expect(parseSarif({ foo: 1 }).ok).toBe(false);
    expect(parseSarif({ version: '1.0.0', runs: [] }).ok).toBe(false);
  });

  it('md と json の基本形', () => {
    const out = importSarif(project, sarif, { scope: 'repo-a', importedAt: AT });
    const md = sarifReportToMarkdown(out);
    expect(md).toContain('# SARIF 取り込みレポート');
    expect(md).toContain('CWE が辞書に無く');
    expect(sarifReportToJson(out)).toMatchObject({ kind: 'cyberriskscape-sarif-import-report', stored: 6, scope: 'repo-a' });
  });
});
