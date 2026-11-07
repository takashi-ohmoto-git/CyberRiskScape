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

describe('importSarif（Trivy の SARIF）', () => {
  const trivy = (() => {
    const r = parseSarif(read('sarif-import', 'trivy.sarif.json'));
    if (!r.ok) throw new Error(r.error);
    return r;
  })();
  const out = importSarif(project, trivy, { scope: 'img-a', importedAt: AT });
  const findings = out.project.findings ?? [];

  it('3 件を保存し、製品名と版は tool.driver から読む', () => {
    expect(out.stored).toBe(3);
    expect(out.runs[0]).toMatchObject({ product: 'Trivy', productVersion: '0.76.2', results: 3, stored: 3, cweUnmapped: 0 });
  });

  it('security-severity の帯で深刻度を決める（7.5→High・5.5→Medium・9.5→Critical）', () => {
    const sev = (rule: string) => findings.find((f) => f.identifiers.some((i) => i.value === rule))?.severity;
    expect(sev('CVE-2026-0101')).toBe('High');
    expect(sev('AVD-EXMPL-0001')).toBe('Medium');
    expect(sev('example-access-key-id')).toBe('Critical');
  });

  it('CWE を持たないため、識別子は rule だけで canonicalIds も空', () => {
    for (const f of findings) {
      expect(f.identifiers).toHaveLength(1);
      expect(f.identifiers[0].scheme).toBe('rule');
      expect(f.identifiers.some((i) => i.scheme === 'cwe')).toBe(false);
      expect(f.canonicalIds).toEqual([]);
    }
    expect(findings.map((f) => f.identifiers[0].value).sort()).toEqual(['AVD-EXMPL-0001', 'CVE-2026-0101', 'example-access-key-id']);
  });

  it('場所は相対的な表記（ROOTPATH の uriBaseId は読まない）で、message 本文は保存しない', () => {
    const labels = findings.map((f) => f.resource?.label).sort();
    expect(labels).toEqual(['.env.example:3', 'infra/main.tf:12', 'package-lock.json:1']);
    const text = JSON.stringify(out.project);
    expect(text).not.toContain('fictitious-misconfig-message-body');
    expect(text).not.toContain('fictitious-vuln-body-text');
    expect(text).not.toContain('EXAMPLE_KEY_ID');
  });
});

describe('importSarif（ZAP の SARIF）', () => {
  const zap = (() => {
    const r = parseSarif(read('sarif-import', 'zap.sarif.json'));
    if (!r.ok) throw new Error(r.error);
    return r;
  })();
  const out = importSarif(project, zap, { scope: 'app-a', importedAt: AT });
  const findings = out.project.findings ?? [];
  const byRule = (rule: string) => findings.find((f) => f.identifiers.some((i) => i.value === rule));

  it('3 件を保存し、製品名と版は tool.driver から読む', () => {
    expect(out.stored).toBe(3);
    expect(out.runs[0]).toMatchObject({ product: 'ZAP', productVersion: '2.17.0', results: 3, stored: 3 });
  });

  it('level で深刻度を決める（error→High・warning→Medium）', () => {
    expect(byRule('40018')).toMatchObject({ severity: 'High', sourceSeverity: 'error' });
    expect(byRule('40012')).toMatchObject({ severity: 'High', sourceSeverity: 'error' });
    expect(byRule('10038')).toMatchObject({ severity: 'Medium', sourceSeverity: 'warning' });
  });

  it('CWE は relationships（toolComponent が CWE の数値 id）から読む', () => {
    expect(byRule('40018')?.identifiers).toContainEqual({ scheme: 'cwe', value: '89' });
    expect(byRule('10038')?.identifiers).toContainEqual({ scheme: 'cwe', value: '693' });
    expect(byRule('40012')?.identifiers).toContainEqual({ scheme: 'cwe', value: '79' });
  });

  it('canonicalId は cwe.yaml の対応どおり（89 は対応あり・693 と 79 は対応なしで未対応として数える）', () => {
    expect(byRule('40018')?.canonicalIds).toEqual(expect.arrayContaining(['api-query-injection']));
    expect(byRule('10038')?.canonicalIds).toEqual([]);
    expect(byRule('40012')?.canonicalIds).toEqual([]);
    expect(out.runs[0].cweUnmapped).toBe(2);
  });

  it('title は rule の shortDescription（message ではない）', () => {
    expect(byRule('40018')?.title).toBe('SQL Injection');
    expect(byRule('10038')?.title).toBe('Content Security Policy (CSP) Header Not Set');
  });

  it('リクエスト・レスポンス・snippet・攻撃文字列・message 本文は保存しない', () => {
    expect(JSON.stringify(out.project)).not.toContain('ZAP-SECRET-MARKER');
  });

  it('resource.label は URL（スキーム・ホスト・クエリを含む）に行番号を付けた表記', () => {
    // クエリは保存される（2026-11-07 ユーザー決定で変更しない）
    expect(byRule('40018')?.resource?.label).toBe("https://app.example.com/search?q=1'+OR+'1'='1:1");
    expect(byRule('10038')?.resource?.label).toBe('https://app.example.com/:1');
  });
});
