import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { importNuclei, nucleiReportToJson, nucleiReportToMarkdown } from './importNuclei';
import { parseNuclei } from '../features/nuclei-import/parseNuclei';
import { deserializeProject } from '../features/persistence/serialize';

const AT = '2026-11-07T00:00:00.000Z';
const project = JSON.parse(readFileSync(new URL('../features/prowler-import/__fixtures__/sample-project.json', import.meta.url), 'utf-8'));
const parsed = (() => {
  const r = parseNuclei(readFileSync(new URL('../features/nuclei-import/__fixtures__/nuclei.jsonl', import.meta.url), 'utf-8'));
  if (!r.ok) throw new Error(r.error);
  return r;
})();

describe('importNuclei', () => {
  it('指摘を保存し、プロジェクト JSON として読み直せる', () => {
    const out = importNuclei(project, parsed, { scope: 'dast', importedAt: AT, invalid: parsed.invalid });
    expect(out.stored).toBe(4);
    const loaded = deserializeProject(JSON.parse(JSON.stringify(out.project)));
    expect(loaded?.findings).toHaveLength(4);
    expect(loaded?.findings?.every((f) => f.source.format === 'nuclei')).toBe(true);
    expect(JSON.stringify(out.project)).not.toContain('NUCLEI-SECRET-MARKER');
  });

  it('--node で結びつけ、見つからないときは未結合と理由', () => {
    const linked = importNuclei(project, parsed, { scope: 's', node: 'C1', importedAt: AT });
    expect(linked.linked).toContain('C1');
    expect(linked.project.findings?.every((f) => f.subject?.nodeId === 'n-web')).toBe(true);
    const none = importNuclei(project, parsed, { scope: 's', node: 'C99', importedAt: AT });
    expect(none.unlinkedReason).toBe('unknownNode');
  });

  it('取り込み直しは scope で置き換える：別 scope は残り、同じ scope は継続', () => {
    const a = importNuclei(project, parsed, { scope: 'a', importedAt: AT });
    const b = importNuclei(JSON.parse(JSON.stringify(a.project)), parsed, { scope: 'b', importedAt: AT });
    expect(b.project.findings).toHaveLength(8);
    const again = importNuclei(JSON.parse(JSON.stringify(b.project)), parsed, { scope: 'a', importedAt: AT });
    expect(again.replaced).toEqual({ product: 'Nuclei', added: 0, resolved: 0, continued: 4 });
    expect(again.project.findings).toHaveLength(8);
  });

  it('md と json の基本形', () => {
    const out = importNuclei(project, parsed, { scope: 'dast', importedAt: AT, invalid: parsed.invalid });
    const md = nucleiReportToMarkdown(out);
    expect(md).toContain('# Nuclei 取り込みレポート');
    expect(md).toContain('保存しなかった情報');
    expect(md).toContain('info 1 / マッチしなかった結果 1');
    expect(nucleiReportToJson(out)).toMatchObject({ kind: 'cyberriskscape-nuclei-import-report', stored: 4, scope: 'dast', invalid: 1 });
  });
});
