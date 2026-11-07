import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { importSecurityAudit, securityAuditReportToJson, securityAuditReportToMarkdown } from './importSecurityAudit';
import { parseCoverageLedger, parseSecurityAudit } from '../features/security-audit-import/parseSecurityAudit';
import { deserializeProject } from '../features/persistence/serialize';

const AT = '2026-11-07T00:00:00.000Z';
const read = (dir: string, name: string) => JSON.parse(readFileSync(new URL(`../features/${dir}/__fixtures__/${name}`, import.meta.url), 'utf-8'));
const project = () => read('prowler-import', 'sample-project.json');
const items = (() => {
  const r = parseSecurityAudit(read('security-audit-import', 'findings.json'));
  if (!r.ok) throw new Error(r.error);
  return r;
})();
const ledger = (() => {
  const r = parseCoverageLedger(read('security-audit-import', 'coverage-ledger.json'));
  if (!r.ok) throw new Error(r.error);
  return r.units;
})();
const roundTrip = (p: unknown) => JSON.parse(JSON.stringify(p));

describe('importSecurityAudit', () => {
  it('confirmed と要確認を保存し、rejected は保存しない。往復しても印が残る', () => {
    const out = importSecurityAudit(project(), items.items, { ledger, invalid: items.invalid, importedAt: AT });
    expect(out.scope).toBe('default');
    expect(out.stored).toBe(3);
    expect(out.report).toMatchObject({ confirmed: 2, unverified: 1, rejected: 1, unmapped: 1 });
    const findings = deserializeProject(roundTrip(out.project))?.findings ?? [];
    expect(findings).toHaveLength(3);
    const nv = findings.find((f) => f.externalId === 'default:fp-nv-003');
    expect(nv).toMatchObject({ outcome: 'unverified', severity: 'Low' });
    expect(nv?.sourceSeverity).toBeUndefined();
    expect(nv?.openQuestions).toHaveLength(5);
    expect(findings.find((f) => f.externalId === 'default:fp-authz-001')?.conditions).toHaveLength(6);
  });

  it('payloads・修正コード等の秘匿対象はプロジェクト JSON と報告のどこにも現れない', () => {
    const out = importSecurityAudit(project(), items.items, { ledger, importedAt: AT });
    const all = JSON.stringify(out.project) + securityAuditReportToMarkdown(out) + JSON.stringify(securityAuditReportToJson(out));
    for (const w of ['PAYLOAD-SECRET', 'FIXED-CODE-SECRET', 'REJECTED-TITLE-SECRET', 'EVIDENCE-TEXT', 'ROOTCAUSE-TEXT', 'LOCAL-PLAN-SECRET']) {
      expect(all, w).not.toContain(w);
    }
  });

  it('取り込み直し → 同じ scope を置き換え、他の scope は触らない', () => {
    const first = importSecurityAudit(project(), items.items, { scope: 'a', importedAt: AT });
    const other = importSecurityAudit(roundTrip(first.project), items.items, { scope: 'b', importedAt: AT });
    expect(other.project.findings).toHaveLength(6);
    const again = importSecurityAudit(roundTrip(other.project), items.items.slice(0, 1), { scope: 'a', importedAt: AT });
    expect(again.diff).toEqual({ added: 0, resolved: 2, continued: 1 });
    expect(again.project.findings?.filter((f) => f.source.scope === 'b')).toHaveLength(3);
  });

  it('scope 未指定で --node あり → scope はノードの ID。別の scope の同じ指紋とは ID が衝突しない', () => {
    const linked = importSecurityAudit(project(), items.items, { node: 'C1', importedAt: AT });
    expect(linked.scope).toBe('n-web');
    const both = importSecurityAudit(roundTrip(linked.project), items.items, { scope: 'other', importedAt: AT });
    const ids = (both.project.findings ?? []).map((f) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('--node → すべての指摘が結びつく。無い・曖昧でない不明なノードは理由を出す', () => {
    const linked = importSecurityAudit(project(), items.items, { node: 'C1', importedAt: AT });
    expect(linked.linked).toContain('C1');
    expect(linked.project.findings?.every((f) => f.subject?.layer === 'L1' && f.subject.nodeId === 'n-web')).toBe(true);
    const unknown = importSecurityAudit(project(), items.items, { node: 'C99', importedAt: AT });
    expect(unknown.unlinkedReason).toBe('unknownNode');
    expect(unknown.project.findings?.some((f) => f.subject)).toBe(false);
  });

  it('報告（md・json）に件数・対応づけできない指摘・表に無い攻撃クラスが出る', () => {
    const out = importSecurityAudit(project(), items.items, { ledger, invalid: items.invalid, importedAt: AT });
    const md = securityAuditReportToMarkdown(out);
    expect(md).toContain('# ソース監査の取り込みレポート');
    expect(md).toContain('保存 3 件（新規 3 / 解消 0 / 継続 0）');
    expect(md).toContain('反証されたため保存しなかった指摘（rejected） 1 件');
    expect(md).toContain('形が合わず読めなかった要素 1 件');
    expect(md).toContain('対応づけできなかった指摘 1 件');
    expect(md).toContain('CLIENT-SIDE.md#DOM-based XSS');
    expect(securityAuditReportToJson(out)).toMatchObject({
      kind: 'cyberriskscape-security-audit-import-report',
      product: 'Cloudflare security-audit',
      stored: 3,
      rejected: 1,
      unverified: 1,
      unmapped: 1,
      ledgerGiven: true,
      unmappedClasses: ['CLIENT-SIDE.md#DOM-based XSS'],
    });
  });

  it('台帳なし → その旨を報告する', () => {
    const out = importSecurityAudit(project(), items.items, { importedAt: AT });
    expect(out.ledgerGiven).toBe(false);
    expect(securityAuditReportToMarkdown(out)).toContain('台帳（--ledger）が無い');
  });

  it('プロジェクト JSON が不正 → 例外', () => {
    expect(() => importSecurityAudit({ nope: 1 }, items.items)).toThrow();
  });
});
