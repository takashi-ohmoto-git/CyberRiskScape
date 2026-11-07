import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { MAX_FINDINGS } from '../../core/model/types';
import { BUNDLED_SECURITY_AUDIT_MAP } from '../findings-report/findingMap';
import { parseCoverageLedger, parseSecurityAudit, type AuditItem } from './parseSecurityAudit';
import { SECURITY_AUDIT_PRODUCT, securityAuditToFindings } from './securityAuditToFindings';

const read = (name: string): unknown => JSON.parse(readFileSync(new URL(`./__fixtures__/${name}`, import.meta.url), 'utf-8'));
const audit = (() => {
  const r = parseSecurityAudit(read('findings.json'));
  if (!r.ok) throw new Error(r.error);
  return r.items;
})();
const ledger = (() => {
  const r = parseCoverageLedger(read('coverage-ledger.json'));
  if (!r.ok) throw new Error(r.error);
  return r.units;
})();
const AT = '2026-11-07T00:00:00.000Z';
const convert = (withLedger = true) =>
  securityAuditToFindings({ items: audit, ...(withLedger ? { ledger } : {}), map: BUNDLED_SECURITY_AUDIT_MAP, scope: 'repo-a', importedAt: AT });
const byFp = <T extends { externalId: string }>(fs: T[], fp: string): T | undefined => fs.find((f) => f.externalId === `repo-a:${fp}`);

describe('securityAuditToFindings', () => {
  it('confirmed → outcome なし・重大度は overall_severity・元の表記を保持', () => {
    const f = byFp(convert().findings, 'fp-authz-001') as ReturnType<typeof convert>['findings'][number];
    expect(f).toMatchObject({
      id: `${SECURITY_AUDIT_PRODUCT}:repo-a:fp-authz-001`,
      source: { format: 'security-audit', product: 'Cloudflare security-audit', scope: 'repo-a', importedAt: AT },
      severity: 'High',
      sourceSeverity: 'high',
      title: 'Order lookup does not check the owner',
    });
    expect(f.outcome).toBeUndefined();
    expect(f.validationPlan).toBeUndefined();
    expect(byFp(convert().findings, 'fp-dom-002')).toMatchObject({ severity: 'Low', sourceSeverity: 'informational' });
  });

  it('needs_validation → unverified・sourceSeverity なし・blockers は 5 件まで・deployment の手順だけ持つ', () => {
    const f = byFp(convert().findings, 'fp-nv-003') as ReturnType<typeof convert>['findings'][number];
    expect(f.outcome).toBe('unverified');
    expect(f.severity).toBe('Low');
    expect('sourceSeverity' in f).toBe(false);
    expect(f.openQuestions).toHaveLength(5);
    expect(f.openQuestions?.[0]).toContain('deployed model');
    expect(f.validationPlan).toContain('staging assistant');
    expect(f.validationPlan).not.toContain('LOCAL-PLAN');
  });

  it('rejected → 保存せず件数だけ数える', () => {
    const c = convert();
    expect(c.findings.map((f) => f.externalId)).toEqual(['repo-a:fp-authz-001', 'repo-a:fp-dom-002', 'repo-a:fp-nv-003']);
    expect(c.report).toMatchObject({ confirmed: 2, unverified: 1, rejected: 1, unmapped: 1, overLimit: 0, duplicates: 0 });
    expect(JSON.stringify(c.findings)).not.toContain('REJECTED-TITLE-SECRET');
  });

  it('conditions の種類を CRS の語彙に変換し、元の種類を残す', () => {
    const f = byFp(convert().findings, 'fp-authz-001') as ReturnType<typeof convert>['findings'][number];
    expect(f.conditions?.map((c) => [c.kind, c.sourceKind])).toEqual([
      ['reachability', 'network_routing'],
      ['authentication', 'authentication_level'],
      ['authorization', 'authorization_role'],
      ['configuration', 'system_configuration'],
      ['user-interaction', 'user_interaction'],
      ['other', 'timing_dependency'],
    ]);
  });

  it('conditions は 10 件、各文は 200 文字まで', () => {
    const many: AuditItem = {
      verdict: 'confirmed',
      fingerprint: 'fp-many',
      title: 't'.repeat(500),
      trace: [],
      conditions: Array.from({ length: 15 }, () => ({ kind: 'data_state', description: 'x'.repeat(500) })),
      severity: { overall_severity: 'medium' },
    };
    const f = securityAuditToFindings({ items: [many], map: [], scope: 's', importedAt: AT }).findings[0];
    expect(f.conditions).toHaveLength(10);
    expect(f.conditions?.every((c) => c.text.length === 200)).toBe(true);
    expect(f.title).toHaveLength(200);
  });

  it('台帳 → 指紋に攻撃クラスの識別子と canonicalId を付ける（複数の単位は和集合）', () => {
    const fs = convert().findings;
    const a = byFp(fs, 'fp-authz-001') as (typeof fs)[number];
    expect(a.identifiers).toEqual([
      { scheme: 'security-audit-fingerprint', value: 'fp-authz-001' },
      { scheme: 'security-audit-attack-class', value: 'ATTACK-CLASSES.md#Access control' },
      { scheme: 'security-audit-attack-class', value: 'AI-AND-LLM.md#Indirect injection through retrieved or ingested content' },
    ]);
    expect(a.canonicalIds).toEqual(expect.arrayContaining(['api-object-level-authorization', 'indirect-prompt-injection']));
    // 表に載っていない型（XSS）は識別子だけ残り、canonicalId は付かない
    const dom = byFp(fs, 'fp-dom-002') as (typeof fs)[number];
    expect(dom.canonicalIds).toEqual([]);
    expect(dom.identifiers).toContainEqual({ scheme: 'security-audit-attack-class', value: 'CLIENT-SIDE.md#DOM-based XSS' });
  });

  it('台帳が無い → 指紋の識別子だけ・canonicalId なし（対応づけできない指摘に数える）', () => {
    const c = convert(false);
    expect(c.findings.every((f) => f.canonicalIds.length === 0 && f.identifiers.length === 1)).toBe(true);
    expect(c.report.unmapped).toBe(3);
  });

  it('resource.label は entrypoint の場所で、ドライブとユーザー名を持ち帰らない', () => {
    const f = byFp(convert().findings, 'fp-authz-001') as ReturnType<typeof convert>['findings'][number];
    expect(f.resource?.label).toBe('repo/src/api/orders.ts:42');
    expect(JSON.stringify(convert().findings)).not.toContain('alice');
    // entrypoint が無ければ先頭
    expect(byFp(convert().findings, 'fp-dom-002')?.resource?.label).toBe('web/app.js:3');
  });

  it('payloads・修正コード・証拠・原因・trace の説明は出力に現れない', () => {
    const text = JSON.stringify(convert());
    for (const w of [
      'PAYLOAD-SECRET',
      'FIXED-CODE-SECRET',
      'REMEDIATION-STRATEGY',
      'EVIDENCE-TEXT',
      'ROOTCAUSE-TEXT',
      'INTENDED-TEXT',
      'TRACE-DESC-TEXT',
      'ATTACKER-TEXT',
      'OBSERVED-TEXT',
      'LIKELIHOOD-REASON',
      'CONFIDENCE-REASON',
      'CLAIMED-ROOTCAUSE',
      'LOCAL-PLAN-SECRET',
    ]) {
      expect(text, w).not.toContain(w);
    }
  });

  it('指紋の重複は 1 件にまとめて数える', () => {
    const c = securityAuditToFindings({ items: [...audit, audit[0]], map: [], scope: 's', importedAt: AT });
    expect(c.report.duplicates).toBe(1);
    expect(c.findings).toHaveLength(3);
  });

  it('上限（MAX_FINDINGS）を超えた分は保存せず数える', () => {
    const items: AuditItem[] = Array.from({ length: MAX_FINDINGS + 3 }, (_, i) => ({ verdict: 'rejected' as const, fingerprint: `r${i}` }));
    const confirmed: AuditItem[] = Array.from({ length: MAX_FINDINGS + 3 }, (_, i) => ({
      verdict: 'confirmed' as const,
      fingerprint: `c${i}`,
      title: 't',
      trace: [],
      conditions: [],
    }));
    const c = securityAuditToFindings({ items: [...items, ...confirmed], map: [], scope: 's', importedAt: AT });
    expect(c.findings).toHaveLength(MAX_FINDINGS);
    expect(c.report).toMatchObject({ overLimit: 3, rejected: MAX_FINDINGS + 3 });
  });

  it('重大度が未知の表記・欠落 → Low', () => {
    const odd: AuditItem = { verdict: 'confirmed', fingerprint: 'odd', title: 't', trace: [], conditions: [], severity: { overall_severity: 'catastrophic' } };
    const none: AuditItem = { verdict: 'confirmed', fingerprint: 'none', title: 't', trace: [], conditions: [] };
    const fs = securityAuditToFindings({ items: [odd, none], map: [], scope: 's', importedAt: AT }).findings;
    expect(fs.map((f) => f.severity)).toEqual(['Low', 'Low']);
    expect(fs[1].sourceSeverity).toBeUndefined();
  });
});
