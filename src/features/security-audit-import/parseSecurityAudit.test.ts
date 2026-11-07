import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseCoverageLedger, parseSecurityAudit } from './parseSecurityAudit';

const read = (name: string): unknown => JSON.parse(readFileSync(new URL(`./__fixtures__/${name}`, import.meta.url), 'utf-8'));

describe('parseSecurityAudit', () => {
  it('配列でない入力 → 拒否する', () => {
    expect(parseSecurityAudit({ findings: [] }).ok).toBe(false);
    expect(parseSecurityAudit('x').ok).toBe(false);
  });

  it('3 種の判定を読み、形が合わない要素は数えて捨てる', () => {
    const r = parseSecurityAudit(read('findings.json'));
    if (!r.ok) throw new Error(r.error);
    expect(r.items.map((i) => i.verdict)).toEqual(['confirmed', 'confirmed', 'needs_validation', 'rejected']);
    expect(r.invalid).toBe(1);
  });

  it('未知のキーと、読まない項目（payloads・修正コード・本文）は結果に残らない', () => {
    const r = parseSecurityAudit(read('findings.json'));
    const text = JSON.stringify(r);
    for (const w of ['PAYLOAD-SECRET', 'FIXED-CODE-SECRET', 'EVIDENCE-TEXT', 'ROOTCAUSE-TEXT', 'unknown_extra_key', 'LOCAL-PLAN-SECRET']) {
      expect(text).not.toContain(w);
    }
  });

  it('指紋が規約に合わない要素 → 捨てる', () => {
    const r = parseSecurityAudit([{ verdict: 'rejected', fingerprint: '../etc/passwd' }, { verdict: 'rejected', fingerprint: 'ok-1' }]);
    expect(r).toMatchObject({ ok: true, invalid: 1 });
  });
});

describe('parseCoverageLedger', () => {
  it('単位の攻撃クラスと指紋を読み、単位でない要素は読み飛ばす', () => {
    const r = parseCoverageLedger(read('coverage-ledger.json'));
    if (!r.ok) throw new Error(r.error);
    expect(r.units).toHaveLength(4);
    expect(r.units[0]).toEqual({ attackClass: 'ATTACK-CLASSES.md#Access control', fingerprints: ['fp-authz-001'] });
    expect(r.units[3]).toEqual({ fingerprints: [] });
  });

  it('配列でない入力 → 拒否する', () => {
    expect(parseCoverageLedger({}).ok).toBe(false);
  });
});
