import { describe, expect, it } from 'vitest';
import type { Finding } from '../../core/model/types';
import { securityAuditFindingsForThreat } from './matchSecurityAudit';
import { buildAuditRows } from './auditRows';

function f(over: Partial<Finding> & { format?: 'security-audit' | 'pentest' } = {}): Finding {
  const { format = 'security-audit', ...rest } = over;
  return {
    id: 'x:1',
    source: { product: 'x', format },
    externalId: '1',
    identifiers: [],
    severity: 'High',
    canonicalIds: ['idor'],
    subject: { layer: 'L1', nodeId: 'n1' },
    ...rest,
  } as Finding;
}

describe('securityAuditFindingsForThreat', () => {
  it('同じノード・同じ canonicalId の security-audit だけ返す', () => {
    const t = { nodeId: 'n1', canonicalId: 'idor' };
    expect(securityAuditFindingsForThreat([f()], t)).toHaveLength(1);
    expect(securityAuditFindingsForThreat([f({ format: 'pentest' })], t)).toHaveLength(0);
    expect(securityAuditFindingsForThreat([f({ subject: { layer: 'L1', nodeId: 'n2' } })], t)).toHaveLength(0);
    expect(securityAuditFindingsForThreat([f({ canonicalIds: ['other'] })], t)).toHaveLength(0);
    expect(securityAuditFindingsForThreat([f()], { nodeId: 'n1' })).toHaveLength(0);
  });
});

describe('buildAuditRows', () => {
  it('ノードの security-audit だけを行にし、unverified と未対応づけを区別する', () => {
    const rows = buildAuditRows(
      [f({ id: 'a' }), f({ id: 'b', outcome: 'unverified', canonicalIds: [] }), f({ id: 'c', format: 'pentest' }), f({ id: 'd', subject: { layer: 'L1', nodeId: 'z' } })],
      'n1',
      undefined,
    );
    expect(rows.map((r) => [r.id, r.status, r.mapped])).toEqual([
      ['a', 'confirmed', true],
      ['b', 'unverified', false],
    ]);
  });
});
