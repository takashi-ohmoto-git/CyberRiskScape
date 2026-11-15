import { describe, expect, it } from 'vitest';
import type { Finding } from '../../core/model/types';
import { entraAppsFindingsForThreat } from './matchEntraApps';

const finding = (format: string, nodeId: string, canonicalIds: string[]): Finding =>
  ({
    id: `p:${format}-${nodeId}`,
    source: { product: 'p', format },
    externalId: 'x',
    identifiers: [],
    severity: 'High',
    canonicalIds,
    subject: { layer: 'L1', nodeId },
  }) as unknown as Finding;

describe('entraAppsFindingsForThreat', () => {
  const findings = [
    finding('msgraph', 'idp', ['idp-app-consent']),
    finding('bloodhound', 'idp', ['idp-app-consent']),
    finding('msgraph', 'other', ['idp-app-consent']),
  ];

  it('同じノードで canonicalId が一致する msgraph の指摘だけを返す', () => {
    const r = entraAppsFindingsForThreat(findings, { nodeId: 'idp', canonicalId: 'idp-app-consent' });
    expect(r).toHaveLength(1);
    expect(r[0].source.format).toBe('msgraph');
    expect(entraAppsFindingsForThreat(findings, { nodeId: 'idp', canonicalId: 'other-id' })).toEqual([]);
  });

  it('別のノードの指摘は返さない → 空', () => {
    expect(entraAppsFindingsForThreat(findings, { nodeId: 'none', canonicalId: 'idp-app-consent' })).toEqual([]);
  });

  it('canonicalId が無い脅威 → 空', () => {
    expect(entraAppsFindingsForThreat(findings, { nodeId: 'idp' })).toEqual([]);
  });
});
