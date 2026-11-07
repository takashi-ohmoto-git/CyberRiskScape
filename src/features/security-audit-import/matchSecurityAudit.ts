import type { Finding, ThreatView } from '../../core/model/types';

/**
 * ソース監査（security-audit）の指摘と脅威カードの突き合わせ（カードの「ソース監査で実証／要確認」表示用）。
 * ペンテストの findingsForThreat とは別（形式 'security-audit' だけを見る）。純粋関数。
 */
export function securityAuditFindingsForThreat(
  findings: readonly Finding[],
  threat: Pick<ThreatView, 'nodeId' | 'canonicalId'>,
): Finding[] {
  if (threat.canonicalId === undefined) return [];
  const id = threat.canonicalId;
  return findings.filter(
    (f) => f.source.format === 'security-audit' && f.subject?.nodeId === threat.nodeId && f.canonicalIds.includes(id),
  );
}
