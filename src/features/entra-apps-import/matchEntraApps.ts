import type { Finding, ThreatView } from '../../core/model/types';

/**
 * Microsoft Graph（Entra ID の外部アプリ・同意）の指摘と脅威カードの突き合わせ（カードの「Entra の設定で確認」の印用）。
 * 同じノードで、脅威の canonicalId が指摘の canonicalIds に含まれるもの。
 * DOM にも Node にも依存しない純粋関数。
 */
export function entraAppsFindingsForThreat(
  findings: readonly Finding[],
  threat: Pick<ThreatView, 'nodeId' | 'canonicalId'>,
): Finding[] {
  if (threat.canonicalId === undefined) return [];
  return findings.filter(
    (f) => f.source.format === 'msgraph' && f.subject?.nodeId === threat.nodeId && f.canonicalIds.includes(threat.canonicalId!),
  );
}
