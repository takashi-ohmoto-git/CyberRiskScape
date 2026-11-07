import type { Finding, LayerData, Severity } from '../../core/model/types';
import { compareConditions, type ConditionComparisonResult } from './compareConditions';

/**
 * ノード詳細パネルの「ソース監査の指摘」欄の表示用データを作る純粋関数（docs/architecture.md §8.9）。
 */

export interface AuditRow {
  id: string;
  title: string;
  /** 要確認は重大度を持たない（severity は表示しない）。 */
  status: 'confirmed' | 'unverified';
  severity: Severity;
  resourceLabel?: string;
  /** 脅威カードに対応づけられている（canonicalIds がある）。 */
  mapped: boolean;
  comparison: ConditionComparisonResult;
  validationPlan?: string;
}

export function buildAuditRows(findings: readonly Finding[], nodeId: string, layer: LayerData | undefined): AuditRow[] {
  return findings
    .filter((f) => f.source.format === 'security-audit' && f.subject?.nodeId === nodeId)
    .map((f) => ({
      id: f.id,
      title: f.title ?? f.externalId,
      status: f.outcome === 'unverified' ? ('unverified' as const) : ('confirmed' as const),
      severity: f.severity,
      ...(f.resource?.label ? { resourceLabel: f.resource.label } : {}),
      mapped: f.canonicalIds.length > 0,
      comparison: compareConditions(f, layer),
      ...(f.validationPlan ? { validationPlan: f.validationPlan } : {}),
    }));
}
