import { MAX_FINDINGS, type Finding, type Severity } from '../../core/model/types';

/**
 * 外部製品の指摘の取り込みで、形式によらず共通の部品（docs/architecture.md §8.6「共通の口」）。
 * - 取り込み直しの置き換え（製品 × 範囲の単位）
 * - 深刻度の正規化
 * - 上限での切り詰め
 */

export interface FindingsDiff {
  added: number;
  resolved: number;
  continued: number;
}

/**
 * 同じ製品・同じ範囲の指摘を丸ごと置き換える（スナップショット）。他の製品・他の範囲の指摘は触らない。
 * `scope` が undefined なら、範囲を持たない指摘（Prowler 等）だけが対象。
 */
export function replaceFindings(
  existing: readonly Finding[] | undefined,
  incoming: readonly Finding[],
  product: string,
  scope?: string,
): { findings: Finding[]; diff: FindingsDiff } {
  const same = (f: Finding) => f.source.product === product && f.source.scope === scope;
  const prev = (existing ?? []).filter(same);
  const prevIds = new Set(prev.map((f) => f.id));
  const nextIds = new Set(incoming.map((f) => f.id));
  const continued = [...nextIds].filter((id) => prevIds.has(id)).length;
  return {
    findings: [...(existing ?? []).filter((f) => !same(f)), ...incoming],
    diff: { added: nextIds.size - continued, resolved: prevIds.size - continued, continued },
  };
}

/**
 * 製品の深刻度表記を正規化する（大文字小文字は問わない）。
 * OCSF・XCCDF（high/medium/low/info/unknown）・OVAL の勧告（Critical/Important/Moderate/Low）に対応。
 * 不明・情報は Low。
 */
export function normalizeSeverity(raw: string | undefined): Severity {
  switch (raw?.trim().toLowerCase()) {
    case 'critical':
      return 'Critical';
    case 'high':
    case 'important':
      return 'High';
    case 'medium':
    case 'moderate':
      return 'Medium';
    default:
      return 'Low';
  }
}

/** 上限（MAX_FINDINGS）で切り詰め、切った件数を返す。 */
export function capFindings(findings: Finding[]): { findings: Finding[]; truncated: number } {
  const truncated = Math.max(0, findings.length - MAX_FINDINGS);
  return { findings: truncated > 0 ? findings.slice(0, MAX_FINDINGS) : findings, truncated };
}
