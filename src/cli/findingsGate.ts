import { isSuppressed, type Finding, type Severity } from '../core/model/types';
import { SEVERITY_RANK, type LayerAnalysisResult } from './analyze';
import { linkFindingToThreats } from './sarif';

/**
 * 保存済み指摘のゲート判定（CLI の `analyze --fail-on-findings`）。
 * 重大度が `failOn` 以上の指摘を返す。ただし次は数えない。
 * - 試行のみで未実証の指摘（outcome === 'attempted'）
 * - 受容済み：結び付く脅威が 1 件以上あり、そのすべてが抑制（受容・誤検知）されている指摘
 *   結び付く脅威が無い指摘（未結合・ノード消失を含む）は受容できないので数える。
 */
export function evaluateSavedFindingsGate(
  findings: readonly Finding[],
  results: readonly LayerAnalysisResult[],
  failOn: Severity,
): Finding[] {
  const threshold = SEVERITY_RANK[failOn];
  return findings.filter((f) => {
    if (f.outcome === 'attempted') return false;
    if (SEVERITY_RANK[f.severity] < threshold) return false;
    const threats = linkFindingToThreats(f, results)?.threats ?? [];
    return !(threats.length > 0 && threats.every(isSuppressed));
  });
}

/** ゲート不合格の指摘 1 件の表示行（重大度・製品・タイトル（無ければ識別子）・ノード）。 */
export function formatGateFinding(f: Finding, results: readonly LayerAnalysisResult[]): string {
  const title = f.title ?? f.identifiers[0]?.value ?? f.id;
  const node = linkFindingToThreats(f, results)?.node;
  const nodeText = node ? ` @ ${node.label?.trim() || node.type}` : '';
  return `[${f.severity}] ${f.source.product}: ${title}${nodeText}`;
}
