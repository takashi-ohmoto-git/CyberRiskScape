import { isSuppressed, type Severity, type ThreatView } from '../../core/model/types';

const SEVERITY_ORDER: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };

/**
 * 重大度の高い順（Critical → High → Medium → Low）に並べる。
 * 受容・誤検知で抑制した脅威はアクティブ件数に数えないため末尾へ回す。同順位は元の順を保つ。
 */
export function sortThreatsBySeverity(threats: readonly ThreatView[]): ThreatView[] {
  return [...threats].sort(
    (a, b) =>
      Number(isSuppressed(a)) - Number(isSuppressed(b)) ||
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
}
