import type {
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  ElementKind,
  Severity,
  ThreatView,
} from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';
import { effectiveSeverity } from '../../core/model/dread';

/**
 * Analytics の ElementalID 単位リスト構築（[[plan]] §2.26 Step 5）。
 *
 * `ThreatView.subject` を正準キーに、アクティブレイヤーの全要素（node / edge /
 * boundary）へ脅威を集約する純粋関数。表示ラベルの解決（registry 依存）は UI 層に委ね、
 * ここは構造・集約・最大 severity の算出のみを担う（テスタビリティのため）。
 */

const SEVERITY_RANK: Record<Severity, number> = { Low: 1, Medium: 2, High: 3, Critical: 4 };

export interface ElementAnalyticsRow {
  kind: ElementKind;
  /** 要素の内部 ID（不変キー）。 */
  id: string;
  /** 採番（旧データ等で未設定の可能性あり）。 */
  seq?: number;
  /** 表示用 ElementalID（`C1` / `DF1` / `Z1`）。seq 欠落時は内部 ID にフォールバック。 */
  elementalId: string;
  /** この要素に紐づく脅威（検出 + 手動）。 */
  threats: ThreatView[];
  /** 紐づく脅威の最大実効 severity（DREAD 評価済みは評価由来ランク優先）。脅威ゼロなら null。 */
  maxSeverity: Severity | null;
}

export interface ElementAnalytics {
  rows: ElementAnalyticsRow[];
  /** どの要素にも紐づかない脅威（subject 未設定の全体スコープ手動脅威 / 不在要素参照）。 */
  unassigned: ThreatView[];
}

export interface BuildElementAnalyticsInput {
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  boundaries: DiagramBoundary[];
  /** アクティブレイヤー + アクティブ framework で構築済みの脅威ビュー。 */
  threats: ThreatView[];
}

function maxSeverityOf(threats: ThreatView[]): Severity | null {
  let max: Severity | null = null;
  for (const t of threats) {
    const sev = effectiveSeverity(t);
    if (max === null || SEVERITY_RANK[sev] > SEVERITY_RANK[max]) max = sev;
  }
  return max;
}

export function buildElementAnalytics({
  nodes,
  edges,
  boundaries,
  threats,
}: BuildElementAnalyticsInput): ElementAnalytics {
  // 実在する要素のキー集合（subject が不在要素を指す場合は unassigned へ）。
  const validKeys = new Set<string>();
  for (const n of nodes) validKeys.add(`node:${n.id}`);
  for (const e of edges) validKeys.add(`edge:${e.id}`);
  for (const b of boundaries) validKeys.add(`boundary:${b.id}`);

  const byKey = new Map<string, ThreatView[]>();
  const unassigned: ThreatView[] = [];
  for (const t of threats) {
    const key = t.subject ? `${t.subject.kind}:${t.subject.id}` : null;
    if (key && validKeys.has(key)) {
      const arr = byKey.get(key);
      if (arr) arr.push(t);
      else byKey.set(key, [t]);
    } else {
      unassigned.push(t);
    }
  }

  const rows: ElementAnalyticsRow[] = [];
  const pushRow = (kind: ElementKind, id: string, seq?: number) => {
    const ts = byKey.get(`${kind}:${id}`) ?? [];
    rows.push({
      kind,
      id,
      seq,
      elementalId: seq != null ? formatElementalId(kind, seq) : id,
      threats: ts,
      maxSeverity: maxSeverityOf(ts),
    });
  };
  // ElementalID の並び（C… → DF… → Z…）に揃えて要素順に出力する。
  for (const n of nodes) pushRow('node', n.id, n.seq);
  for (const e of edges) pushRow('edge', e.id, e.seq);
  for (const b of boundaries) pushRow('boundary', b.id, b.seq);

  return { rows, unassigned };
}
