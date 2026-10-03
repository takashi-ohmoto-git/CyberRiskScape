import type { ControlStatusValue, LayerKey, Severity, SuppressionStatus, ThreatView } from '../../../core/model/types';
import { isSuppressed } from '../../../core/model/types';
import type { AxisLevel } from '../../../core/model/risk';
import type { ThreatReportRow } from '../threatReport';

/**
 * PDF の経営層向けサマリ用の純関数（ランキング・集計・緩和策整形）。
 * 抑制状態・対策実装状況・リスク評価は `ThreatView` の生値から取る（訳語の文字列照合はしない）。
 */

/** 対応方針の生値。抑制注記が無ければ未対応。 */
export type Treatment = 'unaddressed' | SuppressionStatus;

export const TREATMENTS: readonly Treatment[] = [
  'unaddressed',
  'avoid',
  'reduce',
  'transfer',
  'accepted',
  'false-positive',
];

export const SEVERITY_ORDER: readonly Severity[] = ['Critical', 'High', 'Medium', 'Low'];

export interface SummaryItem {
  layer: LayerKey;
  /** レイヤー内の元の並び（タイブレーク用）。 */
  index: number;
  row: ThreatReportRow;
  severity: Severity;
  /** 未評価は ''。 */
  impact: AxisLevel | '';
  likelihood: AxisLevel | '';
  treatment: Treatment;
  /** 未設定は undefined。 */
  control: ControlStatusValue | undefined;
}

/** ThreatView が引けないときは「未対応・未設定・行の値」で扱う。 */
export function toSummaryItem(
  layer: LayerKey,
  index: number,
  row: ThreatReportRow,
  view: ThreatView | undefined,
): SummaryItem {
  return {
    layer,
    index,
    row,
    severity: row.effectiveSeverity,
    impact: row.impact,
    likelihood: row.likelihood,
    treatment: view?.suppression?.status ?? 'unaddressed',
    control: view?.controlStatus?.status,
  };
}

/** 受容・誤検知（抑制）か。`isSuppressed` と同じ判定。 */
export function isSuppressedItem(i: SummaryItem): boolean {
  return isSuppressed({ suppression: i.treatment === 'unaddressed' ? undefined : { status: i.treatment, at: 0 } });
}

const SEV_RANK: Record<Severity, number> = { Critical: 3, High: 2, Medium: 1, Low: 0 };
const AXIS_RANK: Record<AxisLevel | '', number> = { High: 2, Medium: 1, Low: 0, '': -1 };

/** 順位：実効深刻度 → Impact → Likelihood（未評価は最下位）→ 未対応を優先 → 元の並び（レイヤー順、行順）。 */
function compareItems(layerOrder: readonly LayerKey[]) {
  return (a: SummaryItem, b: SummaryItem): number =>
    SEV_RANK[b.severity] - SEV_RANK[a.severity] ||
    AXIS_RANK[b.impact] - AXIS_RANK[a.impact] ||
    AXIS_RANK[b.likelihood] - AXIS_RANK[a.likelihood] ||
    Number(a.treatment !== 'unaddressed') - Number(b.treatment !== 'unaddressed') ||
    layerOrder.indexOf(a.layer) - layerOrder.indexOf(b.layer) ||
    a.index - b.index;
}

/** 受容・誤検知を除いた全レイヤー横断の上位 `limit` 件（既定 10）。 */
export function rankThreats(items: readonly SummaryItem[], layerOrder: readonly LayerKey[], limit = 10): SummaryItem[] {
  return items
    .filter((i) => !isSuppressedItem(i))
    .sort(compareItems(layerOrder))
    .slice(0, limit);
}

export interface Progress {
  implemented: number;
  /** 分母：有効脅威から対象外を除いた数。 */
  total: number;
}

/** 実装済み ÷（有効脅威 − 対象外）。未設定・要対応・却下は未実装として分母に入る。 */
export function computeProgress(active: readonly SummaryItem[]): Progress {
  const counted = active.filter((i) => i.control !== 'not-applicable');
  return { implemented: counted.filter((i) => i.control === 'implemented').length, total: counted.length };
}

/** 分母 0 は「—」。 */
export function formatProgress(p: Progress): string {
  return p.total === 0 ? '—' : `${Math.round((p.implemented / p.total) * 100)}%`;
}

export type ControlBucket = ControlStatusValue | 'unset';
export const CONTROL_BUCKETS: readonly ControlBucket[] = ['implemented', 'required', 'rejected', 'not-applicable', 'unset'];

export interface PdfSummary {
  activeCount: number;
  criticalHighCount: number;
  unaddressedCount: number;
  progressAll: Progress;
  progressCriticalHigh: Progress;
  /** 対応方針別の件数（受容・誤検知も含む全脅威）。 */
  treatmentCounts: Record<Treatment, number>;
  /** 対策実装状況別の件数（有効脅威のみ）。 */
  controlCounts: Record<ControlBucket, number>;
  /** レイヤー別・深刻度別の有効脅威数と、受容・誤検知の数。 */
  byLayer: { layer: LayerKey; severity: Record<Severity, number>; active: number; suppressed: number }[];
}

export function computeSummary(items: readonly SummaryItem[], layers: readonly LayerKey[]): PdfSummary {
  const active = items.filter((i) => !isSuppressedItem(i));
  const critHigh = active.filter((i) => i.severity === 'Critical' || i.severity === 'High');
  const treatmentCounts = Object.fromEntries(TREATMENTS.map((t) => [t, 0])) as Record<Treatment, number>;
  for (const i of items) treatmentCounts[i.treatment] += 1;
  const controlCounts = Object.fromEntries(CONTROL_BUCKETS.map((b) => [b, 0])) as Record<ControlBucket, number>;
  for (const i of active) controlCounts[i.control ?? 'unset'] += 1;
  return {
    activeCount: active.length,
    criticalHighCount: critHigh.length,
    unaddressedCount: active.filter((i) => i.treatment === 'unaddressed').length,
    progressAll: computeProgress(active),
    progressCriticalHigh: computeProgress(critHigh),
    treatmentCounts,
    controlCounts,
    byLayer: layers.map((layer) => {
      const inLayer = items.filter((i) => i.layer === layer);
      const act = inLayer.filter((i) => !isSuppressedItem(i));
      return {
        layer,
        severity: Object.fromEntries(
          SEVERITY_ORDER.map((s) => [s, act.filter((i) => i.severity === s).length]),
        ) as Record<Severity, number>,
        active: act.length,
        suppressed: inLayer.length - act.length,
      };
    }),
  };
}

// ── 緩和策の整形 ──

const TIER_TAG_RE = /\[(?:Foundation|Enterprise|Advanced)\]\s*/g;

/** 生の tier タグ（`[Foundation]` 等）を除去する。 */
export function stripTierTags(text: string): string {
  return text.replace(TIER_TAG_RE, '').trim();
}

export interface MitigationLine {
  tier: 'Foundation' | 'Enterprise' | 'Advanced';
  text: string;
}

/** `mitigationTiers` を段階ごとの行にする。無ければ空配列。 */
export function mitigationLines(row: ThreatReportRow): MitigationLine[] {
  const t = row.mitigationTiers;
  if (!t) return [];
  const out: MitigationLine[] = [];
  if (t.foundation) out.push({ tier: 'Foundation', text: stripTierTags(t.foundation) });
  if (t.enterprise) out.push({ tier: 'Enterprise', text: stripTierTags(t.enterprise) });
  if (t.advanced) out.push({ tier: 'Advanced', text: stripTierTags(t.advanced) });
  return out;
}

/** 「まず着手すべき対策」：Foundation の文。実装済みの脅威には出さない。 */
export function firstStep(row: ThreatReportRow, control: ControlStatusValue | undefined): string {
  if (control === 'implemented') return '';
  return row.mitigationTiers?.foundation ? stripTierTags(row.mitigationTiers.foundation) : '';
}
