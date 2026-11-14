import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { effectiveSeverity } from '../../core/model/risk';
import type { ThreatView } from '../../core/model/types';

/**
 * 脅威モデル単位の指標（docs/org-view.md §4.1）。画面・CLI・Enterprise が同じ関数で同じ数字を出す。
 *
 * - 設定率：対策実装状況が未設定でない脅威の割合
 * - 検討率：リスク対応方針が未設定でない脅威の割合
 * - 実装済みの割合：対策実装状況が「実装済み」の脅威の割合
 *
 * 脅威 1 件の重みは重大度で決める（リスク評価があれば評価後の重大度）。誤検知と、対策実装状況が
 * 適用外の脅威は、分子にも分母にも入れない。設定率と検討率は「検討が済んだ割合」であり、
 * 「リスクが下がった割合」ではない。重みは `data/indicators/weights.yaml`。
 */

const positive = z.number().positive();

const WeightsFileSchema = z.object({
  schemaVersion: z.literal(1),
  severity: z.object({ Critical: positive, High: positive, Medium: positive, Low: positive }),
  indicators: z.object({ controlSet: positive, treatmentSet: positive, implemented: positive }),
});

export type IndicatorWeights = Omit<z.infer<typeof WeightsFileSchema>, 'schemaVersion'>;

export function loadIndicatorWeights(text: string): IndicatorWeights {
  const { severity, indicators } = WeightsFileSchema.parse(parseYaml(text));
  return { severity, indicators };
}

// 同梱データ（Vite の import.meta.glob で raw 文字列として取り込む。CLI ビルド・Vitest でも動く）
const sources = import.meta.glob<string>('../../../data/indicators/weights.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const BUNDLED_INDICATOR_WEIGHTS: IndicatorWeights = loadIndicatorWeights(
  Object.values(sources)[0] ?? '',
);

export interface ModelIndicators {
  /** 渡された脅威の件数。 */
  total: number;
  /** 指標の対象から外した件数（誤検知・適用外）。 */
  excluded: number;
  /** 指標の対象の件数（`total - excluded`）。 */
  inScope: number;
  /** 対象のうち、それぞれに当てはまる件数（重みなし。内訳の表示用）。 */
  counts: { controlSet: number; treatmentSet: number; implemented: number };
  /** 以下は 0〜1 の重み付きの割合。対象が 0 件なら null（0% とも 100% ともしない）。 */
  controlSetRate: number | null;
  treatmentSetRate: number | null;
  implementedRate: number | null;
  /** 脅威モデルの値：3 つの指標の重み付きの平均。対象が 0 件なら null。 */
  value: number | null;
}

type IndicatorThreat = Pick<ThreatView, 'severity' | 'risk' | 'suppression' | 'controlStatus'>;

export function computeIndicators(
  threats: readonly IndicatorThreat[],
  weights: IndicatorWeights = BUNDLED_INDICATOR_WEIGHTS,
): ModelIndicators {
  const counts = { controlSet: 0, treatmentSet: 0, implemented: 0 };
  const sums = { controlSet: 0, treatmentSet: 0, implemented: 0 };
  let inScope = 0;
  let denominator = 0;

  for (const t of threats) {
    if (t.suppression?.status === 'false-positive' || t.controlStatus?.status === 'not-applicable') continue;
    const w = weights.severity[effectiveSeverity(t)];
    inScope += 1;
    denominator += w;
    if (t.controlStatus) {
      counts.controlSet += 1;
      sums.controlSet += w;
    }
    if (t.suppression) {
      counts.treatmentSet += 1;
      sums.treatmentSet += w;
    }
    if (t.controlStatus?.status === 'implemented') {
      counts.implemented += 1;
      sums.implemented += w;
    }
  }

  const base = { total: threats.length, excluded: threats.length - inScope, inScope, counts };
  if (inScope === 0) {
    return { ...base, controlSetRate: null, treatmentSetRate: null, implementedRate: null, value: null };
  }
  const controlSetRate = sums.controlSet / denominator;
  const treatmentSetRate = sums.treatmentSet / denominator;
  const implementedRate = sums.implemented / denominator;
  const iw = weights.indicators;
  const value =
    (controlSetRate * iw.controlSet + treatmentSetRate * iw.treatmentSet + implementedRate * iw.implemented) /
    (iw.controlSet + iw.treatmentSet + iw.implemented);
  return { ...base, controlSetRate, treatmentSetRate, implementedRate, value };
}

/** 割合を「42%」の形にする。null（対象なし）は「—」。 */
export function formatRate(rate: number | null): string {
  return rate === null ? '—' : `${Math.round(rate * 100)}%`;
}
