import type { RiskScore, Severity } from './types';

/**
 * リスク評価の計算ロジック（[[plan]] §2.34 / §2.45）。
 * Impact（損害 × 影響範囲）と Likelihood（再現性 × 攻撃容易性）の 2 軸へ畳み、
 * OWASP Risk Rating Methodology のマトリクスで Severity を決める。
 *
 * 旧 DREAD（Microsoft）方式は不採用。Microsoft 自身が SDL から引退させており、
 * 特に Discoverability は「発見しにくい＝低リスク」という security through obscurity を
 * スコアに持ち込むため落とした。0–10 のクラシック採点も評価者間のブレが大きく不採用
 * （1–3 の 3 段階は従来どおり＝ユーザー合意済み）。
 */

/** Impact 軸を構成する評価項目（表示順）。 */
export const IMPACT_KEYS = ['damage', 'affectedUsers'] as const;

/** Likelihood 軸を構成する評価項目（表示順）。 */
export const LIKELIHOOD_KEYS = ['reproducibility', 'exploitability'] as const;

/** 全評価項目（フォームの表示順＝Impact 軸 → Likelihood 軸）。 */
export const RISK_KEYS = [...IMPACT_KEYS, ...LIKELIHOOD_KEYS] as const;

export type RiskKey = (typeof RISK_KEYS)[number];

/** マトリクスの軸ラベル（Severity の Critical を除く 3 段階）。 */
export type AxisLevel = 'Low' | 'Medium' | 'High';

/**
 * 2 項目（各 1–3）の和 2–6 を 3 段階へ畳む。
 * 2–3=Low / 4=Medium / 5–6=High。9 通りの入力が 3:3:3 に均等配分される。
 */
function axisLevel(sum: number): AxisLevel {
  if (sum >= 5) return 'High';
  if (sum === 4) return 'Medium';
  return 'Low';
}

/** Impact 軸＝損害の深刻度 × 影響ユーザー範囲。 */
export function impactLevel(score: RiskScore): AxisLevel {
  return axisLevel(score.damage + score.affectedUsers);
}

/** Likelihood 軸＝再現性 × 攻撃容易性。 */
export function likelihoodLevel(score: RiskScore): AxisLevel {
  return axisLevel(score.reproducibility + score.exploitability);
}

/**
 * 重大度マトリクス（Impact × Likelihood）。
 * 出典: OWASP Risk Rating Methodology
 * https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
 * 本ツールの Severity は 4 段階のため、OWASP の Informational（Low×Low）は Low に丸めている。
 */
const RISK_MATRIX: Record<AxisLevel, Record<AxisLevel, Severity>> = {
  High: { Low: 'Medium', Medium: 'High', High: 'Critical' },
  Medium: { Low: 'Low', Medium: 'Medium', High: 'High' },
  Low: { Low: 'Low', Medium: 'Low', High: 'Medium' },
};

/** 2 軸のレベルから Severity を引く。 */
export function riskRank(impact: AxisLevel, likelihood: AxisLevel): Severity {
  return RISK_MATRIX[impact][likelihood];
}

/** 評価スコアから Severity を求める（`riskRank` の入力を組み立てる糖衣）。 */
export function riskSeverity(score: RiskScore): Severity {
  return riskRank(impactLevel(score), likelihoodLevel(score));
}

/**
 * 表示用の実効 severity。評価済みなら評価由来ランクを優先し、
 * 未評価ならルール由来 severity をそのまま使う（ユーザー合意済み＝上書き方式）。
 */
export function effectiveSeverity(t: { severity: Severity; risk?: RiskScore }): Severity {
  return t.risk ? riskSeverity(t.risk) : t.severity;
}
