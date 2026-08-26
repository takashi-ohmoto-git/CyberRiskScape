import type { DreadScore, Severity } from './types';

/**
 * DREAD 評価の計算ロジック（[[plan]] §2.34）。
 * 各項目 1–3 の 3 段階で評価し、合計 5–15 を Severity へマッピングする。
 * （0–10 のクラシック方式は評価者間のブレが大きいため不採用＝ユーザー合意済み）
 */

/** DREAD の評価項目キー（表示順）。 */
export const DREAD_KEYS = [
  'damage',
  'reproducibility',
  'exploitability',
  'affectedUsers',
  'discoverability',
] as const;

export type DreadKey = (typeof DREAD_KEYS)[number];

/** 5 項目の合計スコア（5–15）。 */
export function dreadTotal(score: DreadScore): number {
  return DREAD_KEYS.reduce((acc, k) => acc + score[k], 0);
}

/** 合計スコア（5–15）を Severity へマッピングする。 */
export function dreadRank(total: number): Severity {
  if (total >= 13) return 'Critical';
  if (total >= 11) return 'High';
  if (total >= 8) return 'Medium';
  return 'Low';
}

/**
 * 表示用の実効 severity。DREAD 評価済みなら評価由来ランクを優先し、
 * 未評価ならルール由来 severity をそのまま使う（ユーザー合意済み＝上書き方式）。
 */
export function effectiveSeverity(t: { severity: Severity; dread?: DreadScore }): Severity {
  return t.dread ? dreadRank(dreadTotal(t.dread)) : t.severity;
}
