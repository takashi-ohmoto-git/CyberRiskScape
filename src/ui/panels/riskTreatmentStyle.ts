import type { SuppressionStatus } from '../../core/model/types';
import type { TranslationKey } from '../../i18n';

/**
 * リスク対応方針（Risk Treatment）のラベルとバッジ class。
 * 内部の型名は後方互換のため `SuppressionStatus` のまま。
 * 受容 / 誤検知 のみ「抑制」（淡色化・件数/バッジ除外）扱い、
 * 回避 / 低減 / 移転 は「対応中」として表示・カウントを維持する。
 * ThreatCard と AnalyticsModal で共用する。
 *
 * ラベルはモジュールレベル定数（フック不可）のため i18n キーで保持し、
 * 表示側で `t(RISK_TREATMENT_LABEL_KEY[status])` として解決する。
 */
export const RISK_TREATMENT_LABEL_KEY: Record<SuppressionStatus, TranslationKey> = {
  avoid: 'threats.riskTreatment.avoid',
  reduce: 'threats.riskTreatment.reduce',
  transfer: 'threats.riskTreatment.transfer',
  accepted: 'threats.riskTreatment.accepted',
  'false-positive': 'threats.riskTreatment.falsePositive',
};

export const RISK_TREATMENT_BADGE: Record<SuppressionStatus, string> = {
  avoid: 'bg-teal-500/15 text-teal-300 border-teal-500/40',
  reduce: 'bg-sky-500/15 text-sky-300 border-sky-500/40',
  transfer: 'bg-violet-500/15 text-violet-300 border-violet-500/40',
  accepted: 'bg-slate-500/15 text-slate-300 border-slate-500/40',
  'false-positive': 'bg-amber-500/15 text-amber-300 border-amber-500/40',
};

/** セレクタ表示順：回避→低減→移転→受容→誤検知。 */
export const RISK_TREATMENT_ORDER: SuppressionStatus[] = [
  'avoid',
  'reduce',
  'transfer',
  'accepted',
  'false-positive',
];
