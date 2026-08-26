import type { ControlStatusValue } from '../../core/model/types';

/**
 * 対策実装状況（Control Implementation Status）のラベルとバッジ class。
 * リスク対応方針（suppression）・重大度色（severityColors）とは別レイヤーのため、
 * トーンを意図的に分けている。ThreatCard と AnalyticsModal で共用する。
 */
export const CONTROL_STATUS_LABEL: Record<ControlStatusValue, string> = {
  implemented: '実装済み',
  required: '必須',
  'not-applicable': '適用外',
  rejected: '拒否',
};

export const CONTROL_STATUS_BADGE: Record<ControlStatusValue, string> = {
  implemented: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40',
  required: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
  'not-applicable': 'bg-slate-500/15 text-slate-300 border-slate-500/40',
  rejected: 'bg-rose-500/15 text-rose-300 border-rose-500/40',
};

/** note 必須のステータス（空欄では保存させない）。required のみ note 任意。 */
export const CONTROL_STATUS_NOTE_REQUIRED: Record<ControlStatusValue, boolean> = {
  implemented: true,
  required: false,
  'not-applicable': true,
  rejected: true,
};

/** 4 ステータスの表示順（セレクタ・凡例用）。 */
export const CONTROL_STATUS_ORDER: ControlStatusValue[] = [
  'implemented',
  'required',
  'not-applicable',
  'rejected',
];
