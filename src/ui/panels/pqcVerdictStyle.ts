import { HelpCircle, Hourglass, LockOpen, ShieldAlert, ShieldCheck, type LucideIcon } from 'lucide-react';
import type { SegmentPqc } from '../../features/pqc-path/types';
import type { TranslationKey } from '../../i18n';

/**
 * PQC 判定（量子耐性）のラベル・色・アイコン。
 * 重大度（severityColors）・対策状況（controlStatusStyle）・リスク対応方針
 * （riskTreatmentStyle）とは別の意味レイヤーのため、トーンを意図的に分けている。
 * クラス名はテンプレート合成せず、フルクラス文字列で列挙する（Tailwind JIT 対策）。
 * 色だけに意味を載せないよう、アイコンとラベルを必ず併記すること。
 */
export const PQC_VERDICT_ORDER: SegmentPqc[] = ['pqc', 'transitional', 'vulnerable', 'plain', 'unknown'];

export const PQC_VERDICT_LABEL_KEY: Record<SegmentPqc, TranslationKey> = {
  pqc: 'panels.crypto.class.pqc',
  transitional: 'panels.crypto.class.transitional',
  vulnerable: 'panels.crypto.class.vulnerable',
  plain: 'panels.crypto.class.plain',
  unknown: 'panels.crypto.class.unknown',
};

export const PQC_VERDICT_ICON: Record<SegmentPqc, LucideIcon> = {
  pqc: ShieldCheck,
  transitional: Hourglass,
  vulnerable: ShieldAlert,
  plain: LockOpen,
  unknown: HelpCircle,
};

/** 淡背景＋明色テキストのバッジ。 */
export const PQC_VERDICT_BADGE: Record<SegmentPqc, string> = {
  pqc: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40',
  transitional: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/40',
  vulnerable: 'bg-orange-500/15 text-orange-300 border-orange-500/40',
  plain: 'bg-rose-500/15 text-rose-300 border-rose-500/40',
  unknown: 'bg-slate-500/15 text-slate-300 border-slate-500/40',
};

/** 区間の帯の背景。 */
export const PQC_VERDICT_BAND_BG: Record<SegmentPqc, string> = {
  pqc: 'bg-emerald-500/20',
  transitional: 'bg-yellow-500/20',
  vulnerable: 'bg-orange-500/20',
  plain: 'bg-rose-500/20',
  unknown: 'bg-slate-500/20',
};

/** 区間の帯の枠線。 */
export const PQC_VERDICT_BAND_BORDER: Record<SegmentPqc, string> = {
  pqc: 'border-emerald-500/60',
  transitional: 'border-yellow-500/60',
  vulnerable: 'border-orange-500/60',
  plain: 'border-rose-500/60',
  unknown: 'border-slate-500/60',
};
