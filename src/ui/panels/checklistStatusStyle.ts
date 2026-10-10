import { AlertTriangle, CheckCircle2, CircleDashed, HelpCircle, ShieldCheck, type LucideIcon } from 'lucide-react';
import type { ItemStatus } from '../../checklist/evaluate';
import type { TranslationKey } from '../../i18n';

/**
 * 注意喚起チェックリストの項目状態のラベル・バッジ class・アイコン。
 * 重大度・対策実装状況・リスク対応方針（DesignPrinciples §4.1）とは別レイヤー。
 * 色だけに頼らず、ラベルとアイコンでも区別する（§4.1「色だけに意味を載せない」）。
 */
export const CHECKLIST_STATUS_LABEL_KEY: Record<ItemStatus, TranslationKey> = {
  action: 'checklist.status.action',
  unfilled: 'checklist.status.unfilled',
  accepted: 'checklist.status.accepted',
  ok: 'checklist.status.ok',
  notApplicable: 'checklist.status.notApplicable',
};

export const CHECKLIST_STATUS_DESC_KEY: Record<ItemStatus, TranslationKey> = {
  action: 'checklist.status.action.desc',
  unfilled: 'checklist.status.unfilled.desc',
  accepted: 'checklist.status.accepted.desc',
  ok: 'checklist.status.ok.desc',
  notApplicable: 'checklist.status.notApplicable.desc',
};

export const CHECKLIST_STATUS_BADGE: Record<ItemStatus, string> = {
  action: 'bg-rose-500/15 text-rose-300 border-rose-500/40',
  unfilled: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
  accepted: 'bg-slate-500/15 text-slate-300 border-slate-500/40',
  ok: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40',
  notApplicable: 'bg-slate-800 text-slate-500 border-slate-700',
};

export const CHECKLIST_STATUS_ICON: Record<ItemStatus, LucideIcon> = {
  action: AlertTriangle,
  unfilled: HelpCircle,
  accepted: ShieldCheck,
  ok: CheckCircle2,
  notApplicable: CircleDashed,
};
