import { useState } from 'react';
import { BookOpen, ChevronDown, ChevronRight, ExternalLink, Layers, ShieldCheck } from 'lucide-react';
import type { ThreatRule } from '../../../threat-library/schema/threatRule';
import { SEVERITY_BADGE_SOLID } from '../../../core/model/severityColors';
import { summarizeAppliesTo } from '../appliesToSummary';
import { ConditionDiagram } from './ConditionDiagram';
import { useLocale, useT } from '../../../i18n';

interface RuleCardProps {
  /** 代表ルール（canonicalId 畳み込み時は severity 最大のメンバー、同率は先勝ち）。 */
  rule: ThreatRule;
  /** canonicalId を共有する全メンバー（畳み込みなしなら `[rule]`）。 */
  members: ThreatRule[];
  getSource: (ruleId: string) => string | undefined;
  /** node kind ルールを表示する際、選択中の型（`anyOf` の中心表示に使う）。 */
  centerType?: string;
}

/**
 * 脅威ライブラリ・インスペクタの 1 ルールカード。ThreatCard のバッジ・
 * mitigationTiers・references の見た目パターンを踏襲しつつ、読み取り専用（編集操作なし）。
 */
export function RuleCard({ rule, members, getSource, centerType }: RuleCardProps) {
  const [locale] = useLocale();
  const t = useT();
  const [open, setOpen] = useState(false);

  const sources = Array.from(new Set(members.map((m) => getSource(m.id) ?? m.id)));
  const isCorroborated = members.length > 1;

  return (
    <div className="p-3 rounded-xl border border-slate-800 bg-slate-800/40">
      <div className="flex items-start justify-between gap-2 mb-1.5">
        <div className="flex items-center gap-1.5 flex-wrap">
          <span
            className={`text-xs font-black px-2 py-0.5 rounded-md ${SEVERITY_BADGE_SOLID[rule.severity]}`}
          >
            {rule.severity}
          </span>
          <span className="text-xs font-bold px-2 py-0.5 rounded bg-slate-700/60 text-slate-300 border border-slate-600">
            {rule.category}
          </span>
        </div>
        {isCorroborated && (
          <span className="text-xs bg-teal-500/20 text-teal-300 px-2 py-0.5 rounded font-bold inline-flex items-center gap-1 shrink-0">
            <Layers size={10} /> {t('libraryInspector.card.corroborationBadge', { count: members.length })}
          </span>
        )}
      </div>

      <h4 className="font-bold text-sm text-slate-100 mb-1.5">{rule.name ?? rule.category}</h4>

      <ConditionDiagram appliesTo={rule.appliesTo} centerType={centerType} />

      <p className="text-sm text-slate-400 leading-relaxed mt-2">
        {summarizeAppliesTo(rule.appliesTo, locale)}
      </p>

      <div className="flex flex-wrap gap-1.5 mt-2">
        {sources.map((s) => (
          <span
            key={s}
            className="text-xs font-bold bg-slate-800 border border-slate-700 text-slate-400 px-2 py-0.5 rounded"
          >
            {t('libraryInspector.card.sourceLabel')}: {s}
          </span>
        ))}
      </div>

      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="mt-2 flex items-center gap-1 text-xs font-bold uppercase text-slate-500 hover:text-slate-300 transition-colors"
      >
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        {open ? t('libraryInspector.card.detailsHide') : t('libraryInspector.card.detailsShow')}
      </button>

      {open && (
        <div className="mt-2 space-y-2">
          <div>
            <div className="text-xs font-black text-slate-500 uppercase tracking-widest mb-1">
              {t('libraryInspector.card.descriptionHeading')}
            </div>
            <p className="text-sm text-slate-300 leading-relaxed">{rule.description}</p>
          </div>

          {rule.mitigationTiers ? (
            <div className="p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20 space-y-2">
              <div className="flex items-center gap-1.5 text-xs font-black text-emerald-400 uppercase tracking-widest">
                <ShieldCheck size={12} /> {t('libraryInspector.card.mitigationHeading')}
              </div>
              {(['foundation', 'enterprise', 'advanced'] as const).map((tier) => {
                const value = rule.mitigationTiers?.[tier];
                if (!value) return null;
                const tierLabel =
                  tier === 'foundation' ? 'Foundation' : tier === 'enterprise' ? 'Enterprise' : 'Advanced';
                const tierBadge =
                  tier === 'foundation'
                    ? 'bg-emerald-500/15 text-emerald-300'
                    : tier === 'enterprise'
                      ? 'bg-sky-500/15 text-sky-300'
                      : 'bg-violet-500/15 text-violet-300';
                return (
                  <div key={tier} className="flex gap-2">
                    <span
                      className={`shrink-0 h-fit text-xs font-black uppercase tracking-wider px-1.5 py-0.5 rounded ${tierBadge}`}
                    >
                      {tierLabel}
                    </span>
                    <p className="text-sm text-slate-300 leading-relaxed">{value}</p>
                  </div>
                );
              })}
            </div>
          ) : (
            rule.mitigation && (
              <div className="p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
                <div className="flex items-center gap-1.5 mb-1 text-xs font-black text-emerald-400 uppercase tracking-widest">
                  <ShieldCheck size={12} /> {t('libraryInspector.card.mitigationHeading')}
                </div>
                <p className="text-sm text-slate-300 leading-relaxed">{rule.mitigation}</p>
              </div>
            )
          )}

          {rule.references && rule.references.length > 0 && (
            <div>
              <div className="flex items-center gap-1.5 text-xs font-black text-slate-500 uppercase tracking-widest mb-1.5">
                <BookOpen size={12} /> {t('libraryInspector.card.referencesHeading')}
              </div>
              <ul className="space-y-1">
                {rule.references.map((r, i) => (
                  <li key={`${r.title}-${i}`} className="text-xs text-slate-400 leading-snug">
                    {r.url ? (
                      <a
                        href={r.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300 hover:underline"
                      >
                        {r.title}
                        <ExternalLink size={10} />
                      </a>
                    ) : (
                      <span>{r.title}</span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
