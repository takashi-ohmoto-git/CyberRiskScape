import { useEffect } from 'react';
import { X } from 'lucide-react';
import { SEVERITY_BADGE_SUBTLE } from '../../core/model/severityColors';
import type { EntryCandidate } from '../../features/attack-tree/findEntryPoints';
import type { EntrySurfaceDetail } from '../../features/attack-tree/entrySurfaces';
import { useT, type TranslationKey } from '../../i18n';

/**
 * 侵入候補 1 件の詳細のポップアップ。入口と判定した理由・弱点、届き得る先、面ごとの根拠の脅威を出す。読み取り専用。
 * 「届き得る」であり、悪用できるとは言わない。
 * 表示部は props だけで描ける EntryCandidateModalBody に分け、テストしやすくしている。
 */

interface EntryCandidateModalBodyProps {
  /** 例：'C6 受注 API（Pod）' */
  title: string;
  candidate: EntryCandidate;
  details: EntrySurfaceDetail[];
}

export function EntryCandidateModalBody({ title, candidate, details }: EntryCandidateModalBodyProps) {
  const t = useT();
  const reasonLines = [
    ...candidate.reasons.map((r) => t(`panels.node.entryReason.${r}`)),
    ...candidate.weaknesses.map((w) => t(`panels.node.entryWeakness.${w}`)),
  ];
  const outcomeText = (outcomes: readonly string[]) =>
    outcomes.map((o) => t(`panels.node.entryOutcome.${o}` as TranslationKey)).join(' · ');
  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <span className="font-black text-fuchsia-300">
          #{candidate.rank}
          {candidate.assumed ? '*' : ''}
        </span>
        <span className="text-base font-black text-slate-100">{title}</span>
        {candidate.maxSeverity && (
          <span className={`ml-auto shrink-0 text-xs px-1.5 rounded ${SEVERITY_BADGE_SUBTLE[candidate.maxSeverity]}`}>
            {candidate.maxSeverity} · {candidate.threatCount}
          </span>
        )}
      </div>

      <section className="space-y-1">
        <h3 className="text-xs font-black text-slate-400">{t('panels.node.entryDetailReasons')}</h3>
        <ul className="list-disc pl-5 text-sm text-slate-300">
          {reasonLines.map((line, i) => (
            <li key={i}>{line}</li>
          ))}
        </ul>
      </section>

      {candidate.outcomes.length > 0 && (
        <section className="space-y-1">
          <h3 className="text-xs font-black text-slate-400">{t('panels.node.entryDetailOutcomes')}</h3>
          <p className="text-sm text-fuchsia-200">{outcomeText(candidate.outcomes)}</p>
        </section>
      )}

      <section className="space-y-1">
        <h3 className="text-xs font-black text-slate-400">{t('panels.node.entryDetailSurfaces')}</h3>
        {details.length === 0 ? (
          <p className="text-sm text-slate-400">{t('panels.node.entryDetailNoSurfaces')}</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-xs text-slate-400 text-left">
              <tr>
                <th className="py-1 pr-4 font-black">{t('panels.node.entryDetailColSurface')}</th>
                <th className="py-1 pr-4 font-black">{t('panels.node.entryDetailColOutcomes')}</th>
                <th className="py-1 font-black">{t('panels.node.entryDetailColThreats')}</th>
              </tr>
            </thead>
            <tbody>
              {details.map((d) => (
                <tr key={d.id} className="align-top border-t border-slate-800">
                  <td className="py-2 pr-4 w-[28%] font-black text-slate-200">
                    {t(`panels.node.entrySurface.${d.id}` as TranslationKey)}
                  </td>
                  <td className="py-2 pr-4 w-[22%] text-fuchsia-200">{outcomeText(d.outcomes)}</td>
                  <td className="py-2 pr-4">
                    <ul className="space-y-1">
                      {d.threats.map((x) => (
                        <li key={x.id} className="flex items-start gap-2">
                          <span className={`shrink-0 text-xs px-1.5 rounded ${SEVERITY_BADGE_SUBTLE[x.severity]}`}>
                            {x.severity}
                          </span>
                          <span className="text-slate-300 leading-relaxed">{x.name}</span>
                        </li>
                      ))}
                    </ul>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {candidate.assumed && <p className="text-xs text-slate-400">{t('panels.node.entrySearchAssumed')}</p>}
    </div>
  );
}

interface EntryCandidateModalProps extends EntryCandidateModalBodyProps {
  onClose: () => void;
  /** 「このノードを選択」を押したとき。 */
  onSelectNode: () => void;
}

export function EntryCandidateModal({ title, candidate, details, onClose, onSelectNode }: EntryCandidateModalProps) {
  const t = useT();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onMouseDown={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="w-[760px] max-w-[96vw] max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 flex flex-col gap-4"
        onMouseDown={(e) => e.stopPropagation()}
      >
        {/* 操作は上端に置く（面が多いと本文が縦に伸び、下端のボタンが画面の外に出るため） */}
        <div className="flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onSelectNode}
            className="px-4 py-2 rounded-xl text-xs font-black bg-fuchsia-600 text-white hover:bg-fuchsia-500"
          >
            {t('panels.node.entryDetailSelectNode')}
          </button>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            aria-label={t('analytics.close')}
          >
            <X size={16} />
          </button>
        </div>
        <EntryCandidateModalBody title={title} candidate={candidate} details={details} />
      </div>
    </div>
  );
}
