import { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { SEVERITY_BADGE_SUBTLE } from '../../core/model/severityColors';
import { useT, type TranslationKey } from '../../i18n';
import type { DiagramFact } from './compareConditions';
import type { AuditRow } from './auditRows';

/**
 * ソース監査の指摘の一覧（表示のみ。docs/architecture.md §8.9）。
 * 図の事実は中立に並べるだけで、「成立する／しない」の判定は出さない。自由記述はプレーンテキストで描く。
 */

type T = (key: TranslationKey, params?: Record<string, string | number>) => string;

/** 接続の認証値（EdgeAuth）→ 既存の表示名キー（panels.edge.auth.*）の末尾。 */
const AUTH_KEY: Record<string, string> = { ApiKey: 'apiKey', MFA: 'mfa' };

/** 事実 1 件を文言にする（接続の認証・経路・真偽値は既存の表示名・語に引き直す）。 */
export function factText(t: T, fact: DiagramFact): string {
  const raw = fact.params ?? {};
  const params: Record<string, string | number> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (typeof v === 'boolean') params[k] = t(`findings.securityAudit.bool.${v}` as TranslationKey);
    else params[k] = v;
  }
  if (fact.key === 'authentication.edgeAuth') params.auth = t(`panels.edge.auth.${AUTH_KEY[String(raw.auth)] ?? String(raw.auth).toLowerCase()}` as TranslationKey);
  if (fact.key === 'reachability.edgeNetwork') params.network = t(`panels.edge.network.${String(raw.network).toLowerCase()}` as TranslationKey);
  return t(`findings.securityAudit.fact.${fact.key}` as TranslationKey, params);
}

function RowView({ row, defaultOpen }: { row: AuditRow; defaultOpen: boolean }) {
  const t = useT();
  const [open, setOpen] = useState(defaultOpen);
  const { conditions, openQuestions } = row.comparison;
  const hasDetails = conditions.length > 0 || openQuestions.length > 0 || !!row.validationPlan;
  return (
    <li className="rounded-xl border border-slate-700 bg-slate-900/60 p-3 space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        {row.status === 'confirmed' ? (
          <>
            <span className="text-xs font-bold px-2 py-0.5 rounded bg-slate-700/60 text-slate-200 border border-slate-500">
              {t('findings.securityAudit.status.confirmed')}
            </span>
            <span className={`text-xs font-black px-2 py-0.5 rounded border ${SEVERITY_BADGE_SUBTLE[row.severity]}`}>
              {row.severity}
            </span>
          </>
        ) : (
          <span className="text-xs font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-dashed border-slate-500">
            {t('findings.securityAudit.status.unverified')}
          </span>
        )}
        <span
          className={`text-xs px-2 py-0.5 rounded border ${
            row.mapped ? 'text-slate-300 border-slate-600' : 'text-slate-400 border-dashed border-slate-600'
          }`}
        >
          {row.mapped ? t('findings.securityAudit.mapped') : t('findings.securityAudit.unmapped')}
        </span>
      </div>
      <p className="text-xs font-bold text-slate-100 break-words">{row.title}</p>
      {row.resourceLabel && <p className="text-xs font-mono text-slate-400 break-all">{row.resourceLabel}</p>}
      {hasDetails && (
        <>
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            className="flex items-center gap-1 text-xs font-bold text-blue-300 hover:text-blue-200"
          >
            {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />} {t('findings.securityAudit.details')}
          </button>
          {open && (
            <div className="space-y-3">
              {conditions.length > 0 && (
                <div className="space-y-1.5">
                  <p className="text-xs font-bold text-slate-300">{t('findings.securityAudit.conditions')}</p>
                  {conditions.map((c, i) => (
                    <div key={i} className="grid grid-cols-2 gap-2 text-xs">
                      <div className="text-slate-200 break-words">
                        <span className="font-bold text-slate-400">
                          {t(`findings.securityAudit.kind.${c.kind}` as TranslationKey)}
                        </span>
                        <br />
                        {c.text}
                      </div>
                      <div className="text-slate-400 border-l border-slate-700 pl-2 space-y-0.5">
                        <span className="font-bold">{t('findings.securityAudit.diagramFacts')}</span>
                        {c.diagramFacts.length === 0 ? (
                          <p>{t('findings.securityAudit.noFacts')}</p>
                        ) : (
                          c.diagramFacts.map((f, j) => <p key={j}>{factText(t, f)}</p>)
                        )}
                      </div>
                    </div>
                  ))}
                  <p className="text-xs text-slate-500">{t('findings.securityAudit.factsNote')}</p>
                </div>
              )}
              {openQuestions.length > 0 && (
                <div className="space-y-1">
                  <p className="text-xs font-bold text-slate-300">{t('findings.securityAudit.openQuestions')}</p>
                  <ul className="list-disc pl-4 text-xs text-slate-200 space-y-0.5">
                    {openQuestions.map((q, i) => (
                      <li key={i} className="break-words">
                        {q.text}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {row.validationPlan && (
                <div className="space-y-1">
                  <p className="text-xs font-bold text-slate-300">{t('findings.securityAudit.validationPlan')}</p>
                  <p className="text-xs text-slate-200 break-words">{row.validationPlan}</p>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </li>
  );
}

export function SecurityAuditList({ rows, defaultOpen = false }: { rows: readonly AuditRow[]; defaultOpen?: boolean }) {
  const t = useT();
  if (rows.length === 0) return <p className="text-xs text-slate-500">{t('findings.securityAudit.empty')}</p>;
  return (
    <ul className="space-y-2">
      {rows.map((r) => (
        <RowView key={r.id} row={r} defaultOpen={defaultOpen} />
      ))}
    </ul>
  );
}
