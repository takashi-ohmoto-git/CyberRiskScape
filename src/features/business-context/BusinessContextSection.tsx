import { useState } from 'react';
import { Briefcase, ChevronDown, ChevronRight } from 'lucide-react';
import {
  BUSINESS_CRITICALITIES,
  type BusinessCriticality,
  type DiagramNode,
  type NodeBusinessContext,
} from '../../core/model/types';
import { useDiagramStore } from '../../core/state/diagramStore';
import { useT } from '../../i18n';

/**
 * ノード詳細パネルの「業務の文脈」欄。ノードが担う業務プロセスと業務上の重要度（取り込み or 手入力）。
 * 重要度を手で変えると「表に記載・手入力」（declared）になり、プロセスと出どころは保つ。未設定にすると記録ごと消す。
 * 脅威ルールには使わない（High は推奨標的と SSVC に効く）。
 */

const BADGE: Record<BusinessCriticality, string> = {
  High: 'bg-rose-500/20 text-rose-200',
  Medium: 'bg-amber-500/20 text-amber-200',
  Low: 'bg-slate-600/40 text-slate-200',
};

export function BusinessContextSection({ node }: { node: DiagramNode }) {
  const t = useT();
  const updateNode = useDiagramStore((s) => s.updateNode);
  const [open, setOpen] = useState(false);
  const bc = node.businessContext;

  const onChange = (value: string) => {
    if (value === '') {
      updateNode(node.id, 'businessContext', undefined);
      return;
    }
    const next: NodeBusinessContext = {
      criticality: value as BusinessCriticality,
      criticalitySource: 'declared',
      processes: bc?.processes ?? [],
      ...(bc?.source ? { source: bc.source } : {}),
    };
    updateNode(node.id, 'businessContext', next);
  };

  return (
    <div className="bg-slate-800/50 rounded-2xl border border-slate-700">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full px-4 py-3 flex items-center justify-between text-xs font-bold text-slate-300 hover:text-slate-100 transition-colors"
        aria-expanded={open}
      >
        <span className="flex items-center gap-2">
          <Briefcase size={14} className="text-blue-500 shrink-0" /> {t('businessContext.section.title')}
          {bc && (
            <span className={`text-xs font-bold px-1.5 rounded ${BADGE[bc.criticality]}`}>
              {t(`businessContext.criticality.${bc.criticality}`)}
            </span>
          )}
        </span>
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-3">
          <p className="text-xs text-slate-500 leading-relaxed">{t('businessContext.section.hint')}</p>
          <label className="block text-xs text-slate-300">
            <span className="font-bold">{t('businessContext.criticality.label')}</span>
            <select
              value={bc?.criticality ?? ''}
              onChange={(e) => onChange(e.target.value)}
              data-testid="business-criticality-select"
              className="block w-full mt-1 rounded-lg bg-slate-900 border border-slate-700 px-2 py-1.5 text-xs text-slate-100"
            >
              <option value="">{t('businessContext.criticality.unset')}</option>
              {BUSINESS_CRITICALITIES.map((c) => (
                <option key={c} value={c}>
                  {t(`businessContext.criticality.${c}`)}
                </option>
              ))}
            </select>
          </label>
          {bc && (
            <>
              <p className="text-xs text-slate-400">{t(`businessContext.criticalitySource.${bc.criticalitySource}`)}</p>
              <div className="space-y-1">
                <p className="text-xs font-bold text-slate-300">{t('businessContext.processes')}</p>
                {bc.processes.length === 0 ? (
                  <p className="text-xs text-slate-500">{t('businessContext.processes.empty')}</p>
                ) : (
                  <ul className="space-y-1">
                    {bc.processes.map((p) => (
                      <li key={p.name} className="text-xs text-slate-300 bg-slate-900 border border-slate-700 rounded-lg px-2 py-1.5">
                        <span className="font-bold">{p.name}</span>
                        <span className="text-slate-400">
                          {p.cases !== undefined && ` · ${t('businessContext.process.cases', { count: p.cases.toLocaleString() })}`}
                          {p.value !== undefined && ` · ${p.value.toLocaleString()}${p.currency ? ` ${p.currency}` : ''}`}
                          {p.period && ` · ${p.period}`}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              {bc.source && (
                <p className="text-xs text-slate-400 leading-relaxed">
                  {t('businessContext.source', { product: bc.source.product, at: bc.source.retrievedAt.slice(0, 10) })}
                  {bc.source.ref && <span className="block">{t('businessContext.source.ref', { ref: bc.source.ref })}</span>}
                </p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
