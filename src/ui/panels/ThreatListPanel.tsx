import { useState } from 'react';
import { BadgeCheck, Crosshair, Eye, EyeOff, Plus, ShieldAlert } from 'lucide-react';
import { isSuppressed, type ThreatView } from '../../core/model/types';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import { getComponentRegistry } from '../../component-library/defaultRegistry';
import { selectActiveNodes, useDiagramStore } from '../../core/state/diagramStore';
import { FRAMEWORK_VIEW_LABEL_KEYS } from '../frameworkLabels';
import { findingsForThreat } from '../../features/pentest-import/matchFindings';
import { ThreatCard } from './ThreatCard';
import { sortThreatsBySeverity } from './sortThreatsBySeverity';
import { useLocale, useT } from '../../i18n';

interface ThreatListPanelProps {
  threats: ThreatView[];
}

export function ThreatListPanel({ threats }: ThreatListPanelProps) {
  const t = useT();
  const [locale] = useLocale();
  const nodes = useDiagramStore(selectActiveNodes);
  const framework = useDiagramStore((s) => s.activeFramework);
  const openManualThreatEditor = useDiagramStore((s) => s.openManualThreatEditor);
  const findings = useDiagramStore((s) => s.findings);

  const [hideSuppressed, setHideSuppressed] = useState(false);
  const [pentestFilter, setPentestFilter] = useState<'verified' | 'attempted' | null>(null);

  const suppressedCount = threats.filter((t) => isSuppressed(t)).length;
  const activeCount = threats.length - suppressedCount;
  const verified = threats.filter((t) => findingsForThreat(findings, t).some((f) => f.outcome !== 'attempted'));
  const attempted = threats.filter((t) => findingsForThreat(findings, t).some((f) => f.outcome === 'attempted'));
  // 該当する脅威が無くなったら（別のプロジェクトを開いた等）絞り込みを解く
  const showVerifiedOnly = pentestFilter === 'verified' && verified.length > 0;
  const showAttemptedOnly = pentestFilter === 'attempted' && attempted.length > 0;
  const base = showVerifiedOnly ? verified : showAttemptedOnly ? attempted : threats;
  const visible = hideSuppressed ? base.filter((t) => !isSuppressed(t)) : base;

  return (
    <div className="flex flex-col h-full">
      <div className="p-6 border-b border-slate-800 bg-slate-900/50">
        <div className="flex items-center justify-between gap-3 mb-2">
          <div className="flex items-center gap-3">
            <ShieldAlert className="text-rose-500" size={24} />
            <h2 className="text-xl font-black tracking-tight">Threat Analysis</h2>
          </div>
          <button
            onClick={() => openManualThreatEditor()}
            className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-black uppercase tracking-wider px-3 py-1.5 rounded-lg transition-colors"
          >
            <Plus size={14} /> {t('threats.list.addScenario')}
          </button>
        </div>
        <div className="flex justify-between items-center text-xs font-bold uppercase tracking-widest">
          <span className="text-slate-500">{t(FRAMEWORK_VIEW_LABEL_KEYS[framework])} MODE</span>
          <span className="bg-rose-500/20 text-rose-500 px-2 py-0.5 rounded-full">
            {activeCount} ISSUES
          </span>
        </div>
        {verified.length > 0 && (
          <button
            onClick={() => setPentestFilter(showVerifiedOnly ? null : 'verified')}
            aria-pressed={showVerifiedOnly}
            title={t('threats.threatCard.pentestVerifiedHint')}
            className={`mt-3 flex items-center gap-1.5 text-xs font-bold px-2 py-1 rounded border transition-colors ${
              showVerifiedOnly
                ? 'bg-slate-200 text-slate-900 border-slate-200'
                : 'bg-slate-700/60 text-slate-200 border-slate-500 hover:border-slate-300'
            }`}
          >
            <BadgeCheck size={12} />
            {showVerifiedOnly
              ? t('threats.list.verifiedShowAll')
              : t('threats.list.verifiedOnly', { count: verified.length })}
          </button>
        )}
        {attempted.length > 0 && (
          <button
            onClick={() => setPentestFilter(showAttemptedOnly ? null : 'attempted')}
            aria-pressed={showAttemptedOnly}
            title={t('threats.threatCard.pentestAttemptedHint')}
            className={`mt-3 flex items-center gap-1.5 text-xs font-bold px-2 py-1 rounded border border-dashed transition-colors ${
              showAttemptedOnly
                ? 'bg-slate-200 text-slate-900 border-slate-200'
                : 'bg-slate-800/60 text-slate-300 border-slate-500 hover:border-slate-300'
            }`}
          >
            <Crosshair size={12} />
            {showAttemptedOnly
              ? t('threats.list.verifiedShowAll')
              : t('threats.list.attemptedOnly', { count: attempted.length })}
          </button>
        )}
        {suppressedCount > 0 && (
          <button
            onClick={() => setHideSuppressed((v) => !v)}
            className="mt-3 flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-slate-500 hover:text-slate-300 transition-colors"
          >
            {hideSuppressed ? <Eye size={12} /> : <EyeOff size={12} />}
            {hideSuppressed
              ? t('threats.list.suppressedShow', { count: suppressedCount })
              : t('threats.list.suppressedHide', { count: suppressedCount })}
          </button>
        )}
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-1.5">
        {visible.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-700 opacity-50 p-8 text-center">
            <Eye size={64} className="mb-4" />
            <p className="text-sm font-bold">{t('threats.list.empty')}</p>
          </div>
        ) : (
          sortThreatsBySeverity(visible).map((threat) => {
            let targetName: string;
            if (threat.nodeId) {
              const targetNode = nodes.find((n) => n.id === threat.nodeId);
              targetName = targetNode ? getNodeDisplayName(targetNode) : 'Unknown';
            } else if (threat.manualTargetType) {
              const typeLabel =
                getComponentRegistry(locale).get(threat.manualTargetType)?.label ??
                threat.manualTargetType;
              targetName = t('threats.list.typeTarget', { type: typeLabel });
            } else {
              targetName = t('threats.list.wholeProject');
            }
            return <ThreatCard key={threat.id} threat={threat} targetName={targetName} collapsible />;
          })
        )}
      </div>
    </div>
  );
}
