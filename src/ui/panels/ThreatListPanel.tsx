import { useState } from 'react';
import { Eye, EyeOff, Plus, ShieldAlert } from 'lucide-react';
import { isSuppressed, type ThreatView } from '../../core/model/types';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import { componentRegistry } from '../../component-library/defaultRegistry';
import { selectActiveNodes, useDiagramStore } from '../../core/state/diagramStore';
import { FRAMEWORK_VIEW_LABELS } from '../frameworkLabels';
import { ThreatCard } from './ThreatCard';

interface ThreatListPanelProps {
  threats: ThreatView[];
}

export function ThreatListPanel({ threats }: ThreatListPanelProps) {
  const nodes = useDiagramStore(selectActiveNodes);
  const framework = useDiagramStore((s) => s.activeFramework);
  const openManualThreatEditor = useDiagramStore((s) => s.openManualThreatEditor);

  const [hideSuppressed, setHideSuppressed] = useState(false);

  const suppressedCount = threats.filter((t) => isSuppressed(t)).length;
  const activeCount = threats.length - suppressedCount;
  const visible = hideSuppressed ? threats.filter((t) => !isSuppressed(t)) : threats;

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
            className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white text-[10px] font-black uppercase tracking-wider px-3 py-1.5 rounded-lg transition-colors"
          >
            <Plus size={14} /> シナリオ追加
          </button>
        </div>
        <div className="flex justify-between items-center text-[10px] font-bold uppercase tracking-widest">
          <span className="text-slate-500">{FRAMEWORK_VIEW_LABELS[framework]} MODE</span>
          <span className="bg-rose-500/20 text-rose-500 px-2 py-0.5 rounded-full">
            {activeCount} ISSUES
          </span>
        </div>
        {suppressedCount > 0 && (
          <button
            onClick={() => setHideSuppressed((v) => !v)}
            className="mt-3 flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-500 hover:text-slate-300 transition-colors"
          >
            {hideSuppressed ? <Eye size={12} /> : <EyeOff size={12} />}
            抑制済み {suppressedCount} 件を{hideSuppressed ? '表示' : '非表示'}
          </button>
        )}
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {visible.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-700 opacity-50 p-8 text-center">
            <Eye size={64} className="mb-4" />
            <p className="text-sm font-bold">脅威は検出されませんでした</p>
          </div>
        ) : (
          visible.map((threat) => {
            let targetName: string;
            if (threat.nodeId) {
              const targetNode = nodes.find((n) => n.id === threat.nodeId);
              targetName = targetNode ? getNodeDisplayName(targetNode) : 'Unknown';
            } else if (threat.manualTargetType) {
              const typeLabel =
                componentRegistry.get(threat.manualTargetType)?.label ?? threat.manualTargetType;
              targetName = `${typeLabel}型（該当ノードなし）`;
            } else {
              targetName = 'プロジェクト全体';
            }
            return <ThreatCard key={threat.id} threat={threat} targetName={targetName} />;
          })
        )}
      </div>
    </div>
  );
}
