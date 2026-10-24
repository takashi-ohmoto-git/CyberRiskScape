import { useMemo } from 'react';
import { Radar } from 'lucide-react';
import type { DiagramNode, ThreatView } from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import { SEVERITY_BADGE_SUBTLE } from '../../core/model/severityColors';
import {
  selectActiveBoundaries,
  selectActiveEdges,
  selectActiveNodes,
  useDiagramStore,
} from '../../core/state/diagramStore';
import { findEntryPoints } from '../../features/attack-tree/findEntryPoints';
import { useT } from '../../i18n';

interface EntrySearchSectionProps {
  attacker: DiagramNode;
  /** アクティブレイヤーの全 ThreatView（候補の順位付けに使う）。 */
  threats: ThreatView[];
}

/**
 * 侵入ポイントの分析（Search Attack Graph）の操作と候補の一覧。
 * 押すと攻撃者から入口の候補へ仮想の線をキャンバスに重ね（EntryProbeLayer）、ここに入りやすい順で並べる。
 * 候補を押すとそのノードを選択する。
 */
export function EntrySearchSection({ attacker, threats }: EntrySearchSectionProps) {
  const t = useT();
  const activeId = useDiagramStore((s) => s.entrySearchAttackerId);
  const setActiveId = useDiagramStore((s) => s.setEntrySearchAttackerId);
  const selectNode = useDiagramStore((s) => s.selectNode);
  const nodes = useDiagramStore(selectActiveNodes);
  const edges = useDiagramStore(selectActiveEdges);
  const boundaries = useDiagramStore(selectActiveBoundaries);
  const isActive = activeId === attacker.id;

  const candidates = useMemo(
    () => (isActive ? findEntryPoints(nodes, edges, boundaries, threats, attacker.id) : []),
    [isActive, nodes, edges, boundaries, threats, attacker.id],
  );

  return (
    <div className="space-y-2">
      <button
        onClick={() => setActiveId(isActive ? null : attacker.id)}
        aria-pressed={isActive}
        title={t('panels.node.entrySearchTitle')}
        className={`w-full py-3 rounded-xl font-black text-xs transition-colors flex items-center justify-center gap-2 border ${
          isActive
            ? 'bg-fuchsia-500/15 border-fuchsia-400 text-fuchsia-200 hover:bg-fuchsia-500/25'
            : 'bg-fuchsia-600 border-fuchsia-600 text-white hover:bg-fuchsia-500'
        }`}
      >
        <Radar size={16} /> {isActive ? t('panels.node.entrySearchHide') : t('panels.node.entrySearchButton')}
      </button>

      {isActive && (
        <div className="space-y-1.5">
          <p className="text-xs font-black text-slate-400">{t('panels.node.entrySearchHeading')}</p>
          {candidates.length === 0 ? (
            <p className="text-xs text-slate-400 leading-relaxed">{t('panels.node.entrySearchEmpty')}</p>
          ) : (
            <ol className="space-y-1.5">
              {candidates.map((c) => {
                const n = nodes.find((x) => x.id === c.nodeId);
                if (!n) return null;
                const id = n.seq !== undefined ? formatElementalId('node', n.seq) : '';
                return (
                  <li key={c.nodeId}>
                    <button
                      onClick={() => selectNode(c.nodeId)}
                      className="w-full text-left bg-slate-900 border border-slate-700 hover:border-fuchsia-400 rounded-lg px-3 py-2 transition-colors"
                    >
                      <span className="flex items-center gap-2 text-sm text-slate-100">
                        <span className="font-black text-fuchsia-300">
                          #{c.rank}
                          {c.assumed ? '*' : ''}
                        </span>
                        <span className="font-mono text-xs text-slate-400">{id}</span>
                        <span className="truncate">{getNodeDisplayName(n)}</span>
                        {c.maxSeverity && (
                          <span className={`ml-auto shrink-0 text-xs px-1.5 rounded ${SEVERITY_BADGE_SUBTLE[c.maxSeverity]}`}>
                            {c.maxSeverity} · {c.threatCount}
                          </span>
                        )}
                      </span>
                      <span className="block text-xs text-slate-300 mt-1 leading-relaxed">
                        {[
                          ...c.reasons.map((r) => t(`panels.node.entryReason.${r}`)),
                          ...c.weaknesses.map((w) => t(`panels.node.entryWeakness.${w}`)),
                        ].join(' · ')}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ol>
          )}
          {candidates.some((c) => c.assumed) && (
            <p className="text-xs text-slate-400 leading-relaxed">{t('panels.node.entrySearchAssumed')}</p>
          )}
        </div>
      )}
    </div>
  );
}
