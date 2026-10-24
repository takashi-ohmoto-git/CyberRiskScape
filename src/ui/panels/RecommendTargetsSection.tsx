import { useMemo } from 'react';
import { ShieldCheck, Crosshair } from 'lucide-react';
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
import {
  aggregatePriorityDefenses,
  recommendTargets,
  type TargetCategory,
} from '../../features/attack-tree/recommendTargets';
import { useT } from '../../i18n';

interface RecommendTargetsSectionProps {
  attacker: DiagramNode;
  /** アクティブレイヤーの全 ThreatView（推奨の順位付けに使う）。 */
  threats: ThreatView[];
}

const CATEGORY_KEY: Record<TargetCategory, 'panels.node.recommendCategory.credential' | 'panels.node.recommendCategory.data'> = {
  credential: 'panels.node.recommendCategory.credential',
  data: 'panels.node.recommendCategory.data',
};

/**
 * 守る側が優先して保護する標的の推奨と、複数の標的に共通して効く対策点（優先的に守る経路）。
 * 標的を押すと攻撃者の objective に設定し、既存の攻撃経路分析につなぐ。
 */
export function RecommendTargetsSection({ attacker, threats }: RecommendTargetsSectionProps) {
  const t = useT();
  const activeId = useDiagramStore((s) => s.recommendTargetsAttackerId);
  const setActiveId = useDiagramStore((s) => s.setRecommendTargetsAttackerId);
  const updateNode = useDiagramStore((s) => s.updateNode);
  const nodes = useDiagramStore(selectActiveNodes);
  const edges = useDiagramStore(selectActiveEdges);
  const boundaries = useDiagramStore(selectActiveBoundaries);
  const isActive = activeId === attacker.id;

  const recommendations = useMemo(
    () => (isActive ? recommendTargets(nodes, edges, boundaries, threats, attacker.id) : []),
    [isActive, nodes, edges, boundaries, threats, attacker.id],
  );
  const defenses = useMemo(
    () =>
      isActive
        ? aggregatePriorityDefenses(nodes, edges, boundaries, threats, attacker.id, recommendations)
            .filter((d) => d.targetHits >= 2)
            .slice(0, 5)
        : [],
    [isActive, nodes, edges, boundaries, threats, attacker.id, recommendations],
  );

  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.id, n] as const)), [nodes]);
  const shortLabel = (id: string): string => {
    const n = nodeById.get(id);
    if (!n) return id;
    const eid = n.seq !== undefined ? `${formatElementalId('node', n.seq)} ` : '';
    return `${eid}${getNodeDisplayName(n)}`;
  };
  const defenseLabel = (elementKey: string): string => {
    if (elementKey.startsWith('node:')) return shortLabel(elementKey.slice('node:'.length));
    const [a, b] = elementKey.slice('hop:'.length).split('--');
    return `${shortLabel(a)} ⇔ ${shortLabel(b)}`;
  };

  // 攻撃者の objective を設定するだけ（攻撃者パネルを開いたままにして、すぐ攻撃経路分析を押せるようにする）。
  const setObjective = (nodeId: string) => {
    updateNode(attacker.id, 'attackObjectiveId', nodeId);
  };

  return (
    <div className="space-y-2">
      <button
        onClick={() => setActiveId(isActive ? null : attacker.id)}
        aria-pressed={isActive}
        title={t('panels.node.recommendTitle')}
        className={`w-full py-3 rounded-xl font-black text-xs transition-colors flex items-center justify-center gap-2 border ${
          isActive
            ? 'bg-teal-500/15 border-teal-400 text-teal-200 hover:bg-teal-500/25'
            : 'bg-teal-600 border-teal-600 text-white hover:bg-teal-500'
        }`}
      >
        <ShieldCheck size={16} /> {isActive ? t('panels.node.recommendHide') : t('panels.node.recommendButton')}
      </button>

      {isActive && (
        <div className="space-y-3">
          <div className="space-y-1.5">
            <p className="text-xs font-black text-slate-400">{t('panels.node.recommendTargetHeading')}</p>
            {recommendations.length === 0 ? (
              <p className="text-xs text-slate-400 leading-relaxed">{t('panels.node.recommendTargetEmpty')}</p>
            ) : (
              <ol className="space-y-1.5">
                {recommendations.map((r) => {
                  const n = nodeById.get(r.nodeId);
                  if (!n) return null;
                  const id = n.seq !== undefined ? formatElementalId('node', n.seq) : '';
                  return (
                    <li key={r.nodeId} className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2">
                      <div className="flex items-center gap-2 text-sm text-slate-100">
                        <span className="font-black text-teal-300">#{r.rank}</span>
                        <span className="font-mono text-xs text-slate-400">{id}</span>
                        <span className="truncate">{getNodeDisplayName(n)}</span>
                        {r.maxSeverity && (
                          <span className={`ml-auto shrink-0 text-xs px-1.5 rounded ${SEVERITY_BADGE_SUBTLE[r.maxSeverity]}`}>
                            {r.maxSeverity} · {r.threatCount}
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-slate-300 mt-1 leading-relaxed">
                        {t(CATEGORY_KEY[r.category])}
                        {' · '}
                        {r.reasons.map((reason) => t(`panels.node.recommendReason.${reason}`)).join(' · ')}
                      </div>
                      {r.reachable ? (
                        <button
                          onClick={() => setObjective(r.nodeId)}
                          className="mt-1.5 inline-flex items-center gap-1 text-xs font-bold text-teal-300 hover:text-teal-200"
                        >
                          <Crosshair size={12} /> {t('panels.node.recommendSetObjective')}
                        </button>
                      ) : (
                        <p className="mt-1.5 text-xs text-slate-500">{t('panels.node.recommendUnreachable')}</p>
                      )}
                    </li>
                  );
                })}
              </ol>
            )}
          </div>

          <div className="space-y-1.5">
            <p className="text-xs font-black text-slate-400">{t('panels.node.recommendDefenseHeading')}</p>
            {defenses.length === 0 ? (
              <p className="text-xs text-slate-400 leading-relaxed">{t('panels.node.recommendDefenseEmpty')}</p>
            ) : (
              <ul className="space-y-1">
                {defenses.map((d) => (
                  <li
                    key={d.elementKey}
                    className="flex items-center gap-2 bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  >
                    <span className="truncate">{defenseLabel(d.elementKey)}</span>
                    <span className="ml-auto shrink-0 text-xs text-teal-300 font-bold">
                      {t('panels.node.recommendDefenseHits', { count: d.targetHits })}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">{t('panels.node.recommendNote')}</p>
        </div>
      )}
    </div>
  );
}
