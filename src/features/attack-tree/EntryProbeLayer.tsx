import { useMemo } from 'react';
import type { ThreatView } from '../../core/model/types';
import {
  selectActiveBoundaries,
  selectActiveEdges,
  selectActiveNodes,
  useDiagramStore,
} from '../../core/state/diagramStore';
import { getEdgeAnchorAt, getEdgeEndpointGeometry } from '../../core/canvas/nodeGeometry';
import { ENTRY_PROBE, ENTRY_TARGET } from '../../core/notation/edgeNotation';
import { useT } from '../../i18n';
import { buildAttackGraph } from './buildAttackGraph';
import { analyzeAttackGraph } from './analyzeAttackGraph';
import { buildHopEvidence, NEUTRAL_EVIDENCE, type HopEvidence } from './hopEvidence';
import { buildEntryEdges, findEntryPoints } from './findEntryPoints';

interface EntryProbeLayerProps {
  threats: ThreatView[];
}

/** 経由ノードの丸印の半径（標的の二重環より小さくする）。 */
const TRANSIT_RADIUS = 6;

/**
 * 侵入候補の線（Search Attack Graph）。攻撃者ノードから各入口の候補へ、仮想の線を重ねて描く。
 * エッジとしては保存せず、選択もできない（pointer-events-none）。候補の詳細は NodePanel の一覧で見る。
 *
 * 侵入候補を表示中に objective が設定されていれば、攻撃者から標的への経路も重ねる。
 * 経路は攻撃経路分析と同じ最弱ルート（最小コスト）を辿り、経由ノードに丸印、標的に二重環を付ける。
 * 記法は `ENTRY_PROBE` / `ENTRY_TARGET`（凡例と共有）。
 */
export function EntryProbeLayer({ threats }: EntryProbeLayerProps) {
  const t = useT();
  const attackerId = useDiagramStore((s) => s.entrySearchAttackerId);
  const nodes = useDiagramStore(selectActiveNodes);
  const edges = useDiagramStore(selectActiveEdges);
  const boundaries = useDiagramStore(selectActiveBoundaries);

  const candidates = useMemo(
    () => (attackerId ? findEntryPoints(nodes, edges, boundaries, threats, attackerId) : []),
    [attackerId, nodes, edges, boundaries, threats],
  );
  const attacker = attackerId ? nodes.find((n) => n.id === attackerId) : undefined;
  // 侵入候補を表示中に objective が設定されていれば、攻撃者から標的への経路も描く。
  const targetId = attacker?.attackObjectiveId;
  const targetNode = targetId ? nodes.find((n) => n.id === targetId) : undefined;

  // 標的への最弱ルート（攻撃経路分析と同じ）。侵入候補の仮想の線込みで辿る。
  // 経路が無ければ null（標的マークだけ出す）。先頭が攻撃者、末尾が標的のノード列。
  const routeNodeIds = useMemo(() => {
    if (!attackerId || !targetNode) return null;
    const entryEdges = buildEntryEdges(
      attackerId,
      findEntryPoints(nodes, edges, boundaries, threats, attackerId),
    );
    const graph = buildAttackGraph(nodes, [...edges, ...entryEdges], attackerId, targetNode.id);
    if (graph.routes.length === 0) return null;
    const evidence = buildHopEvidence(threats);
    const getEvidence = (key: string): HopEvidence => evidence.get(key) ?? NEUTRAL_EVIDENCE;
    const analysis = analyzeAttackGraph(graph, getEvidence);
    return analysis.routes[0]?.route.nodeIds ?? null;
  }, [attackerId, targetNode, nodes, edges, boundaries, threats]);

  if (!attacker || (candidates.length === 0 && !targetNode)) return null;

  const aGeom = getEdgeEndpointGeometry(attacker, nodes);
  const r = ENTRY_PROBE.reticleRadius;
  const tr = ENTRY_TARGET.reticleRadius;

  // a → b のセグメントと、b 側に置くマーク（経由ノード＝丸印 / 標的＝二重環）。
  const renderTargetSegment = (fromId: string, toId: string, isTarget: boolean) => {
    const a = nodes.find((n) => n.id === fromId);
    const b = nodes.find((n) => n.id === toId);
    if (!a || !b) return null;
    const ag = getEdgeEndpointGeometry(a, nodes);
    const bg = getEdgeEndpointGeometry(b, nodes);
    const s = getEdgeAnchorAt(ag.center, ag.dims, bg.center.x, bg.center.y);
    const e = getEdgeAnchorAt(bg.center, bg.dims, ag.center.x, ag.center.y);
    const len = Math.hypot(s.x - e.x, s.y - e.y) || 1;
    const ux = (s.x - e.x) / len;
    const uy = (s.y - e.y) / len;
    const mr = isTarget ? tr : TRANSIT_RADIUS;
    // マークの中心はノードの縁から手前（攻撃者側）へ半径ぶん離し、ノードに重ねない。
    const mx = e.x + ux * mr;
    const my = e.y + uy * mr;
    return (
      <g key={`${fromId}->${toId}`}>
        <line
          x1={s.x}
          y1={s.y}
          x2={mx}
          y2={my}
          stroke={ENTRY_TARGET.stroke}
          strokeWidth={ENTRY_TARGET.strokeWidth}
          strokeDasharray={ENTRY_TARGET.dash}
        />
        {isTarget ? (
          // 二重環＋塗りの標的マーク（経由ノードの丸印とは環の数で分ける）。
          <g transform={`translate(${mx} ${my})`} stroke={ENTRY_TARGET.stroke} strokeWidth={2} fill="none">
            <circle r={tr} />
            <circle r={tr - 4} />
            <circle r={2.5} fill={ENTRY_TARGET.stroke} />
          </g>
        ) : (
          // 経由ノードの丸印（単環＋塗り）。
          <g transform={`translate(${mx} ${my})`} stroke={ENTRY_TARGET.stroke} strokeWidth={2} fill="none">
            <circle r={TRANSIT_RADIUS} />
            <circle r={2} fill={ENTRY_TARGET.stroke} />
          </g>
        )}
        {isTarget && (
          <text
            x={mx + ux * (tr + 14)}
            y={my + uy * (tr + 14)}
            dy={4}
            textAnchor="middle"
            fill="#fecdd3"
            stroke="#0f172a"
            strokeWidth={3}
            paintOrder="stroke"
            style={{ fontSize: 12, fontWeight: 800, userSelect: 'none' }}
          >
            {t('canvas.edgeNotation.entryTargetMark')}
          </text>
        )}
      </g>
    );
  };

  return (
    <svg className="absolute inset-0 w-full h-full overflow-visible pointer-events-none" aria-hidden>
      {candidates.map((c) => {
        const target = nodes.find((n) => n.id === c.nodeId);
        if (!target) return null;
        const tGeom = getEdgeEndpointGeometry(target, nodes);
        const s = getEdgeAnchorAt(aGeom.center, aGeom.dims, tGeom.center.x, tGeom.center.y);
        const t2 = getEdgeAnchorAt(tGeom.center, tGeom.dims, aGeom.center.x, aGeom.center.y);
        // 照準マークの中心は入口の縁から攻撃者側へ半径ぶん離し、ノードに重ねない。
        const len = Math.hypot(s.x - t2.x, s.y - t2.y) || 1;
        const ux = (s.x - t2.x) / len;
        const uy = (s.y - t2.y) / len;
        const rx = t2.x + ux * r;
        const ry = t2.y + uy * r;
        return (
          <g key={c.nodeId}>
            <line
              x1={s.x}
              y1={s.y}
              x2={rx + ux * r}
              y2={ry + uy * r}
              stroke={ENTRY_PROBE.stroke}
              strokeWidth={ENTRY_PROBE.strokeWidth}
              strokeDasharray={ENTRY_PROBE.dash}
              strokeLinecap="round"
              className="entry-probe-flow"
            />
            <g transform={`translate(${rx} ${ry})`} stroke={ENTRY_PROBE.stroke} strokeWidth={2} fill="none">
              <circle r={r} />
              <circle r={2.5} fill={ENTRY_PROBE.stroke} />
              <line x1={-r - 4} y1={0} x2={-r + 3} y2={0} />
              <line x1={r - 3} y1={0} x2={r + 4} y2={0} />
              <line x1={0} y1={-r - 4} x2={0} y2={-r + 3} />
              <line x1={0} y1={r - 3} x2={0} y2={r + 4} />
            </g>
            <text
              x={rx + ux * (r + 14)}
              y={ry + uy * (r + 14)}
              dy={4}
              textAnchor="middle"
              fill="#f5d0fe"
              stroke="#0f172a"
              strokeWidth={3}
              paintOrder="stroke"
              style={{ fontSize: 12, fontWeight: 800, userSelect: 'none' }}
            >
              {`#${c.rank}${c.assumed ? '*' : ''}`}
            </text>
          </g>
        );
      })}

      {/* 標的への経路：最弱ルートがあれば経由ノードを辿り、無ければ標的マークだけ出す。 */}
      {targetNode && routeNodeIds
        ? routeNodeIds
            .slice(1)
            .map((id, i) =>
              renderTargetSegment(routeNodeIds[i], id, i === routeNodeIds.length - 2),
            )
        : targetNode && renderTargetSegment(attacker.id, targetNode.id, true)}
    </svg>
  );
}
