import { useMemo } from 'react';
import type { ThreatView } from '../../core/model/types';
import {
  selectActiveBoundaries,
  selectActiveEdges,
  selectActiveNodes,
  useDiagramStore,
} from '../../core/state/diagramStore';
import { getEdgeAnchorAt, getEdgeEndpointGeometry } from '../../core/canvas/nodeGeometry';
import { ENTRY_PROBE } from '../../core/notation/edgeNotation';
import { findEntryPoints } from './findEntryPoints';

interface EntryProbeLayerProps {
  threats: ThreatView[];
}

/**
 * 侵入候補の線（Search Attack Graph）。攻撃者ノードから各入口の候補へ、仮想の線を重ねて描く。
 * エッジとしては保存せず、選択もできない（pointer-events-none）。候補の詳細は NodePanel の一覧で見る。
 * 記法は `ENTRY_PROBE`（凡例と共有）。
 */
export function EntryProbeLayer({ threats }: EntryProbeLayerProps) {
  const attackerId = useDiagramStore((s) => s.entrySearchAttackerId);
  const nodes = useDiagramStore(selectActiveNodes);
  const edges = useDiagramStore(selectActiveEdges);
  const boundaries = useDiagramStore(selectActiveBoundaries);

  const candidates = useMemo(
    () => (attackerId ? findEntryPoints(nodes, edges, boundaries, threats, attackerId) : []),
    [attackerId, nodes, edges, boundaries, threats],
  );
  const attacker = attackerId ? nodes.find((n) => n.id === attackerId) : undefined;
  if (!attacker || candidates.length === 0) return null;

  const aGeom = getEdgeEndpointGeometry(attacker, nodes);
  const r = ENTRY_PROBE.reticleRadius;

  return (
    <svg className="absolute inset-0 w-full h-full overflow-visible pointer-events-none" aria-hidden>
      {candidates.map((c) => {
        const target = nodes.find((n) => n.id === c.nodeId);
        if (!target) return null;
        const tGeom = getEdgeEndpointGeometry(target, nodes);
        const s = getEdgeAnchorAt(aGeom.center, aGeom.dims, tGeom.center.x, tGeom.center.y);
        const t = getEdgeAnchorAt(tGeom.center, tGeom.dims, aGeom.center.x, aGeom.center.y);
        // 照準マークの中心は入口の縁から攻撃者側へ半径ぶん離し、ノードに重ねない。
        const len = Math.hypot(s.x - t.x, s.y - t.y) || 1;
        const ux = (s.x - t.x) / len;
        const uy = (s.y - t.y) / len;
        const rx = t.x + ux * r;
        const ry = t.y + uy * r;
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
    </svg>
  );
}
