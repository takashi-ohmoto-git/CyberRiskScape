import type { MouseEvent } from 'react';
import type { DiagramEdge, DiagramNode } from '../model/types';
import { getEdgeAnchorAt, getEdgeEndpointGeometry } from './nodeGeometry';
import { formatElementalId } from '../model/elementalId';
import {
  EDGE_STROKE_COLORS,
  ENCRYPTION_DASH,
  isHighRiskEdge,
  type EdgeStrokeKey,
} from '../notation/edgeNotation';

interface EdgeLayerProps {
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  selectedEdgeId: string | null;
  onSelectEdge: (edgeId: string) => void;
}

/**
 * 矢印マーカーの色キー。線記法スペック（`edgeNotation`）の stroke 色と 1:1。
 * SVG marker は path の塗りを line の stroke から継承できないため、選択/危険/通常で
 * ID を分けて切り替える。
 */
type MarkerKey = EdgeStrokeKey;

/** 兄弟エッジ（同一ノードペアを共有する別エッジ）同士の弧と弧の距離。 */
const SIBLING_SPACING = 36;
/** ラベルを曲線の頂点からさらに外側へ押し出す距離。 */
const LABEL_PADDING = 10;

function pairKey(a: string, b: string): string {
  return a < b ? `${a}|${b}` : `${b}|${a}`;
}

export function EdgeLayer({ nodes, edges, selectedEdgeId, onSelectEdge }: EdgeLayerProps) {
  // 同一ノードペア（向き無視）を共有するエッジ群を集計。
  // 兄弟が複数あれば、各エッジを線の垂直方向にオフセットして重なりを回避する。
  const siblingGroups = new Map<string, DiagramEdge[]>();
  for (const e of edges) {
    const key = pairKey(e.source, e.target);
    const arr = siblingGroups.get(key);
    if (arr) arr.push(e);
    else siblingGroups.set(key, [e]);
  }
  // 並び順を決定的にする（ID の小さい方を起点とする方向を先頭に → A→B と B→A が必ず反対側に分かれる）。
  for (const arr of siblingGroups.values()) {
    if (arr.length > 1) {
      arr.sort((a, b) => {
        const aForward = a.source < a.target ? 0 : 1;
        const bForward = b.source < b.target ? 0 : 1;
        return aForward - bForward || a.id.localeCompare(b.id);
      });
    }
  }

  return (
    <svg className="absolute inset-0 w-full h-full pointer-events-none">
      <defs>
        {(Object.keys(EDGE_STROKE_COLORS) as MarkerKey[]).map((key) => (
          <marker
            key={key}
            id={`arrow-${key}`}
            viewBox="0 0 10 10"
            refX="10"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" fill={EDGE_STROKE_COLORS[key]} />
          </marker>
        ))}
      </defs>
      {edges.map((edge) => {
        const sNode = nodes.find((n) => n.id === edge.source);
        const tNode = nodes.find((n) => n.id === edge.target);
        if (!sNode || !tNode) return null;

        // 端点はソース／ターゲットそのものの視覚位置（トップレベルはノード中心、
        // 親内包の子はバッジ位置）を使う。これにより同じ親配下でも子ごとに別々の
        // 接続先へ線を引ける。
        const sGeom = getEdgeEndpointGeometry(sNode, nodes);
        const tGeom = getEdgeEndpointGeometry(tNode, nodes);
        // 自己ループ（同一ノード）または overflow フォールバックで同一視覚位置に解決された場合はスキップ。
        if (edge.source === edge.target) return null;
        if (sGeom.center.x === tGeom.center.x && sGeom.center.y === tGeom.center.y) return null;

        const isSelected = selectedEdgeId === edge.id;
        const isAtRisk = isHighRiskEdge(edge);
        const sCenter = sGeom.center;
        const tCenter = tGeom.center;

        const group = siblingGroups.get(pairKey(edge.source, edge.target))!;
        const offsetMagnitude =
          group.length > 1
            ? (group.indexOf(edge) - (group.length - 1) / 2) * SIBLING_SPACING
            : 0;
        const isCurved = offsetMagnitude !== 0;

        // 兄弟エッジの曲げ向きを揃えるため、垂線はソース/ターゲットIDの正準順序で計算する。
        // ノード対 (A,B) に対して常に同じ法線を使うことで、A→B と B→A が反対側に振り分けられる。
        let cx = (sCenter.x + tCenter.x) / 2;
        let cy = (sCenter.y + tCenter.y) / 2;
        if (isCurved) {
          const [ac, bc] = edge.source < edge.target ? [sCenter, tCenter] : [tCenter, sCenter];
          const vx = bc.x - ac.x;
          const vy = bc.y - ac.y;
          const vlen = Math.hypot(vx, vy) || 1;
          const nx = -vy / vlen;
          const ny = vx / vlen;
          cx += offsetMagnitude * nx;
          cy += offsetMagnitude * ny;
        }

        // 曲線時は制御点方向、直線時は相手中心方向にアンカーをクリップ。
        const sAnchor = getEdgeAnchorAt(
          sGeom.center,
          sGeom.dims,
          isCurved ? cx : tCenter.x,
          isCurved ? cy : tCenter.y,
        );
        const tAnchor = getEdgeAnchorAt(
          tGeom.center,
          tGeom.dims,
          isCurved ? cx : sCenter.x,
          isCurved ? cy : sCenter.y,
        );

        const markerKey: MarkerKey = isSelected ? 'selected' : isAtRisk ? 'risk' : 'normal';
        const markerUrl = `url(#arrow-${markerKey})`;
        const dataFlow = edge.dataFlow ?? 'outbound';
        const showEndArrow = dataFlow === 'outbound' || dataFlow === 'bidirectional';
        const showStartArrow = dataFlow === 'inbound' || dataFlow === 'bidirectional';

        const handleClick = (e: MouseEvent) => {
          e.stopPropagation();
          onSelectEdge(edge.id);
        };

        const pathD = isCurved
          ? `M ${sAnchor.x} ${sAnchor.y} Q ${cx} ${cy} ${tAnchor.x} ${tAnchor.y}`
          : `M ${sAnchor.x} ${sAnchor.y} L ${tAnchor.x} ${tAnchor.y}`;

        const elementalId = edge.seq != null ? formatElementalId('edge', edge.seq) : null;
        const dataFlowName = edge.dataFlowName;
        // ID（DFn）と任意のデータフロー名のどちらか一方でもあればラベルを描画する。
        const hasLabel = elementalId != null || (dataFlowName != null && dataFlowName !== '');
        // ラベル位置：直線時は中点、曲線時は弧の頂点（t=0.5 のベジエ点）からさらに外側へパディング。
        const midAnchorX = (sAnchor.x + tAnchor.x) / 2;
        const midAnchorY = (sAnchor.y + tAnchor.y) / 2;
        let labelX = midAnchorX;
        let labelY = midAnchorY;
        if (isCurved) {
          const apexX = 0.25 * sAnchor.x + 0.5 * cx + 0.25 * tAnchor.x;
          const apexY = 0.25 * sAnchor.y + 0.5 * cy + 0.25 * tAnchor.y;
          const ox = apexX - midAnchorX;
          const oy = apexY - midAnchorY;
          const olen = Math.hypot(ox, oy) || 1;
          labelX = apexX + (ox / olen) * LABEL_PADDING;
          labelY = apexY + (oy / olen) * LABEL_PADDING;
        }

        // 線の傾きに合わせて回転。読みやすさのため、上下逆さになる向きでは 180° 反転。
        // 二次ベジエの t=0.5 における接線方向は (P2 - P0) と平行なので、直線時と同じ角度で良い。
        const rawAngle = (Math.atan2(tAnchor.y - sAnchor.y, tAnchor.x - sAnchor.x) * 180) / Math.PI;
        const textAngle = rawAngle > 90 || rawAngle < -90 ? rawAngle + 180 : rawAngle;

        return (
          <g key={edge.id} className="pointer-events-auto cursor-pointer" onClick={handleClick}>
            <path
              d={pathD}
              fill="none"
              stroke={EDGE_STROKE_COLORS[markerKey]}
              strokeWidth={isSelected ? 4 : 2}
              strokeDasharray={ENCRYPTION_DASH[edge.encryption]}
              markerStart={showStartArrow ? markerUrl : undefined}
              markerEnd={showEndArrow ? markerUrl : undefined}
              className="transition-all duration-300"
            />
            <path d={pathD} fill="none" stroke="transparent" strokeWidth={20} />
            {hasLabel && (
              <text
                x={labelX}
                y={labelY}
                dy={isCurved ? 0 : -8}
                textAnchor="middle"
                transform={`rotate(${textAngle} ${labelX} ${labelY})`}
                fill={isSelected ? '#bfdbfe' : '#e2e8f0'}
                stroke="#0f172a"
                strokeWidth={3}
                paintOrder="stroke"
                style={{ fontSize: 11, fontWeight: 700, userSelect: 'none' }}
              >
                {elementalId && (
                  <tspan fill="#94a3b8" style={{ fontFamily: 'monospace' }}>
                    {elementalId}
                  </tspan>
                )}
                {elementalId && dataFlowName ? ' ' : ''}
                {dataFlowName}
              </text>
            )}
          </g>
        );
      })}
    </svg>
  );
}
