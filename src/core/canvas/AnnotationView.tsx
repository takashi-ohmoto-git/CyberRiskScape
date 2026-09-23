import type { MouseEvent } from 'react';
import { Trash2 } from 'lucide-react';
import type { DiagramAnnotation, DiagramNode } from '../model/types';
import { getEdgeAnchorAt, getEdgeEndpointGeometry } from './nodeGeometry';

/** callout の固定幅（`w-56` と一致）。[[plan]] §2.48：リサイズは v1 スコープ外。 */
const CALLOUT_WIDTH = 224;
/**
 * 引き出し線のアンカー計算に使う仮の高さ。callout の実高さは本文に応じた自動サイズで
 * ストア側からは分からないが、ボックス自体が線の始点付近を上から覆って描画される
 * （描画順：… < 引き出し線 < … < 注釈ボックス）。1 行のボックス（約 32px）でも始点が
 * 必ずボックス内に収まるよう、最小高さを採る（大きくすると短い吹き出しの下に線が浮く）。
 */
const CALLOUT_ANCHOR_HEIGHT = 32;

interface AnnotationViewProps {
  annotation: DiagramAnnotation;
  isSelected: boolean;
  onMouseDown: (e: MouseEvent, id: string) => void;
  onDelete: (id: string) => void;
}

/** 注釈 1 件分の描画（テキストラベル or 吹き出しボックス）。 */
export function AnnotationView({ annotation, isSelected, onMouseDown, onDelete }: AnnotationViewProps) {
  const isCallout = annotation.kind === 'callout';

  return (
    <div
      onMouseDown={(e) => onMouseDown(e, annotation.id)}
      className={`absolute pointer-events-auto cursor-move group ${
        isSelected ? 'ring-2 ring-blue-500/50 rounded-lg' : ''
      }`}
      style={{
        left: annotation.x,
        top: annotation.y,
        width: isCallout ? CALLOUT_WIDTH : undefined,
        touchAction: 'none',
      }}
    >
      {isCallout ? (
        <div className="bg-slate-900/85 backdrop-blur-[1px] border border-amber-500/50 rounded-xl px-3 py-2 text-amber-100 text-xs font-bold whitespace-pre-wrap shadow-xl">
          {annotation.text}
        </div>
      ) : (
        <div className="text-sm font-black text-slate-100 whitespace-pre-wrap px-1 drop-shadow">
          {annotation.text}
        </div>
      )}
      <button
        onClick={(e) => {
          e.stopPropagation();
          onDelete(annotation.id);
        }}
        className="absolute -top-2 -right-2 bg-slate-800 hover:bg-rose-600 p-1.5 rounded-full opacity-0 group-hover:opacity-100 transition-all border border-slate-700 pointer-events-auto"
      >
        <Trash2 size={12} />
      </button>
    </div>
  );
}

interface AnnotationLeaderLinesProps {
  annotations: DiagramAnnotation[];
  nodes: DiagramNode[];
}

/**
 * callout がノードへリンクされている場合の引き出し線（SVG の破線）。
 * ボックス中心からノード外周への線分（[[plan]] §2.48）。描画順は境界/エッジより後、
 * ノード/注釈ボックスより前（Canvas.tsx を参照）。
 */
export function AnnotationLeaderLines({ annotations, nodes }: AnnotationLeaderLinesProps) {
  const callouts = annotations.filter(
    (a): a is DiagramAnnotation & { targetNodeId: string } =>
      a.kind === 'callout' && a.targetNodeId != null,
  );
  if (callouts.length === 0) return null;

  return (
    <svg className="absolute inset-0 w-full h-full pointer-events-none">
      {callouts.map((a) => {
        const target = nodes.find((n) => n.id === a.targetNodeId);
        if (!target) return null;
        const boxCenter = { x: a.x + CALLOUT_WIDTH / 2, y: a.y + CALLOUT_ANCHOR_HEIGHT / 2 };
        const { center: nodeCenter, dims: nodeDims } = getEdgeEndpointGeometry(target, nodes);
        const anchor = getEdgeAnchorAt(nodeCenter, nodeDims, boxCenter.x, boxCenter.y);
        return (
          <line
            key={a.id}
            x1={boxCenter.x}
            y1={boxCenter.y}
            x2={anchor.x}
            y2={anchor.y}
            stroke="#f59e0b"
            strokeWidth={1.5}
            strokeDasharray="4 3"
          />
        );
      })}
    </svg>
  );
}
