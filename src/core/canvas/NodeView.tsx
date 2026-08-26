import { type MouseEvent } from 'react';
import { ShieldAlert, Trash2 } from 'lucide-react';
import type {
  DetectedThreat,
  DiagramNode,
  Severity,
  ShapeKind,
} from '../model/types';
import { componentRegistry } from '../../component-library/defaultRegistry';
import { renderIcon } from '../../component-library/iconRegistry';
import { SEVERITY_BG } from '../model/severityColors';
import { getNodeDisplayName } from '../model/nodeDisplay';
import { formatElementalId } from '../model/elementalId';
import { SHAPE_DIMENSIONS } from './nodeGeometry';

/** 未登録コンポーネント型のフォールバック表示。 */
const FALLBACK_SHAPE: ShapeKind = 'rounded';
const FALLBACK_COLOR = 'bg-slate-500';

interface NodeViewProps {
  node: DiagramNode;
  /** このノードに内包される子ノード（Canvas で集約してから渡す）。 */
  childNodes: DiagramNode[];
  isSelected: boolean;
  threats: DetectedThreat[];
  onMouseDown: (e: MouseEvent, nodeId: string) => void;
  /** 子バッジクリック時に呼ばれる。親 mousedown と分離するため stopPropagation 済み。 */
  onSelectChild: (nodeId: string) => void;
  onDelete: (nodeId: string) => void;
}

/** バッジで表示するチップの最大件数（残りは "+N" でまとめる）。 */
const BADGE_VISIBLE_LIMIT = 3;

function maxSeverity(threats: DetectedThreat[]): Severity {
  if (threats.some((t) => t.severity === 'Critical')) return 'Critical';
  if (threats.some((t) => t.severity === 'High')) return 'High';
  if (threats.some((t) => t.severity === 'Medium')) return 'Medium';
  return 'Low';
}

interface ShapeStyle {
  outer: string;
  iconWrapper: string;
  iconSize: number;
  showLabel: boolean;
  deleteBtnPos: string;
}

const SHAPE_STYLES: Record<ShapeKind, ShapeStyle> = {
  rounded: {
    outer: 'rounded-3xl border-2 border-slate-800 bg-slate-900/90 shadow-xl',
    iconWrapper: 'p-3 rounded-2xl shadow-inner',
    iconSize: 28,
    showLabel: true,
    deleteBtnPos: '-bottom-2 -right-2',
  },
  rectangle: {
    outer: 'rounded-none border-2 border-slate-800 bg-slate-900/90 shadow-xl',
    iconWrapper: 'p-2.5 rounded-md',
    iconSize: 26,
    showLabel: true,
    deleteBtnPos: '-bottom-2 -right-2',
  },
  circle: {
    outer: 'rounded-full border-2 border-slate-800 bg-slate-900/90 shadow-xl',
    iconWrapper: 'p-2 rounded-full',
    iconSize: 24,
    showLabel: true,
    deleteBtnPos: '-bottom-1 -right-1',
  },
  'data-store': {
    // DFD Yourdon記法: 上下の平行線のみ（左右は開いた状態）
    outer: 'rounded-none border-t-2 border-b-2 border-slate-600 bg-slate-900/90 shadow-md',
    iconWrapper: 'p-2.5 rounded-md',
    iconSize: 26,
    showLabel: true,
    deleteBtnPos: '-bottom-2 -right-2',
  },
  connector: {
    outer: 'bg-transparent',
    iconWrapper: 'p-1.5 rounded-full',
    iconSize: 16,
    showLabel: false,
    deleteBtnPos: '-top-4 -right-4',
  },
};

export function NodeView({
  node,
  childNodes,
  isSelected,
  threats,
  onMouseDown,
  onSelectChild,
  onDelete,
}: NodeViewProps) {
  const config = componentRegistry.get(node.type);
  const shape: ShapeKind = config?.shape ?? FALLBACK_SHAPE;
  const color = config?.color ?? FALLBACK_COLOR;
  const style = SHAPE_STYLES[shape];
  const dims = SHAPE_DIMENSIONS[shape];
  const severity = maxSeverity(threats);
  const visibleChildren = childNodes.slice(0, BADGE_VISIBLE_LIMIT);
  const overflowCount = Math.max(0, childNodes.length - BADGE_VISIBLE_LIMIT);

  const badgeColor = SEVERITY_BG[severity];

  return (
    <div
      onMouseDown={(e) => onMouseDown(e, node.id)}
      className={`absolute pointer-events-auto cursor-grab active:cursor-grabbing transition-[transform,box-shadow] group flex flex-col items-center justify-center gap-1 ${style.outer} ${
        isSelected ? 'ring-4 ring-blue-500 z-30 scale-110 shadow-2xl shadow-blue-500/20' : 'z-20'
      }`}
      style={{
        left: node.x,
        top: node.y,
        width: dims.w,
        height: dims.h,
        touchAction: 'none',
      }}
    >
      {threats.length > 0 && (
        <div
          className={`absolute -top-3 -right-3 rounded-full p-2 shadow-lg animate-pulse border-2 border-slate-950 ${badgeColor}`}
        >
          <ShieldAlert size={16} className="text-white" />
        </div>
      )}

      {node.seq != null && (
        <span
          className="absolute -bottom-2 -left-2 z-10 font-mono text-[9px] font-bold leading-none text-slate-200 bg-slate-950/90 border border-slate-700 rounded px-1 py-[2px] shadow pointer-events-none"
          title="Analytics ID"
        >
          {formatElementalId('node', node.seq)}
        </span>
      )}

      {childNodes.length > 0 && (
        <div
          className="absolute -top-2 -left-2 flex items-center gap-0.5 z-10"
          // 親 mousedown と分離（バッジ操作中にノードドラッグが開始しないように）。
          onMouseDown={(e) => e.stopPropagation()}
        >
          {visibleChildren.map((child) => {
            const childConfig = componentRegistry.get(child.type);
            const childColor = childConfig?.color ?? FALLBACK_COLOR;
            const title = `${childConfig?.label ?? child.type}${child.label ? `: ${child.label}` : ''}`;
            return (
              <button
                key={child.id}
                onClick={(e) => {
                  e.stopPropagation();
                  onSelectChild(child.id);
                }}
                title={title}
                className={`${childColor} p-1 rounded-md text-white border border-slate-950 shadow hover:scale-110 transition-transform cursor-pointer`}
              >
                {renderIcon(childConfig?.icon ?? { kind: 'builtin', name: 'box' }, { size: 10 })}
              </button>
            );
          })}
          {overflowCount > 0 && (
            <span
              className="bg-slate-700 text-slate-100 text-[9px] font-black px-1.5 py-[3px] rounded-md border border-slate-950 shadow"
              title={`他 ${overflowCount} 件`}
            >
              +{overflowCount}
            </span>
          )}
        </div>
      )}

      <div
        className={`${color} ${style.iconWrapper} text-white flex items-center justify-center`}
      >
        {renderIcon(config?.icon ?? { kind: 'builtin', name: 'box' }, { size: style.iconSize })}
      </div>

      {style.showLabel && (
        <span className="text-[9px] font-black text-center uppercase tracking-widest text-slate-400 px-1 leading-tight">
          {getNodeDisplayName(node)}
        </span>
      )}

      <button
        onClick={(e) => {
          e.stopPropagation();
          onDelete(node.id);
        }}
        className={`absolute bg-slate-800 hover:bg-rose-600 p-2 rounded-full opacity-0 group-hover:opacity-100 transition-all border border-slate-700 ${style.deleteBtnPos}`}
      >
        <Trash2 size={12} />
      </button>
    </div>
  );
}
