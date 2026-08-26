import type { MouseEvent } from 'react';
import { Trash2 } from 'lucide-react';
import type { DiagramBoundary, ResizeHandle } from '../model/types';
import { BOUNDARY_TYPES } from '../constants/boundaryTypes';
import { formatElementalId } from '../model/elementalId';

interface BoundaryViewProps {
  boundary: DiagramBoundary;
  isSelected: boolean;
  onMouseDown: (e: MouseEvent, boundaryId: string) => void;
  onResizeStart: (e: MouseEvent, boundaryId: string, handle: ResizeHandle) => void;
  onDelete: (boundaryId: string) => void;
}

interface HandleConfig {
  handle: ResizeHandle;
  cursor: string;
  /** ハンドルを境界矩形のどの位置に表示するか（top/left を tailwind 任意値で指定）。 */
  position: string;
}

const HANDLES: HandleConfig[] = [
  { handle: 'nw', cursor: 'cursor-nwse-resize', position: '-top-1.5 -left-1.5' },
  { handle: 'n', cursor: 'cursor-ns-resize', position: '-top-1.5 left-1/2 -translate-x-1/2' },
  { handle: 'ne', cursor: 'cursor-nesw-resize', position: '-top-1.5 -right-1.5' },
  { handle: 'e', cursor: 'cursor-ew-resize', position: 'top-1/2 -right-1.5 -translate-y-1/2' },
  { handle: 'se', cursor: 'cursor-nwse-resize', position: '-bottom-1.5 -right-1.5' },
  { handle: 's', cursor: 'cursor-ns-resize', position: '-bottom-1.5 left-1/2 -translate-x-1/2' },
  { handle: 'sw', cursor: 'cursor-nesw-resize', position: '-bottom-1.5 -left-1.5' },
  { handle: 'w', cursor: 'cursor-ew-resize', position: 'top-1/2 -left-1.5 -translate-y-1/2' },
];

export function BoundaryView({
  boundary,
  isSelected,
  onMouseDown,
  onResizeStart,
  onDelete,
}: BoundaryViewProps) {
  const config = BOUNDARY_TYPES[boundary.type];
  const trustColor =
    boundary.trustLevel === 'Internal'
      ? 'border-emerald-500/50 text-emerald-500'
      : boundary.trustLevel === 'Partner'
        ? 'border-orange-500/50 text-orange-500'
        : 'border-blue-500/50 text-blue-500';

  return (
    <div
      onMouseDown={(e) => onMouseDown(e, boundary.id)}
      className={`absolute pointer-events-auto cursor-move transition-all flex flex-col p-2 group ${
        isSelected ? 'ring-2 ring-blue-500/50' : ''
      }`}
      style={{
        left: boundary.x,
        top: boundary.y,
        width: boundary.width,
        height: boundary.height,
        touchAction: 'none',
      }}
    >
      <div
        className={`w-full h-full border-2 ${config.isDashed ? 'border-dashed' : 'border-solid'} ${
          config.rounded ? 'rounded-3xl' : 'rounded-none'
        } ${trustColor} bg-white/5 backdrop-blur-[1px]`}
      >
        <div className="absolute top-2 left-4 flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded bg-slate-950/80 border border-inherit">
          {boundary.seq != null && (
            <span className="font-mono normal-case tracking-normal text-slate-300" title="Analytics ID">
              {formatElementalId('boundary', boundary.seq)}
            </span>
          )}
          {boundary.trustLevel}: {config.name}
        </div>
        <button
          onClick={(e) => {
            e.stopPropagation();
            onDelete(boundary.id);
          }}
          className="absolute top-2 right-2 bg-slate-800 hover:bg-rose-600 p-1.5 rounded-full opacity-0 group-hover:opacity-100 transition-all border border-slate-700 pointer-events-auto"
        >
          <Trash2 size={12} />
        </button>
      </div>

      {isSelected &&
        HANDLES.map((h) => (
          <div
            key={h.handle}
            onMouseDown={(e) => {
              e.stopPropagation();
              onResizeStart(e, boundary.id, h.handle);
            }}
            className={`absolute ${h.position} ${h.cursor} w-3 h-3 bg-white border-2 border-blue-500 rounded-sm shadow z-10`}
          />
        ))}
    </div>
  );
}
