import { useMemo } from 'react';
import type { DiagramNode, LayerData, ThreatView } from '../../../core/model/types';
import { isSuppressed } from '../../../core/model/types';
import { NodeView } from '../../../core/canvas/NodeView';
import { BoundaryView } from '../../../core/canvas/BoundaryView';
import { EdgeLayer } from '../../../core/canvas/EdgeLayer';
import { AnnotationView, AnnotationLeaderLines } from '../../../core/canvas/AnnotationView';
import type { ContentBounds } from './contentBounds';

/** スナップショット周囲の余白（px）。 */
export const SNAPSHOT_PADDING = 48;

const noop = () => {};

interface DiagramSnapshotProps {
  layer: LayerData;
  threats: ThreatView[];
  bounds: ContentBounds;
}

/** bbox ＋余白に収めたスナップショットの寸法（CSS px、等倍）。 */
export function snapshotSize(bounds: ContentBounds): { width: number; height: number } {
  return {
    width: Math.ceil(bounds.maxX - bounds.minX + SNAPSHOT_PADDING * 2),
    height: Math.ceil(bounds.maxY - bounds.minY + SNAPSHOT_PADDING * 2),
  };
}

/**
 * 指定レイヤーを静的に描画する（PNG 書き出し用）。Canvas と同じ部品・同じ子ノード束ね／
 * 脅威集約で描くが、選択・ハイライト・操作は持たない。bbox 左上＋余白が (0,0) になる。
 * Canvas.tsx の束ね処理は ~15 行のため、リスクの高い共通化はせず複製している。
 */
export function DiagramSnapshot({ layer, threats, bounds }: DiagramSnapshotProps) {
  const { nodes, edges, boundaries, annotations } = layer;
  const { width, height } = snapshotSize(bounds);

  const { topLevelNodes, childrenByParent } = useMemo(() => {
    const ids = new Set(nodes.map((n) => n.id));
    const tops: DiagramNode[] = [];
    const groups = new Map<string, DiagramNode[]>();
    for (const n of nodes) {
      if (n.parentId && ids.has(n.parentId)) {
        const arr = groups.get(n.parentId) ?? [];
        arr.push(n);
        groups.set(n.parentId, arr);
      } else {
        tops.push(n);
      }
    }
    return { topLevelNodes: tops, childrenByParent: groups };
  }, [nodes]);

  return (
    <div
      className="relative overflow-hidden bg-slate-950 text-slate-100 font-sans select-none"
      style={{
        width,
        height,
        backgroundImage: 'radial-gradient(#1e293b 1.5px, transparent 1.5px)',
        backgroundSize: '32px 32px',
      }}
    >
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          transform: `translate(${SNAPSHOT_PADDING - bounds.minX}px, ${SNAPSHOT_PADDING - bounds.minY}px)`,
          transformOrigin: '0 0',
        }}
      >
        {boundaries.map((boundary) => (
          <BoundaryView
            key={boundary.id}
            boundary={boundary}
            isSelected={false}
            onMouseDown={noop}
            onResizeStart={noop}
            onDelete={noop}
          />
        ))}

        <EdgeLayer
          nodes={nodes}
          edges={edges}
          boundaries={boundaries}
          selectedEdgeId={null}
          onSelectEdge={noop}
        />

        <AnnotationLeaderLines annotations={annotations} nodes={nodes} />

        {topLevelNodes.map((node) => {
          const children = childrenByParent.get(node.id) ?? [];
          const childIds = new Set(children.map((c) => c.id));
          const aggregatedThreats = threats.filter(
            (t) => !isSuppressed(t) && (t.nodeId === node.id || childIds.has(t.nodeId)),
          );
          return (
            <NodeView
              key={node.id}
              node={node}
              childNodes={children}
              isSelected={false}
              threats={aggregatedThreats}
              onMouseDown={noop}
              onSelectChild={noop}
              onDelete={noop}
            />
          );
        })}

        {annotations.map((annotation) => (
          <AnnotationView
            key={annotation.id}
            annotation={annotation}
            isSelected={false}
            onMouseDown={noop}
            onDelete={noop}
          />
        ))}
      </div>
    </div>
  );
}
