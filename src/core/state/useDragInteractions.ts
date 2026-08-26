import { useEffect } from 'react';
import { useDiagramStore } from './diagramStore';
import { findDropTargetParent } from './parenting';
import { componentRegistry } from '../../component-library/defaultRegistry';

/**
 * グローバル mousemove / mouseup を購読し、ドラッグ・リサイズ中の
 * ノード / 境界の座標を更新する副作用フック。
 * App ルートで 1 度だけ呼ぶこと。
 */
export function useDragInteractions(): void {
  // どれか 1 つでも進行中ならグローバルリスナを張る。
  // 各ハンドラ内では getState() で最新の transient 状態を読む（マーキー矩形は
  // mousemove 毎にオブジェクトが変わるため、購読すると毎フレーム再登録になってしまう）。
  const isDraggingNode = useDiagramStore((s) => s.draggingNode !== null);
  const isDraggingBoundary = useDiagramStore((s) => s.draggingBoundary !== null);
  const isResizing = useDiagramStore((s) => s.resizingBoundary !== null);
  const isDraggingGroup = useDiagramStore((s) => s.draggingGroup !== null);
  const isMarquee = useDiagramStore((s) => s.marquee !== null);
  const isPanning = useDiagramStore((s) => s.panning !== null);

  useEffect(() => {
    if (
      !isDraggingNode &&
      !isDraggingBoundary &&
      !isResizing &&
      !isDraggingGroup &&
      !isMarquee &&
      !isPanning
    )
      return;

    const handleMouseMove = (e: MouseEvent) => {
      const s = useDiagramStore.getState();
      // ドラッグ・リサイズは画面差分をワールド差分へ変換する（÷scale）。パンは画面 px のまま。
      const scale = s.viewport.scale;
      if (s.panning) {
        s.panTo(e.clientX, e.clientY);
      }
      if (s.draggingNode) {
        s.setNodePosition(
          s.draggingNode.id,
          s.draggingNode.origX + (e.clientX - s.draggingNode.startClientX) / scale,
          s.draggingNode.origY + (e.clientY - s.draggingNode.startClientY) / scale,
        );
      }
      if (s.draggingBoundary) {
        s.setBoundaryPosition(
          s.draggingBoundary.id,
          s.draggingBoundary.origX + (e.clientX - s.draggingBoundary.startClientX) / scale,
          s.draggingBoundary.origY + (e.clientY - s.draggingBoundary.startClientY) / scale,
        );
      }
      if (s.resizingBoundary) {
        s.applyBoundaryResizeDelta(
          (e.clientX - s.resizingBoundary.startX) / scale,
          (e.clientY - s.resizingBoundary.startY) / scale,
        );
      }
      if (s.draggingGroup) {
        const dx = (e.clientX - s.draggingGroup.startClientX) / scale;
        const dy = (e.clientY - s.draggingGroup.startClientY) / scale;
        if (s.draggingGroup.nodeOrigins.length > 0) {
          s.setNodesPositions(
            s.draggingGroup.nodeOrigins.map((o) => ({ id: o.id, x: o.x + dx, y: o.y + dy })),
          );
        }
        if (s.draggingGroup.boundaryOrigins.length > 0) {
          s.setBoundariesPositions(
            s.draggingGroup.boundaryOrigins.map((o) => ({ id: o.id, x: o.x + dx, y: o.y + dy })),
          );
        }
      }
      if (s.marquee) {
        s.updateMarquee(e.clientX - s.marquee.offsetLeft, e.clientY - s.marquee.offsetTop);
      }
    };

    const handleMouseUp = () => {
      const s = useDiagramStore.getState();
      // 単一ノードドラッグ終了時のみ：他ノードへの再親付け/親解除を判定して反映
      // （グループ移動では reparent しない）。
      if (s.draggingNode) {
        const activeNodes = s.layers[s.activeLayer].nodes;
        const dragged = activeNodes.find((n) => n.id === s.draggingNode!.id);
        if (dragged) {
          const newParentId = findDropTargetParent(dragged, activeNodes, componentRegistry);
          if (newParentId !== dragged.parentId) {
            s.setNodeParent(dragged.id, newParentId);
          }
        }
      }
      if (s.marquee) s.endMarquee();
      s.endInteraction();
    };

    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, [isDraggingNode, isDraggingBoundary, isResizing, isDraggingGroup, isMarquee, isPanning]);
}
