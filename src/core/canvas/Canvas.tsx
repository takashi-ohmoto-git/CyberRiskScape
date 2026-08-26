import { useEffect, useMemo, useRef, useState, type MouseEvent, type ReactNode } from 'react';
import type { DiagramNode, ResizeHandle, ThreatView } from '../model/types';
import { isSuppressed } from '../model/types';
import {
  selectActiveBoundaries,
  selectActiveEdges,
  selectActiveNodes,
  useDiagramStore,
} from '../state/diagramStore';
import { NodeView } from './NodeView';
import { BoundaryView } from './BoundaryView';
import { EdgeLayer } from './EdgeLayer';

interface CanvasProps {
  threats: ThreatView[];
  children?: ReactNode;
}

export function Canvas({ threats, children }: CanvasProps) {
  const nodes = useDiagramStore(selectActiveNodes);
  const edges = useDiagramStore(selectActiveEdges);
  const boundaries = useDiagramStore(selectActiveBoundaries);
  const selectedNodeIds = useDiagramStore((s) => s.selectedNodeIds);
  const selectedEdgeId = useDiagramStore((s) => s.selectedEdgeId);
  const selectedBoundaryIds = useDiagramStore((s) => s.selectedBoundaryIds);
  const marquee = useDiagramStore((s) => s.marquee);
  const viewport = useDiagramStore((s) => s.viewport);

  const beginNodeInteraction = useDiagramStore((s) => s.beginNodeInteraction);
  const beginBoundaryInteraction = useDiagramStore((s) => s.beginBoundaryInteraction);
  const beginBoundaryResize = useDiagramStore((s) => s.beginBoundaryResize);
  const beginMarquee = useDiagramStore((s) => s.beginMarquee);
  const selectNode = useDiagramStore((s) => s.selectNode);
  const selectEdge = useDiagramStore((s) => s.selectEdge);
  const deleteNode = useDiagramStore((s) => s.deleteNode);
  const deleteBoundary = useDiagramStore((s) => s.deleteBoundary);
  const linkingFromId = useDiagramStore((s) => s.linkingFromId);
  const setCanvasSize = useDiagramStore((s) => s.setCanvasSize);
  const zoomAtLocal = useDiagramStore((s) => s.zoomAtLocal);
  const beginPan = useDiagramStore((s) => s.beginPan);

  const mainRef = useRef<HTMLElement>(null);
  // Space 押下中はパンモード。mousedown 内で同期参照するため ref、カーソル表示用に state。
  const spaceHeldRef = useRef(false);
  const [spaceHeld, setSpaceHeld] = useState(false);

  // main の実寸をストアへ同期（zoomIn/Out/Fit の中心・収め計算に使う）。
  useEffect(() => {
    const el = mainRef.current;
    if (!el) return;
    const sync = () => setCanvasSize(el.clientWidth, el.clientHeight);
    sync();
    const ro = new ResizeObserver(sync);
    ro.observe(el);
    return () => ro.disconnect();
  }, [setCanvasSize]);

  // ホイールズーム。React の onWheel は passive で preventDefault が効かないため、
  // ネイティブの非 passive リスナを張る。
  useEffect(() => {
    const el = mainRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const rect = el.getBoundingClientRect();
      const factor = Math.exp(-e.deltaY * 0.0015);
      zoomAtLocal(e.clientX - rect.left, e.clientY - rect.top, factor);
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, [zoomAtLocal]);

  // Space 押下/解放の追跡（入力欄ではパンモードにしない）。
  useEffect(() => {
    const isTypingTarget = (t: EventTarget | null): boolean => {
      const el = t as HTMLElement | null;
      return !!el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable);
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.code === 'Space' && !isTypingTarget(e.target)) {
        e.preventDefault();
        spaceHeldRef.current = true;
        setSpaceHeld(true);
      }
    };
    const onKeyUp = (e: KeyboardEvent) => {
      if (e.code === 'Space') {
        spaceHeldRef.current = false;
        setSpaceHeld(false);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    window.addEventListener('keyup', onKeyUp);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      window.removeEventListener('keyup', onKeyUp);
    };
  }, []);

  const selectedIdSet = useMemo(() => new Set(selectedNodeIds), [selectedNodeIds]);
  const selectedBoundaryIdSet = useMemo(
    () => new Set(selectedBoundaryIds),
    [selectedBoundaryIds],
  );

  // 子バッジクリック：リンク作成中なら端点として確定（beginNodeInteraction にリンク完了処理が
  // 入っている）。それ以外は選択のみ（バッジはドラッグ対象にしない）。
  const onSelectChild = (childId: string) => {
    if (linkingFromId) {
      // linking 完了経路は clientX/Y を使わないので 0 で良い。
      beginNodeInteraction(childId, 0, 0);
    } else {
      selectNode(childId);
    }
  };

  // 親が存在するノードは親のバッジとして描画されるためトップレベル一覧から除外する。
  // 親 ID が指す対象が存在しない孤児は安全側に倒してトップレベル扱い。
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

  const onNodeMouseDown = (e: MouseEvent, nodeId: string) => {
    e.stopPropagation();
    beginNodeInteraction(nodeId, e.clientX, e.clientY, e.shiftKey);
  };

  // 背景（main 自身）での mousedown のみ。変換ラッパは pointer-events-none のため、
  // ノード/境界/エッジ以外の空白クリックは pan/zoom に関わらず main に届く。
  // Space 押下中はパン、それ以外はマーキー開始。
  const onCanvasMouseDown = (e: MouseEvent<HTMLElement>) => {
    if (e.target !== e.currentTarget) return;
    if (linkingFromId) return;
    if (spaceHeldRef.current) {
      beginPan(e.clientX, e.clientY);
      return;
    }
    const rect = e.currentTarget.getBoundingClientRect();
    beginMarquee(rect.left, rect.top, e.clientX - rect.left, e.clientY - rect.top);
  };

  const onBoundaryMouseDown = (e: MouseEvent, boundaryId: string) => {
    e.stopPropagation();
    beginBoundaryInteraction(boundaryId, e.clientX, e.clientY, e.shiftKey);
  };

  const onBoundaryResizeStart = (e: MouseEvent, boundaryId: string, handle: ResizeHandle) => {
    beginBoundaryResize(boundaryId, handle, e.clientX, e.clientY);
  };

  const cursor = spaceHeld ? 'cursor-grab active:cursor-grabbing' : '';

  return (
    <main
      ref={mainRef}
      onMouseDown={onCanvasMouseDown}
      className={`flex-1 relative overflow-hidden transition-colors duration-300 ${cursor}`}
      style={{
        // ドットグリッドはビューポートに追従させる（パンで動き、ズームで間隔が変わる）。
        backgroundImage: 'radial-gradient(#1e293b 1.5px, transparent 1.5px)',
        backgroundSize: `${32 * viewport.scale}px ${32 * viewport.scale}px`,
        backgroundPosition: `${viewport.tx}px ${viewport.ty}px`,
        touchAction: 'none',
      }}
    >
      {/* UI オーバーレイ（TopControls / LinkingIndicator）は変換の外側 */}
      {children}

      {/* ダイアグラム本体は 1 枚の変換ラッパに集約。pointer-events-none にして、
          空白クリックを main へ通す（ノード/境界/エッジは各自で auto に戻す）。 */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          transform: `translate(${viewport.tx}px, ${viewport.ty}px) scale(${viewport.scale})`,
          transformOrigin: '0 0',
        }}
      >
        {boundaries.map((boundary) => (
          <BoundaryView
            key={boundary.id}
            boundary={boundary}
            isSelected={selectedBoundaryIdSet.has(boundary.id)}
            onMouseDown={onBoundaryMouseDown}
            onResizeStart={onBoundaryResizeStart}
            onDelete={deleteBoundary}
          />
        ))}

        <EdgeLayer
          nodes={nodes}
          edges={edges}
          selectedEdgeId={selectedEdgeId}
          onSelectEdge={selectEdge}
        />

        {topLevelNodes.map((node) => {
          // 子ノードはキャンバス本体に描画されないため、子に紐づく脅威も親バッジに含めて
          // 可視化する（脅威バッジは内包コンポーネント発の脅威も集約）。
          const children = childrenByParent.get(node.id) ?? [];
          const childThreatIds = new Set(children.map((c) => c.id));
          // 抑制済み（リスク受容 / 誤検知）はアクティブ脅威ではないためバッジから除外する。
          const aggregatedThreats = threats.filter(
            (t) => !isSuppressed(t) && (t.nodeId === node.id || childThreatIds.has(t.nodeId)),
          );
          return (
            <NodeView
              key={node.id}
              node={node}
              childNodes={children}
              isSelected={selectedIdSet.has(node.id)}
              threats={aggregatedThreats}
              onMouseDown={onNodeMouseDown}
              onSelectChild={onSelectChild}
              onDelete={deleteNode}
            />
          );
        })}
      </div>

      {/* マーキーは main ローカル座標で描画（変換の外側）。内包判定は endMarquee で
          ワールド座標へ変換する。 */}
      {marquee && (
        <div
          className="absolute z-40 border border-blue-400 bg-blue-400/15 pointer-events-none"
          style={{
            left: Math.min(marquee.startX, marquee.curX),
            top: Math.min(marquee.startY, marquee.curY),
            width: Math.abs(marquee.curX - marquee.startX),
            height: Math.abs(marquee.curY - marquee.startY),
          }}
        />
      )}
    </main>
  );
}
