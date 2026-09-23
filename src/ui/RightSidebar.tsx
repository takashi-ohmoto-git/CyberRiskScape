import type { ThreatView } from '../core/model/types';
import {
  selectActiveAnnotations,
  selectActiveBoundaries,
  selectActiveEdges,
  selectActiveNodes,
  selectPrimaryBoundaryId,
  selectPrimaryNodeId,
  useDiagramStore,
} from '../core/state/diagramStore';
import { NodePanel } from './panels/NodePanel';
import { EdgePanel } from './panels/EdgePanel';
import { BoundaryPanel } from './panels/BoundaryPanel';
import { AnnotationPanel } from './panels/AnnotationPanel';
import { ThreatListPanel } from './panels/ThreatListPanel';

interface RightSidebarProps {
  threats: ThreatView[];
}

export function RightSidebar({ threats }: RightSidebarProps) {
  const nodes = useDiagramStore(selectActiveNodes);
  const edges = useDiagramStore(selectActiveEdges);
  const boundaries = useDiagramStore(selectActiveBoundaries);
  const annotations = useDiagramStore(selectActiveAnnotations);
  const selectedNodeId = useDiagramStore(selectPrimaryNodeId);
  const selectedEdgeId = useDiagramStore((s) => s.selectedEdgeId);
  const selectedBoundaryId = useDiagramStore(selectPrimaryBoundaryId);
  const selectedAnnotationId = useDiagramStore((s) => s.selectedAnnotationId);

  const selectedNode = nodes.find((n) => n.id === selectedNodeId) ?? null;
  const selectedEdge = edges.find((e) => e.id === selectedEdgeId) ?? null;
  const selectedBoundary = boundaries.find((b) => b.id === selectedBoundaryId) ?? null;
  const selectedAnnotation = annotations.find((a) => a.id === selectedAnnotationId) ?? null;

  return (
    <aside className="w-96 bg-slate-900 border-l border-slate-800 flex flex-col z-50 shadow-2xl overflow-y-auto animate-in slide-in-from-right duration-300">
      {selectedAnnotation ? (
        <AnnotationPanel annotation={selectedAnnotation} />
      ) : selectedBoundary ? (
        <BoundaryPanel boundary={selectedBoundary} />
      ) : selectedNode ? (
        <NodePanel
          node={selectedNode}
          threats={threats.filter((t) => t.nodeId === selectedNode.id)}
          allThreats={threats}
        />
      ) : selectedEdge ? (
        <EdgePanel edge={selectedEdge} />
      ) : (
        <ThreatListPanel threats={threats} />
      )}
    </aside>
  );
}
