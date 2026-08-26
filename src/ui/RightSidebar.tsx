import type { ThreatView } from '../core/model/types';
import {
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
import { ThreatListPanel } from './panels/ThreatListPanel';

interface RightSidebarProps {
  threats: ThreatView[];
}

export function RightSidebar({ threats }: RightSidebarProps) {
  const nodes = useDiagramStore(selectActiveNodes);
  const edges = useDiagramStore(selectActiveEdges);
  const boundaries = useDiagramStore(selectActiveBoundaries);
  const selectedNodeId = useDiagramStore(selectPrimaryNodeId);
  const selectedEdgeId = useDiagramStore((s) => s.selectedEdgeId);
  const selectedBoundaryId = useDiagramStore(selectPrimaryBoundaryId);

  const selectedNode = nodes.find((n) => n.id === selectedNodeId) ?? null;
  const selectedEdge = edges.find((e) => e.id === selectedEdgeId) ?? null;
  const selectedBoundary = boundaries.find((b) => b.id === selectedBoundaryId) ?? null;

  return (
    <aside className="w-96 bg-slate-900 border-l border-slate-800 flex flex-col z-50 shadow-2xl overflow-y-auto animate-in slide-in-from-right duration-300">
      {selectedBoundary ? (
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
