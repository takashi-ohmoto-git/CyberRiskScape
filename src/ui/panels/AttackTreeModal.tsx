import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Check, ChevronDown, ChevronRight, Crosshair, GitBranch, Lock, ShieldHalf, X } from 'lucide-react';
import {
  selectActiveEdges,
  selectActiveNodes,
  useDiagramStore,
} from '../../core/state/diagramStore';
import { componentRegistry } from '../../component-library/defaultRegistry';
import { renderIcon } from '../../component-library/iconRegistry';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import { formatElementalId } from '../../core/model/elementalId';
import type { DiagramEdge, DiagramNode, ThreatView } from '../../core/model/types';
import { buildAttackGraph, type AttackGraphResult, type LogicalHop } from '../../features/attack-tree/buildAttackGraph';
import {
  aggregateLogicalHopEvidence,
  buildHopEvidence,
  edgeElementKey,
  nodeElementKey,
  NEUTRAL_EVIDENCE,
  type HopCoverage,
  type HopEvidence,
  type ThreatRef,
} from '../../features/attack-tree/hopEvidence';
import {
  analyzeAttackGraph,
  type AnalyzedRoute,
  type AnalyzeGraphResult,
  type ChokePoint,
} from '../../features/attack-tree/analyzeAttackGraph';
import { SEVERITY_BADGE_SOLID } from '../../core/model/severityColors';
import { CONTROL_STATUS_BADGE, CONTROL_STATUS_LABEL } from './controlStatusStyle';
import { useT } from '../../i18n';

/** i18n の t() 関数の型（useT の戻り値）。 */
type TFunc = ReturnType<typeof useT>;

interface AttackTreeModalProps {
  /** ルートとなる攻撃者ノード。attackObjectiveId 設定済みであること（呼び出し側でガード）。 */
  attacker: DiagramNode;
  /** アクティブレイヤーの全 ThreatView（経路上の全要素の DREAD/Control 集約に使う）。 */
  allThreats: ThreatView[];
  onClose: () => void;
}

const NODE_W = 208;
const NODE_H = 56;
const GAP_X = 28;
const ROW_GAP = 128;
const PAD = 20;

type Selection = { kind: 'node'; nodeId: string } | { kind: 'hop'; hopKey: string } | null;

/** ノード 1 件分の表示（アイコン + 表示名 + ElementalID）。ヘッダの攻撃者/標的チップに使用。 */
function StepNodeChip({ node, isTarget }: { node: DiagramNode; isTarget: boolean }) {
  const cfg = componentRegistry.get(node.type);
  return (
    <span
      className={`inline-flex items-center gap-2 px-2.5 py-1.5 rounded-lg border text-[11px] font-bold ${
        isTarget
          ? 'bg-rose-600/20 border-rose-500/60 text-rose-200'
          : 'bg-slate-800 border-slate-700 text-slate-200'
      }`}
    >
      <span className={`${cfg?.color ?? 'bg-slate-500'} p-1 rounded text-white`}>
        {renderIcon(cfg?.icon ?? { kind: 'builtin', name: 'box' }, { size: 10 })}
      </span>
      {node.seq !== undefined && (
        <span className="text-[9px] font-black text-slate-500">
          {formatElementalId('node', node.seq)}
        </span>
      )}
      {getNodeDisplayName(node)}
      {isTarget && <Crosshair size={12} className="text-rose-400" />}
    </span>
  );
}

/** レイアウト結果。ノード id → 座標（層＝攻撃者からの最小ホップ数）。 */
interface GraphLayout {
  positions: Map<string, { x: number; y: number; depth: number }>;
  width: number;
  height: number;
}

/**
 * 縦方向レイアウト（最上部=攻撃者 / 最下部=標的）。
 * 層割当は攻撃者からの BFS 最小ホップ数（min-depth）。標的は他ノードと同深度なら
 * 単独で 1 層下げる。同層内の x 座標は「浅い層の隣接ノードの平均 x」ヒューリスティックで
 * 決め、重なりが生じる場合のみ最小間隔を確保して補正する（厳密な交差最小化はしない）。
 */
function buildLayout(graph: AttackGraphResult, attackerId: string, targetId: string): GraphLayout | null {
  if (graph.nodeIds.length === 0) return null;

  const adj = new Map<string, string[]>();
  const addAdj = (a: string, b: string) => {
    const arr = adj.get(a) ?? [];
    arr.push(b);
    adj.set(a, arr);
  };
  for (const hop of graph.hops.values()) {
    addAdj(hop.a, hop.b);
    addAdj(hop.b, hop.a);
  }

  // BFS で攻撃者からの最小ホップ数を割当
  const depth = new Map<string, number>();
  depth.set(attackerId, 0);
  const queue: string[] = [attackerId];
  while (queue.length > 0) {
    const cur = queue.shift()!;
    const d = depth.get(cur)!;
    for (const next of adj.get(cur) ?? []) {
      if (!depth.has(next)) {
        depth.set(next, d + 1);
        queue.push(next);
      }
    }
  }
  for (const id of graph.nodeIds) {
    if (!depth.has(id)) depth.set(id, 0);
  }

  // 標的は他ノードと同深度なら単独で 1 層下げる
  const targetDepth = depth.get(targetId) ?? 0;
  const collision = graph.nodeIds.some((id) => id !== targetId && depth.get(id) === targetDepth);
  if (collision) {
    const maxDepth = Math.max(...graph.nodeIds.map((id) => depth.get(id) ?? 0));
    depth.set(targetId, maxDepth + 1);
  }

  // 層ごとにグルーピング
  const byDepth = new Map<number, string[]>();
  for (const id of graph.nodeIds) {
    const d = depth.get(id)!;
    const arr = byDepth.get(d) ?? [];
    arr.push(id);
    byDepth.set(d, arr);
  }
  const depths = [...byDepth.keys()].sort((a, b) => a - b);

  const SLOT = NODE_W + GAP_X;
  const x = new Map<string, number>();
  for (const d of depths) {
    const ids = byDepth.get(d)!;
    if (d === depths[0]) {
      ids.forEach((id, i) => x.set(id, i * SLOT));
      continue;
    }
    const raw = ids.map((id) => {
      const upperNeighbors = (adj.get(id) ?? []).filter((n) => x.has(n) && (depth.get(n) ?? 0) < d);
      const avg =
        upperNeighbors.length > 0
          ? upperNeighbors.reduce((sum, n) => sum + x.get(n)!, 0) / upperNeighbors.length
          : 0;
      return { id, avg };
    });
    raw.sort((a, b) => a.avg - b.avg);
    let prev = -Infinity;
    for (const r of raw) {
      const xPos = Math.max(r.avg, prev + SLOT);
      x.set(r.id, xPos);
      prev = xPos;
    }
  }

  const minX = Math.min(...[...x.values()]);
  const positions = new Map<string, { x: number; y: number; depth: number }>();
  for (const id of graph.nodeIds) {
    const d = depth.get(id)!;
    positions.set(id, { x: x.get(id)! - minX + PAD, y: d * ROW_GAP + PAD, depth: d });
  }

  const width = Math.max(...[...positions.values()].map((p) => p.x)) + NODE_W + PAD;
  const height = depths[depths.length - 1] * ROW_GAP + NODE_H + PAD * 2;

  return { positions, width, height };
}

const COVERAGE_ICON: Record<HopCoverage, typeof Lock | null> = { none: null, partial: ShieldHalf, full: Lock };

/** SVG 内の 1 ノードカード（foreignObject で既存のアイコン/配色を再利用）。 */
function NodeCard({
  node,
  x,
  y,
  isTarget,
  evidence,
  blocked,
  onWeakestRoute,
  hovered,
  selected,
  onSelect,
  t,
}: {
  node: DiagramNode;
  x: number;
  y: number;
  isTarget: boolean;
  evidence: HopEvidence;
  blocked: boolean;
  onWeakestRoute: boolean;
  hovered: boolean;
  selected: boolean;
  onSelect: () => void;
  t: TFunc;
}) {
  const cfg = componentRegistry.get(node.type);
  const CovIcon = COVERAGE_ICON[evidence.coverage];

  let frame = 'bg-slate-800 border-slate-700 text-slate-200';
  if (blocked) frame = 'bg-slate-800/40 border-slate-700 border-dashed text-slate-500';
  else if (hovered) frame = 'bg-sky-950/60 border-sky-400 text-sky-100';
  else if (onWeakestRoute) frame = 'bg-rose-950/60 border-rose-500 text-rose-100';
  else if (evidence.coverage === 'full') frame = 'bg-emerald-950/40 border-emerald-700/60 text-emerald-100';

  return (
    <foreignObject x={x} y={y} width={NODE_W} height={NODE_H}>
      <div
        role="button"
        tabIndex={0}
        onClick={onSelect}
        className={`h-full w-full rounded-lg border px-2 py-1 flex items-center gap-1.5 overflow-hidden cursor-pointer ${frame} ${
          selected ? 'ring-2 ring-sky-400' : ''
        }`}
      >
        <span className={`${cfg?.color ?? 'bg-slate-500'} p-1 rounded text-white shrink-0`}>
          {renderIcon(cfg?.icon ?? { kind: 'builtin', name: 'box' }, { size: 11 })}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1">
            {node.seq !== undefined && (
              <span className="text-[8px] font-black text-slate-500 shrink-0">
                {formatElementalId('node', node.seq)}
              </span>
            )}
            <span className="text-[10px] font-bold truncate">{getNodeDisplayName(node)}</span>
            {isTarget && <Crosshair size={10} className="text-rose-400 shrink-0" />}
          </div>
          <div className="flex items-center gap-1.5 text-[8px] font-bold text-slate-400">
            <span>
              {evidence.difficultyBasis === 'dread'
                ? t('attackTree.node.difficulty', { value: evidence.difficulty })
                : evidence.difficultyBasis === 'severity-soft'
                  ? t('attackTree.node.softDifficulty', { value: evidence.difficulty })
                  : t('attackTree.node.unevaluated')}
            </span>
            {CovIcon && (
              <span
                className={`flex items-center gap-0.5 ${
                  evidence.coverage === 'full' ? 'text-emerald-300' : 'text-amber-300'
                }`}
              >
                <CovIcon size={8} />
                {evidence.coverage === 'full' ? t('attackTree.coverage.full') : t('attackTree.coverage.partial')}
              </span>
            )}
            {evidence.threats.length > 0 && (
              <span className="text-slate-500 truncate">
                {t('attackTree.node.threatCount', { count: evidence.threats.length })}
              </span>
            )}
          </div>
        </div>
      </div>
    </foreignObject>
  );
}

/** 縦方向ベジェのリンクパス（同層ホップは側面へ膨らむ曲線）。 */
function hopPath(
  x1: number,
  y1: number,
  x2: number,
  y2: number,
  sideways: boolean,
): { d: string; mid: { x: number; y: number } } {
  if (sideways) {
    const bulge = NODE_W * 0.7;
    const d = `M${x1},${y1} C${x1 + bulge},${y1 - 40} ${x2 + bulge},${y2 - 40} ${x2},${y2}`;
    return { d, mid: { x: (x1 + x2) / 2 + bulge * 0.6, y: (y1 + y2) / 2 - 30 } };
  }
  const my = (y1 + y2) / 2;
  const d = `M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2}`;
  return { d, mid: { x: (x1 + x2) / 2, y: my } };
}

/** 検出根拠一覧の 1 行（脅威名 + severity + Exploitability + controlStatus）。 */
function ThreatRefRow({ threat }: { threat: ThreatRef }) {
  return (
    <div className="flex items-start justify-between gap-2 text-[10px]">
      <span className="text-slate-300 leading-snug">{threat.name}</span>
      <span className="flex items-center gap-1 shrink-0">
        <span className={`px-1.5 py-0.5 rounded font-black ${SEVERITY_BADGE_SOLID[threat.severity]}`}>
          {threat.severity}
        </span>
        {threat.exploitability !== undefined && (
          <span className="px-1 py-0.5 rounded bg-slate-700 text-slate-300 font-bold">
            E:{threat.exploitability}
          </span>
        )}
        {threat.controlStatus && (
          <span className={`px-1.5 py-0.5 rounded border font-bold ${CONTROL_STATUS_BADGE[threat.controlStatus]}`}>
            {CONTROL_STATUS_LABEL[threat.controlStatus]}
          </span>
        )}
      </span>
    </div>
  );
}

/** ノードの短縮表記（ElementalID があればそれ、無ければ表示名）。経路テーブルの短縮列に使う。 */
function nodeShortLabel(node: DiagramNode | undefined, nodeId: string): string {
  if (!node) return nodeId;
  return node.seq !== undefined ? formatElementalId('node', node.seq) : getNodeDisplayName(node);
}

/** ノードの完全表記（ElementalID + 表示名）。チョークポイントチップや title 属性に使う。 */
function nodeFullLabel(node: DiagramNode | undefined, nodeId: string): string {
  if (!node) return nodeId;
  return node.seq !== undefined
    ? `${formatElementalId('node', node.seq)} ${getNodeDisplayName(node)}`
    : getNodeDisplayName(node);
}

/** チョークポイント上位チップ 1 件分。ノード/ホップいずれかを表示し、クリックで該当要素を選択する。 */
function ChokePointChip({
  chokePoint,
  totalRoutes,
  nodeById,
  graph,
  onSelectNode,
  onSelectHop,
  t,
}: {
  chokePoint: ChokePoint;
  totalRoutes: number;
  nodeById: Map<string, DiagramNode>;
  graph: AttackGraphResult;
  onSelectNode: (nodeId: string) => void;
  onSelectHop: (hopKey: string) => void;
  t: TFunc;
}) {
  const isNode = chokePoint.elementKey.startsWith('node:');
  let label: string;
  let onClick: () => void;
  if (isNode) {
    const nodeId = chokePoint.elementKey.slice('node:'.length);
    label = nodeFullLabel(nodeById.get(nodeId), nodeId);
    onClick = () => onSelectNode(nodeId);
  } else {
    const hopKeyStr = chokePoint.elementKey.slice('hop:'.length);
    const hop = graph.hops.get(hopKeyStr);
    label = hop
      ? `${nodeFullLabel(nodeById.get(hop.a), hop.a)} ⇔ ${nodeFullLabel(nodeById.get(hop.b), hop.b)}`
      : hopKeyStr;
    onClick = () => onSelectHop(hopKeyStr);
  }

  const amber = chokePoint.coverage === 'none';
  const CovIcon = COVERAGE_ICON[chokePoint.coverage];

  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-left text-[10px] font-bold transition-colors ${
        amber
          ? 'bg-amber-950/40 border-amber-600/60 text-amber-200 hover:border-amber-500'
          : 'bg-slate-800/60 border-slate-700 text-slate-300 hover:border-slate-500'
      }`}
    >
      <Crosshair size={11} className={amber ? 'text-amber-400 shrink-0' : 'text-slate-500 shrink-0'} />
      <span className="flex flex-col leading-tight">
        <span className="truncate max-w-[220px]" title={label}>
          {label}
        </span>
        <span className="flex items-center gap-1 text-[9px] font-normal opacity-80">
          {t('attackTree.chokePoint.hits', { hits: chokePoint.routeHits, total: totalRoutes })}
          {CovIcon && (
            <CovIcon size={9} className={chokePoint.coverage === 'full' ? 'text-emerald-300' : 'text-amber-300'} />
          )}
        </span>
      </span>
    </button>
  );
}

/** 経路コスト表示（Infinity は「遮断」）。 */
function formatRouteCost(cost: number, t: TFunc): string {
  return Number.isFinite(cost) ? String(cost) : t('attackTree.routeTable.blocked');
}

/** 経路テーブル（折りたたみ可能。既定で開く）。行ホバーで onHoverRoute を通知しグラフ側をハイライトする。 */
function RouteTable({
  analysis,
  nodeById,
  graph,
  onHoverRoute,
  t,
}: {
  analysis: AnalyzeGraphResult;
  nodeById: Map<string, DiagramNode>;
  graph: AttackGraphResult;
  onHoverRoute: (index: number | null) => void;
  t: TFunc;
}) {
  const [open, setOpen] = useState(true);

  return (
    <div className="bg-slate-800/40 border border-slate-700 rounded-xl">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center gap-1.5 px-3 py-2 text-[10px] font-black uppercase tracking-widest text-slate-300"
      >
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        {t('attackTree.routeTable.heading')}
      </button>
      {open && (
        <div className="overflow-auto max-h-40 px-3 pb-3" onMouseLeave={() => onHoverRoute(null)}>
          <table className="w-full text-[10px] text-slate-300">
            <thead>
              <tr className="text-slate-500 text-left border-b border-slate-700">
                <th className="py-1 pr-2 font-bold">#</th>
                <th className="py-1 pr-2 font-bold">{t('attackTree.routeTable.colRoute')}</th>
                <th className="py-1 pr-2 font-bold">{t('attackTree.routeTable.colCost')}</th>
                <th className="py-1 pr-2 font-bold">{t('attackTree.routeTable.colWeakestHop')}</th>
                <th className="py-1 pr-2 font-bold">{t('attackTree.routeTable.colStatus')}</th>
              </tr>
            </thead>
            <tbody>
              {analysis.routes.map((r: AnalyzedRoute, i: number) => {
                const shortLabel = r.route.nodeIds.map((id) => nodeShortLabel(nodeById.get(id), id)).join(' → ');
                const fullLabel = r.route.nodeIds.map((id) => nodeFullLabel(nodeById.get(id), id)).join(' → ');
                const hop = graph.hops.get(r.weakestHopKey);
                const weakestLabel = hop
                  ? `${nodeFullLabel(nodeById.get(hop.a), hop.a)} ⇔ ${nodeFullLabel(nodeById.get(hop.b), hop.b)}`
                  : '—';
                return (
                  <tr
                    key={i}
                    className="border-b border-slate-800/60 last:border-b-0 cursor-default hover:bg-sky-950/30"
                    onMouseEnter={() => onHoverRoute(i)}
                  >
                    <td className="py-1 pr-2 text-slate-500 font-bold">{i + 1}</td>
                    <td className="py-1 pr-2 max-w-[360px] truncate" title={fullLabel}>
                      {shortLabel}
                    </td>
                    <td className={`py-1 pr-2 font-bold ${r.feasible ? '' : 'text-slate-500'}`}>
                      {formatRouteCost(r.cost, t)}
                    </td>
                    <td className="py-1 pr-2 max-w-[220px] truncate" title={weakestLabel}>
                      {weakestLabel}
                    </td>
                    <td className={`py-1 pr-2 font-bold ${r.feasible ? 'text-rose-300' : 'text-emerald-300'}`}>
                      {r.feasible ? t('attackTree.routeTable.statusFeasible') : t('attackTree.routeTable.statusBlocked')}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/**
 * 攻撃者から標的（objective）までの攻撃経路グラフ（DAG）を縦方向に表示するモーダル。
 * buildAttackGraph → buildHopEvidence → analyzeAttackGraph の結果を用い、
 * ノード/ホップの検出根拠（発火中の脅威）をクリックで右パネルに表示する。
 */
export function AttackTreeModal({ attacker, allThreats, onClose }: AttackTreeModalProps) {
  const nodes = useDiagramStore(selectActiveNodes);
  const edges = useDiagramStore(selectActiveEdges);
  const [residualOnly, setResidualOnly] = useState(false);
  const [selection, setSelection] = useState<Selection>(null);
  const [hoveredRouteIndex, setHoveredRouteIndex] = useState<number | null>(null);
  const t = useT();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const targetId = attacker.attackObjectiveId ?? '';
  const target = nodes.find((n) => n.id === targetId);

  useEffect(() => {
    setSelection(null);
  }, [attacker.id, targetId]);

  const graph = useMemo(
    () => buildAttackGraph(nodes, edges, attacker.id, targetId),
    [nodes, edges, attacker.id, targetId],
  );

  const evidenceMap = useMemo(() => buildHopEvidence(allThreats), [allThreats]);
  const getEvidence = (key: string): HopEvidence => evidenceMap.get(key) ?? NEUTRAL_EVIDENCE;

  const analysis: AnalyzeGraphResult = useMemo(
    () => analyzeAttackGraph(graph, getEvidence, residualOnly),
    [graph, evidenceMap, residualOnly],
  );

  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.id, n] as const)), [nodes]);
  const edgeById = useMemo(() => new Map(edges.map((e) => [e.id, e] as const)), [edges]);

  const layout = useMemo(
    () => buildLayout(graph, attacker.id, targetId),
    [graph, attacker.id, targetId],
  );

  const hasPath = graph.routes.length > 0 && layout !== null;

  const weakestRoute = analysis.feasible ? analysis.routes[0] : undefined;
  const weakestNodeIds = useMemo(() => new Set(weakestRoute?.route.nodeIds ?? []), [weakestRoute]);
  const weakestHopKeys = useMemo(() => new Set(weakestRoute?.route.hopKeys ?? []), [weakestRoute]);

  // 経路テーブルの行ホバー中は最脆弱パス表示より優先してハイライトする
  const hoveredRoute =
    hoveredRouteIndex !== null ? analysis.routes[hoveredRouteIndex] : undefined;
  const hoveredNodeIds = useMemo(() => new Set(hoveredRoute?.route.nodeIds ?? []), [hoveredRoute]);
  const hoveredHopKeys = useMemo(() => new Set(hoveredRoute?.route.hopKeys ?? []), [hoveredRoute]);

  // チョークポイント上位（routeHits >= 2 のみ。単一経路しか無い等で該当なしなら空）
  const topChokePoints = useMemo(
    () => analysis.chokePoints.filter((cp) => cp.routeHits >= 2).slice(0, 3),
    [analysis.chokePoints],
  );

  // 残存経路モードで到達可能な（=いずれかの feasible な経路に含まれる）ノード/ホップ
  const feasibleNodeIds = useMemo(() => {
    const s = new Set<string>();
    for (const r of analysis.routes) if (r.feasible) for (const id of r.route.nodeIds) s.add(id);
    return s;
  }, [analysis.routes]);
  const feasibleHopKeys = useMemo(() => {
    const s = new Set<string>();
    for (const r of analysis.routes) if (r.feasible) for (const k of r.route.hopKeys) s.add(k);
    return s;
  }, [analysis.routes]);

  const selectNode = (nodeId: string) =>
    setSelection((cur) => (cur?.kind === 'node' && cur.nodeId === nodeId ? null : { kind: 'node', nodeId }));
  const selectHop = (hopKey: string) =>
    setSelection((cur) => (cur?.kind === 'hop' && cur.hopKey === hopKey ? null : { kind: 'hop', hopKey }));

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-150"
      onMouseDown={onClose}
    >
      <style>{`@keyframes atkdash { to { stroke-dashoffset: -1000; } }`}</style>
      <div
        className={`${selection ? 'w-[1180px]' : 'w-[880px]'} max-w-[96vw] max-h-[90vh] overflow-hidden bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 flex flex-col gap-4`}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
            <GitBranch size={16} className="text-rose-400" /> {t('attackTree.title')}
          </h2>
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            aria-label="閉じる"
          >
            <X size={16} />
          </button>
        </div>

        <div className="flex items-center gap-2 text-[11px] font-bold text-slate-400 flex-wrap">
          <StepNodeChip node={attacker} isTarget={false} />
          <span className="text-slate-600">→</span>
          {target ? (
            <StepNodeChip node={target} isTarget={true} />
          ) : (
            <span className="text-slate-500">{t('attackTree.targetMissing')}</span>
          )}
          <span className="ml-auto flex items-center gap-3 text-[10px] font-black">
            <span className="text-slate-500">
              {t('attackTree.routesSummary', {
                routes: graph.routes.length,
                combinations: graph.channelCombinations,
              })}
            </span>
            {hasPath && (
              <span className={analysis.feasible ? 'text-rose-300' : 'text-emerald-300'}>
                {analysis.feasible ? t('attackTree.minCost', { cost: analysis.minCost }) : t('attackTree.allBlocked')}
              </span>
            )}
            {hasPath && analysis.allUnevaluated && (
              <span className="text-slate-500 font-bold normal-case">{t('attackTree.allUnevaluatedNote')}</span>
            )}
          </span>
        </div>

        {/* 凡例 + トグル */}
        {hasPath && (
          <div className="flex items-center gap-4 text-[10px] font-bold text-slate-400 flex-wrap">
            <span className="flex items-center gap-1">
              <span className="w-3 h-0.5 bg-rose-500" /> {t('attackTree.legend.weakestRoute')}
            </span>
            <span className="flex items-center gap-1">
              <Lock size={10} className="text-emerald-300" /> {t('attackTree.legend.covered')}
            </span>
            <span className="flex items-center gap-1">
              <ShieldHalf size={10} className="text-amber-300" /> {t('attackTree.legend.partial')}
            </span>
            <span className="flex items-center gap-1">
              <span className="w-3 h-0.5 bg-slate-500 opacity-50" /> {t('attackTree.legend.noEvidence')}
            </span>
            <label className="ml-auto flex items-center gap-1.5 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={residualOnly}
                onChange={(e) => setResidualOnly(e.target.checked)}
                className="accent-rose-500"
              />
              {t('attackTree.residualToggle')}
            </label>
          </div>
        )}

        {hasPath && topChokePoints.length > 0 && (
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">
              {t('attackTree.chokePoint.heading')}
            </span>
            {topChokePoints.map((cp) => (
              <ChokePointChip
                key={cp.elementKey}
                chokePoint={cp}
                totalRoutes={graph.routes.length}
                nodeById={nodeById}
                graph={graph}
                onSelectNode={selectNode}
                onSelectHop={selectHop}
                t={t}
              />
            ))}
          </div>
        )}

        <div className="flex gap-3 min-h-0 flex-1">
          {hasPath ? (
            <div className="bg-slate-800/40 border border-slate-700 rounded-xl p-2 overflow-auto flex-1 min-w-0 min-h-0">
              <svg width={layout.width} height={layout.height} className="block">
                <g fill="none">
                  {[...graph.hops.values()].map((hop) => {
                    const posA = layout.positions.get(hop.a);
                    const posB = layout.positions.get(hop.b);
                    if (!posA || !posB) return null;
                    const [top, bottom] = posA.depth <= posB.depth ? [posA, posB] : [posB, posA];
                    const sideways = top.depth === bottom.depth;
                    const x1 = top.x + NODE_W / 2;
                    const y1 = sideways ? top.y + NODE_H / 2 : top.y + NODE_H;
                    const x2 = bottom.x + NODE_W / 2;
                    const y2 = sideways ? bottom.y + NODE_H / 2 : bottom.y;
                    const { d, mid } = hopPath(x1, y1, x2, y2, sideways);

                    const onWeakestRoute = weakestHopKeys.has(hop.key);
                    const hovered = hoveredHopKeys.has(hop.key);
                    const blocked = residualOnly && !feasibleHopKeys.has(hop.key);
                    const hasEvidence = hop.edgeIds.some((id) => getEvidence(edgeElementKey(id)).threats.length > 0);
                    const selected = selection?.kind === 'hop' && selection.hopKey === hop.key;

                    let stroke = '#334155';
                    let strokeWidth = 1.5;
                    let dash: string | undefined;
                    let animate = false;
                    if (blocked) {
                      stroke = '#475569';
                      dash = '3 4';
                    } else if (hovered) {
                      stroke = '#38bdf8';
                      strokeWidth = 2.5;
                      dash = '6 4';
                      animate = true;
                    } else if (onWeakestRoute) {
                      stroke = '#f43f5e';
                      strokeWidth = 2.5;
                      dash = '6 4';
                      animate = true;
                    } else if (!hasEvidence) {
                      stroke = '#64748b';
                    }
                    if (selected) {
                      stroke = '#38bdf8';
                      strokeWidth = 3;
                      dash = undefined;
                      animate = false;
                    }

                    return (
                      <g key={hop.key}>
                        <path
                          d={d}
                          stroke="transparent"
                          strokeWidth={14}
                          className="cursor-pointer"
                          onClick={() => selectHop(hop.key)}
                        />
                        <path
                          d={d}
                          stroke={stroke}
                          strokeWidth={strokeWidth}
                          strokeOpacity={!hasEvidence && !blocked && !onWeakestRoute && !hovered && !selected ? 0.5 : 1}
                          strokeDasharray={dash}
                          style={animate ? { animation: 'atkdash 30s linear infinite' } : undefined}
                        />
                        {(() => {
                          const hopEv = aggregateLogicalHopEvidence(hop, getEvidence);
                          const chipW =
                            hop.edgeIds.length >= 2 || hopEv.threats.length > 0 || hopEv.difficultyBasis !== 'neutral'
                              ? 56
                              : 40;
                          const label =
                            hopEv.difficultyBasis === 'dread'
                              ? String(hopEv.difficulty)
                              : hopEv.difficultyBasis === 'severity-soft'
                                ? `~${hopEv.difficulty}`
                                : '·';
                          const titleParts = [
                            hopEv.difficultyBasis === 'dread'
                              ? t('attackTree.node.difficulty', { value: hopEv.difficulty })
                              : hopEv.difficultyBasis === 'severity-soft'
                                ? t('attackTree.node.softDifficulty', { value: hopEv.difficulty })
                                : t('attackTree.hop.noEvidence'),
                            hopEv.coverage === 'full'
                              ? t('attackTree.coverage.full')
                              : hopEv.coverage === 'partial'
                                ? t('attackTree.coverage.partial')
                                : '',
                          ].filter(Boolean);
                          return (
                            <g
                              className="cursor-pointer"
                              onClick={() => selectHop(hop.key)}
                              transform={`translate(${mid.x}, ${mid.y})`}
                            >
                              <title>{titleParts.join(' · ')}</title>
                              <rect
                                x={-chipW / 2}
                                y={-10}
                                width={chipW}
                                height={20}
                                rx={4}
                                fill="#1e293b"
                                stroke={selected ? '#38bdf8' : hopEv.threats.length === 0 ? '#475569' : '#64748b'}
                              />
                              <text
                                x={0}
                                y={4}
                                textAnchor="middle"
                                fontSize={9}
                                fontWeight={900}
                                fill={
                                  hopEv.difficultyBasis === 'severity-soft'
                                    ? '#fbbf24'
                                    : hopEv.threats.length === 0
                                      ? '#94a3b8'
                                      : '#e2e8f0'
                                }
                              >
                                {label}
                                {hop.edgeIds.length >= 2
                                  ? ` ${t('attackTree.hop.channelCount', { count: hop.edgeIds.length })}`
                                  : ''}
                              </text>
                            </g>
                          );
                        })()}
                      </g>
                    );
                  })}
                </g>
                {graph.nodeIds.map((nodeId) => {
                  const node = nodeById.get(nodeId);
                  const pos = layout.positions.get(nodeId);
                  if (!node || !pos) return null;
                  return (
                    <NodeCard
                      key={nodeId}
                      node={node}
                      x={pos.x}
                      y={pos.y}
                      isTarget={nodeId === targetId}
                      evidence={getEvidence(nodeElementKey(nodeId))}
                      blocked={residualOnly && !feasibleNodeIds.has(nodeId)}
                      onWeakestRoute={weakestNodeIds.has(nodeId)}
                      hovered={hoveredNodeIds.has(nodeId)}
                      selected={selection?.kind === 'node' && selection.nodeId === nodeId}
                      onSelect={() => selectNode(nodeId)}
                      t={t}
                    />
                  );
                })}
              </svg>
            </div>
          ) : (
            <div className="bg-slate-800/40 border border-slate-700 rounded-xl p-6 text-center flex-1">
              <p className="text-xs text-slate-400 font-bold">{t('attackTree.noPath.title')}</p>
              <p className="text-[10px] text-slate-500 mt-2 leading-relaxed">{t('attackTree.noPath.body')}</p>
            </div>
          )}

          {selection && (
            <DetailPanel
              selection={selection}
              graph={graph}
              analysis={analysis}
              nodeById={nodeById}
              edgeById={edgeById}
              getEvidence={getEvidence}
              onClose={() => setSelection(null)}
              t={t}
            />
          )}
        </div>

        {hasPath && graph.routes.length >= 2 && (
          <RouteTable
            analysis={analysis}
            nodeById={nodeById}
            graph={graph}
            onHoverRoute={setHoveredRouteIndex}
            t={t}
          />
        )}

        {graph.truncated && <p className="text-[10px] text-amber-400/80 font-bold">⚠ {t('attackTree.truncated')}</p>}

        <p className="text-[9px] text-slate-500 leading-relaxed">{t('attackTree.footnote')}</p>
      </div>
    </div>
  );
}

/** ノード/ホップの検出根拠を表示する右サイドパネル。 */
function DetailPanel({
  selection,
  graph,
  analysis,
  nodeById,
  edgeById,
  getEvidence,
  onClose,
  t,
}: {
  selection: NonNullable<Selection>;
  graph: AttackGraphResult;
  analysis: AnalyzeGraphResult;
  nodeById: Map<string, DiagramNode>;
  edgeById: Map<string, DiagramEdge>;
  getEvidence: (key: string) => HopEvidence;
  onClose: () => void;
  t: TFunc;
}) {
  let heading: string;
  let body: ReactNode;

  if (selection.kind === 'node') {
    const node = nodeById.get(selection.nodeId);
    const evidence = getEvidence(nodeElementKey(selection.nodeId));
    heading = t('attackTree.detail.nodeHeading', { name: node ? getNodeDisplayName(node) : selection.nodeId });
    body =
      evidence.threats.length === 0 ? (
        <p className="text-[10px] text-slate-500">{t('attackTree.detail.noThreats')}</p>
      ) : (
        <div className="space-y-1.5">
          {evidence.threats.map((th) => (
            <ThreatRefRow key={th.threatId} threat={th} />
          ))}
        </div>
      );
  } else {
    const hop: LogicalHop | undefined = graph.hops.get(selection.hopKey);
    heading = t('attackTree.detail.hopHeading');
    // 最脆弱経路上での通過方向（ノード列の隣接順）
    const weakest = analysis.routes[0];
    let travelFrom: string | undefined;
    let travelTo: string | undefined;
    if (weakest && hop) {
      const ids = weakest.route.nodeIds;
      for (let i = 0; i < ids.length - 1; i++) {
        const a = ids[i];
        const b = ids[i + 1];
        if ((a === hop.a && b === hop.b) || (a === hop.b && b === hop.a)) {
          travelFrom = a;
          travelTo = b;
          break;
        }
      }
    }
    const hopAgg = hop ? aggregateLogicalHopEvidence(hop, getEvidence) : NEUTRAL_EVIDENCE;
    body = (
      <div className="space-y-3">
        {hop && (
          <div className="space-y-1">
            <p className="text-[10px] font-bold text-slate-400">
              {t('attackTree.detail.hopEndpoints', {
                a: nodeFullLabel(nodeById.get(hop.a), hop.a),
                b: nodeFullLabel(nodeById.get(hop.b), hop.b),
              })}
            </p>
            {travelFrom && travelTo && (
              <p className="text-[10px] text-rose-300/90 font-bold">
                {t('attackTree.detail.travelDirection', {
                  from: nodeFullLabel(nodeById.get(travelFrom), travelFrom),
                  to: nodeFullLabel(nodeById.get(travelTo), travelTo),
                })}
              </p>
            )}
            <p className="text-[10px] text-slate-500">
              {hopAgg.difficultyBasis === 'dread'
                ? t('attackTree.node.difficulty', { value: hopAgg.difficulty })
                : hopAgg.difficultyBasis === 'severity-soft'
                  ? t('attackTree.node.softDifficulty', { value: hopAgg.difficulty })
                  : t('attackTree.hop.noEvidence')}
              {hopAgg.threats.length > 0
                ? ` · ${t('attackTree.node.threatCount', { count: hopAgg.threats.length })}`
                : ''}
            </p>
          </div>
        )}
        {(hop?.edgeIds ?? []).map((edgeId) => {
          const edge = edgeById.get(edgeId);
          const evidence = getEvidence(edgeElementKey(edgeId));
          const chosen = analysis.routes.some((r) => r.chosenChannels.get(selection.hopKey) === edgeId);
          return (
            <div key={edgeId} className="border-t border-white/5 pt-2 first:border-t-0 first:pt-0">
              <div className="flex items-center gap-1.5 text-[10px] font-black text-slate-400 mb-1">
                {edge?.seq !== undefined && <span>{formatElementalId('edge', edge.seq)}</span>}
                {edge?.dataFlowName && <span className="text-slate-500">{edge.dataFlowName}</span>}
                {chosen && (
                  <span className="flex items-center gap-0.5 text-sky-300">
                    <Check size={10} /> {t('attackTree.detail.chosenChannel')}
                  </span>
                )}
              </div>
              {evidence.threats.length === 0 ? (
                <p className="text-[10px] text-slate-500">{t('attackTree.detail.noThreats')}</p>
              ) : (
                <div className="space-y-1.5">
                  {evidence.threats.map((th) => (
                    <ThreatRefRow key={th.threatId} threat={th} />
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  }

  return (
    <div className="w-72 shrink-0 overflow-y-auto bg-slate-800/40 border border-slate-700 rounded-xl p-3 flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <h3 className="text-[10px] font-black uppercase tracking-widest text-slate-300">{heading}</h3>
        <button onClick={onClose} className="text-slate-500 hover:text-slate-200" aria-label={t('attackTree.detail.close')}>
          <X size={14} />
        </button>
      </div>
      {body}
      <p className="text-[9px] text-slate-500 leading-relaxed border-t border-white/5 pt-2 mt-auto">
        {t('attackTree.detail.formula')}
      </p>
    </div>
  );
}
