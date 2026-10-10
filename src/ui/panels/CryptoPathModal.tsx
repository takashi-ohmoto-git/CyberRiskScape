import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Check, Lock, Plus, Route, Scissors, X } from 'lucide-react';
import {
  selectActiveBoundaries,
  selectActiveEdges,
  selectActiveNodes,
  useDiagramStore,
} from '../../core/state/diagramStore';
import { getComponentRegistry } from '../../component-library/defaultRegistry';
import { renderIcon } from '../../component-library/iconRegistry';
import { formatElementalId } from '../../core/model/elementalId';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import type { DiagramNode } from '../../core/model/types';
import { BUNDLED_ALGORITHM_TABLE, getTerminationBehaviors } from '../../crypto-behavior/bundled';
import { analyzeCryptoPath } from '../../features/pqc-path/analyzeCryptoPath';
import {
  findCryptoFlow,
  nodeTermination,
  routeNodeRoles,
  segmentSpans,
} from '../../features/pqc-path/cryptoPathView';
import type {
  CryptoSegment,
  EffectiveTermination,
  SegmentPqc,
} from '../../features/pqc-path/types';
import { useLocale, useT } from '../../i18n';
import {
  PQC_VERDICT_BADGE,
  PQC_VERDICT_BAND_BG,
  PQC_VERDICT_BAND_BORDER,
  PQC_VERDICT_ICON,
  PQC_VERDICT_LABEL_KEY,
} from './pqcVerdictStyle';

type TFunc = ReturnType<typeof useT>;

interface CryptoPathModalProps {
  sourceId: string;
  targetId: string;
  onClose: () => void;
}

const NODE_COL_W = 156;
const EDGE_COL_W = 132;

/** ノードの短縮表記（ElementalID、無ければ表示名）。 */
function shortLabel(node: DiagramNode | undefined, fallback: string): string {
  if (!node) return fallback;
  return node.seq !== undefined ? formatElementalId('node', node.seq) : getNodeDisplayName(node);
}

/** ノードの完全表記（ElementalID + 表示名）。 */
function fullLabel(node: DiagramNode | undefined, fallback: string): string {
  if (!node) return fallback;
  return node.seq !== undefined
    ? `${formatElementalId('node', node.seq)} ${getNodeDisplayName(node)}`
    : getNodeDisplayName(node);
}

function terminationLabel(term: EffectiveTermination, t: TFunc): string {
  return term.value === 'endpoint'
    ? t('panels.crypto.terminationEndpoint')
    : t(`panels.crypto.termination.${term.value}`);
}

/** PQC 判定のバッジ（アイコン＋ラベル。色だけに意味を載せない）。 */
function VerdictBadge({ verdict, t, testId }: { verdict: SegmentPqc; t: TFunc; testId?: string }) {
  const Icon = PQC_VERDICT_ICON[verdict];
  return (
    <span
      data-testid={testId}
      className={`inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-bold ${PQC_VERDICT_BADGE[verdict]}`}
    >
      <Icon size={12} /> {t(PQC_VERDICT_LABEL_KEY[verdict])}
    </span>
  );
}

/** 経路図の 1 ノード分のチップ。 */
function RouteNodeChip({
  node,
  fallbackId,
  role,
  term,
  t,
}: {
  node: DiagramNode | undefined;
  fallbackId: string;
  role: 'endpoint' | 'cut' | 'via';
  term: EffectiveTermination;
  t: TFunc;
}) {
  const [locale] = useLocale();
  const cfg = node ? getComponentRegistry(locale).get(node.type) : undefined;
  const frame =
    role === 'cut'
      ? 'bg-slate-800 border-sky-500/60 text-slate-100'
      : role === 'via'
        ? 'bg-slate-800/40 border-slate-700 border-dashed text-slate-300'
        : 'bg-slate-800 border-slate-600 text-slate-200';
  return (
    <div className={`w-full rounded-lg border px-2 py-1.5 flex flex-col gap-1 ${frame}`}>
      <div className="flex items-center gap-1.5 min-w-0">
        <span className={`${cfg?.color ?? 'bg-slate-500'} p-1 rounded text-white shrink-0`}>
          {renderIcon(cfg?.icon ?? { kind: 'builtin', name: 'box' }, { size: 12 })}
        </span>
        {node?.seq !== undefined && (
          <span className="text-xs font-black text-slate-400 shrink-0">
            {formatElementalId('node', node.seq)}
          </span>
        )}
        <span className="text-xs font-bold truncate" title={node ? getNodeDisplayName(node) : fallbackId}>
          {node ? getNodeDisplayName(node) : t('panels.cryptoPath.nodeMissing')}
        </span>
      </div>
      <div className="flex items-center gap-1 text-xs font-bold flex-wrap">
        {role === 'cut' && (
          <span className="flex items-center gap-0.5 text-sky-300" title={t('panels.cryptoPath.nodeCut')}>
            <Scissors size={12} />
          </span>
        )}
        <span className={role === 'cut' ? 'text-sky-200' : 'text-slate-400'}>
          {terminationLabel(term, t)}
        </span>
        {term.confidence !== 'endpoint' && (
          <span className="text-slate-400 font-normal">
            ({t(`panels.crypto.confidence.${term.confidence}`)})
          </span>
        )}
      </div>
    </div>
  );
}

const dash = (values: string[], t: TFunc) =>
  values.length > 0 ? values.join(', ') : t('panels.cryptoPath.none');

function SegmentRow({
  seg,
  index,
  nodeById,
  t,
}: {
  seg: CryptoSegment;
  index: number;
  nodeById: Map<string, DiagramNode>;
  t: TFunc;
}) {
  const node = (id: string) => nodeById.get(id);
  return (
    <tr className="border-b border-slate-800/60 last:border-b-0 align-top" data-testid="crypto-segment-row">
      <td className="py-2 pr-3 font-black text-slate-400">{index + 1}</td>
      <td className="py-2 pr-3 whitespace-nowrap">
        {fullLabel(node(seg.fromNodeId), seg.fromNodeId)} → {fullLabel(node(seg.toNodeId), seg.toNodeId)}
      </td>
      <td className="py-2 pr-3">
        {seg.viaNodeIds.length > 0
          ? seg.viaNodeIds.map((id) => fullLabel(node(id), id)).join(', ')
          : t('panels.cryptoPath.none')}
      </td>
      <td className="py-2 pr-3 whitespace-nowrap">
        {terminationLabel(seg.startTermination, t)}
        {seg.startTermination.confidence !== 'endpoint' && (
          <span className="text-slate-400"> ({t(`panels.crypto.confidence.${seg.startTermination.confidence}`)})</span>
        )}
      </td>
      <td className="py-2 pr-3">
        <div>{dash(seg.protocols, t)}</div>
        <div className="text-slate-400">{dash(seg.kex, t)}</div>
        <div className="text-slate-400">{dash(seg.signatures, t)}</div>
      </td>
      <td className="py-2 pr-3 whitespace-nowrap">{t(`panels.crypto.probability.${seg.probability}`)}</td>
      <td className="py-2 pr-3">
        <VerdictBadge verdict={seg.pqc} t={t} testId="crypto-segment-pqc" />
      </td>
      <td className="py-2 pr-3">
        <VerdictBadge verdict={seg.signatureClass} t={t} />
      </td>
      <td className="py-2 pr-3 whitespace-nowrap">
        {seg.providerManaged ? t('panels.cryptoPath.providerManaged') : ''}
      </td>
      <td className="py-2">
        {seg.warnings.map((w) => (
          <div key={w} className="flex items-center gap-1 text-amber-300 font-bold whitespace-nowrap">
            <AlertTriangle size={12} /> {t(`panels.crypto.warning.${w}`)}
          </div>
        ))}
      </td>
    </tr>
  );
}

/**
 * 送信元→送信先の暗号経路を、区間（暗号が切れる単位）ごとに表示するモーダル。
 * 設計は docs/pqc-path-analysis.md §8。分析は analyzeCryptoPath（純関数）が行う。
 */
export function CryptoPathModal({ sourceId, targetId, onClose }: CryptoPathModalProps) {
  const t = useT();
  const [locale] = useLocale();
  const nodes = useDiagramStore(selectActiveNodes);
  const edges = useDiagramStore(selectActiveEdges);
  const boundaries = useDiagramStore(selectActiveBoundaries);
  const flows = useDiagramStore((s) => s.layers[s.activeLayer].cryptoFlows);
  const addCryptoFlow = useDiagramStore((s) => s.addCryptoFlow);
  const [routeIndex, setRouteIndex] = useState(0);
  const [labelInput, setLabelInput] = useState('');

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  useEffect(() => {
    setRouteIndex(0);
    setLabelInput('');
  }, [sourceId, targetId]);

  const behaviors = useMemo(() => getTerminationBehaviors(locale), [locale]);
  const result = useMemo(
    () =>
      analyzeCryptoPath({
        nodes,
        edges,
        boundaries,
        sourceId,
        targetId,
        behaviors,
        algorithms: BUNDLED_ALGORITHM_TABLE,
      }),
    [nodes, edges, boundaries, sourceId, targetId, behaviors],
  );
  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.id, n] as const)), [nodes]);

  const source = nodeById.get(sourceId);
  const target = nodeById.get(targetId);
  const route = result.routes[Math.min(routeIndex, Math.max(result.routes.length - 1, 0))];
  const registered = findCryptoFlow(flows, sourceId, targetId) !== undefined;
  const defaultLabel = `${source ? getNodeDisplayName(source) : sourceId}→${target ? getNodeDisplayName(target) : targetId}`;

  const roles = route ? routeNodeRoles(route) : [];
  const spans = route ? segmentSpans(route) : [];
  const gridTemplate = route
    ? route.nodeIds
        .map((_, i) => (i === 0 ? `${NODE_COL_W}px` : `${EDGE_COL_W}px ${NODE_COL_W}px`))
        .join(' ')
    : undefined;

  const onAdd = () =>
    addCryptoFlow({ sourceId, targetId, label: labelInput.trim() || defaultLabel });

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-150"
      onMouseDown={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={t('panels.cryptoPath.title')}
        className="w-[1180px] max-w-[96vw] max-h-[90vh] overflow-hidden bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 flex flex-col gap-4"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2
            className="text-base font-bold text-slate-200 flex items-center gap-2"
            data-testid="crypto-path-title"
          >
            <Lock size={16} className="text-emerald-400" />
            {t('panels.cryptoPath.title')}：{fullLabel(source, sourceId)} → {fullLabel(target, targetId)}
          </h2>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-slate-200 transition-colors"
            aria-label={t('analytics.close')}
          >
            <X size={16} />
          </button>
        </div>

        <div className="flex flex-col gap-4 overflow-y-auto min-h-0">
          {result.undirectedFallback && (
            <p
              data-testid="crypto-path-undirected"
              className="flex items-center gap-2 text-sm text-amber-300 font-bold"
            >
              <AlertTriangle size={14} /> {t('panels.cryptoPath.undirected')}
            </p>
          )}
          {result.truncated && (
            <p
              data-testid="crypto-path-truncated"
              className="flex items-center gap-2 text-sm text-amber-300 font-bold"
            >
              <AlertTriangle size={14} /> {t('panels.cryptoPath.truncated')}
            </p>
          )}

          {!route ? (
            <div
              data-testid="crypto-path-empty"
              className="bg-slate-800/40 border border-slate-700 rounded-xl p-6 text-center"
            >
              <p className="text-sm text-slate-300 font-bold">{t('panels.cryptoPath.empty.title')}</p>
              <p className="text-sm text-slate-400 mt-2 leading-relaxed">{t('panels.cryptoPath.empty.body')}</p>
            </div>
          ) : (
            <>
              {result.routes.length > 1 && (
                <div role="tablist" className="flex gap-2 flex-wrap">
                  {result.routes.map((r, i) => {
                    const active = r === route;
                    return (
                      <button
                        key={i}
                        role="tab"
                        aria-selected={active}
                        onClick={() => setRouteIndex(i)}
                        className={`px-3 py-2 rounded-lg border text-left transition-colors ${
                          active
                            ? 'bg-slate-700 border-sky-500/60 text-slate-100'
                            : 'bg-slate-800/60 border-slate-700 text-slate-300 hover:border-slate-500'
                        }`}
                      >
                        <span className="block text-sm font-bold">
                          {t('panels.cryptoPath.routeTab', { n: i + 1 })}
                        </span>
                        <span className="block text-xs text-slate-400">
                          {r.nodeIds.map((id) => shortLabel(nodeById.get(id), id)).join(' → ')}
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}

              <section>
                <h3 className="text-xs font-black text-slate-400 uppercase mb-2 flex items-center gap-2">
                  <Route size={14} /> {t('panels.cryptoPath.diagram')}
                </h3>
                <div className="overflow-x-auto bg-slate-800/40 border border-slate-700 rounded-xl p-3">
                  <div
                    className="grid items-stretch gap-y-3 w-max"
                    style={{ gridTemplateColumns: gridTemplate }}
                    data-testid="crypto-path-diagram"
                  >
                    {route.nodeIds.map((id, i) => {
                      const node = nodeById.get(id);
                      const term = nodeTermination(node, behaviors, roles[i] === 'endpoint');
                      const edge = i > 0 ? edges.find((e) => e.id === route.edgeIds[i - 1]) : undefined;
                      return [
                        i > 0 && (
                          <div
                            key={`e${i}`}
                            style={{ gridColumn: 2 * i, gridRow: 1 }}
                            className="flex flex-col items-center justify-center px-1 text-center text-xs text-slate-300 break-words"
                          >
                            <span className="text-slate-500">──▶</span>
                            <span className="font-bold">
                              {edge?.crypto?.protocol ?? edge?.encryption ?? ''}
                            </span>
                            {edge?.crypto?.kex && <span className="text-slate-400">{edge.crypto.kex}</span>}
                          </div>
                        ),
                        <div key={`n${i}`} style={{ gridColumn: 2 * i + 1, gridRow: 1 }} className="flex">
                          <RouteNodeChip node={node} fallbackId={id} role={roles[i]} term={term} t={t} />
                        </div>,
                      ];
                    })}
                    {route.segments.map((seg, k) => (
                      <div
                        key={`b${k}`}
                        data-testid="crypto-segment-band"
                        style={{ gridColumn: `${2 * spans[k].from + 2} / ${2 * spans[k].to + 1}`, gridRow: 2 }}
                        className={`rounded-lg border px-2 py-1.5 flex flex-col items-center justify-center gap-1 text-center ${PQC_VERDICT_BAND_BG[seg.pqc]} ${PQC_VERDICT_BAND_BORDER[seg.pqc]}`}
                      >
                        <span className="text-xs font-black text-slate-200">
                          {t('panels.cryptoPath.segmentCard', { n: k + 1 })}
                        </span>
                        <VerdictBadge verdict={seg.pqc} t={t} />
                      </div>
                    ))}
                  </div>
                </div>
              </section>

              <section>
                <h3 className="text-xs font-black text-slate-400 uppercase mb-2 flex items-center justify-between gap-2">
                  <span>
                    {t('panels.cryptoPath.table')}（{route.segments.length}）
                  </span>
                  <span className="font-normal normal-case text-slate-400">
                    {t('panels.cryptoPath.uniqueSegments', { count: result.uniqueSegments.length })}
                  </span>
                </h3>
                <div className="overflow-x-auto bg-slate-800/40 border border-slate-700 rounded-xl p-3">
                  <table className="w-full text-xs text-slate-300">
                    <thead>
                      <tr className="text-slate-400 text-left border-b border-slate-700">
                        {(
                          [
                            'no',
                            'fromTo',
                            'via',
                            'termination',
                            'crypto',
                            'probability',
                            'pqc',
                            'signature',
                            'provider',
                            'warnings',
                          ] as const
                        ).map((c) => (
                          <th key={c} className="py-1 pr-3 font-bold">
                            {t(`panels.cryptoPath.col.${c}`)}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {route.segments.map((seg, k) => (
                        <SegmentRow key={k} seg={seg} index={k} nodeById={nodeById} t={t} />
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          )}
        </div>

        <div className="flex items-end gap-3 flex-wrap border-t border-slate-800 pt-4">
          <div className="flex-1 min-w-[240px]">
            <label htmlFor="crypto-flow-label" className="text-xs font-black text-slate-400 uppercase block mb-1.5">
              {t('panels.cryptoPath.labelField')}
            </label>
            <input
              id="crypto-flow-label"
              type="text"
              maxLength={200}
              value={labelInput}
              onChange={(e) => setLabelInput(e.target.value)}
              placeholder={defaultLabel}
              disabled={registered}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500 disabled:opacity-60"
            />
          </div>
          <button
            onClick={onAdd}
            disabled={registered}
            data-testid="crypto-flow-add"
            className="bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-400 disabled:cursor-not-allowed px-4 py-2.5 rounded-xl font-bold text-sm transition-colors flex items-center gap-2"
          >
            {registered ? <Check size={16} /> : <Plus size={16} />}
            {registered ? t('panels.cryptoPath.added') : t('panels.cryptoPath.add')}
          </button>
          <button
            onClick={onClose}
            className="bg-slate-800 hover:bg-slate-700 px-4 py-2.5 rounded-xl font-bold text-sm transition-colors"
          >
            {t('panels.common.close')}
          </button>
        </div>
      </div>
    </div>
  );
}
