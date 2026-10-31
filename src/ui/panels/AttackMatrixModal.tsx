import { useEffect, useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, X } from 'lucide-react';
import type { DiagramEdge, DiagramNode, Severity, ThreatView } from '../../core/model/types';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import { SEVERITY_DOT } from '../../core/model/severityColors';
import type { AttackGraphResult } from '../../features/attack-tree/buildAttackGraph';
import type { AnalyzeGraphResult } from '../../features/attack-tree/analyzeAttackGraph';
import { ATTACK_MATRIX, localizedName } from '../../features/attack-matrix/attackMatrix';
import { collectPathTechniques, type PathTechnique } from '../../features/attack-matrix/collectPathTechniques';
import { useLocale, useT } from '../../i18n';

interface AttackMatrixModalProps {
  attackerId: string;
  allThreats: ThreatView[];
  /** AttackTreeModal が表示中の graph / analysis（再計算せず画面と一致させる）。 */
  graph: AttackGraphResult;
  analysis: AnalyzeGraphResult;
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  onClose: () => void;
}

const STEP_MARK = ['①', '②', '③', '④', '⑤', '⑥', '⑦', '⑧', '⑨', '⑩'];
const stepText = (steps: number[]) => steps.map((s) => STEP_MARK[s - 1] ?? String(s)).join('');

const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low'];

/** 該当のあるサブテクニック ID（親の「サブが該当」判定用）。 */
function subHitIds(parentId: string, hits: Map<string, PathTechnique>): string[] {
  const tech = ATTACK_MATRIX.techniques.get(parentId);
  return (tech?.subtechniques ?? []).filter((s) => hits.has(s.id)).map((s) => s.id);
}

export function AttackMatrixModal({
  attackerId,
  allThreats,
  graph,
  analysis,
  nodes,
  edges,
  onClose,
}: AttackMatrixModalProps) {
  const t = useT();
  const [locale] = useLocale();

  const hits = useMemo(
    () => collectPathTechniques(allThreats, graph, analysis, attackerId),
    [allThreats, graph, analysis, attackerId],
  );

  // 該当サブがあるテクニックは既定で展開
  const [expanded, setExpanded] = useState<Set<string>>(() => {
    const s = new Set<string>();
    for (const id of ATTACK_MATRIX.techniques.keys()) if (subHitIds(id, hits).length > 0) s.add(id);
    return s;
  });
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const toggle = (id: string) =>
    setExpanded((cur) => {
      const next = new Set(cur);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const withSubs = [...ATTACK_MATRIX.techniques.values()].filter((x) => x.subtechniques.length > 0);

  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.id, n] as const)), [nodes]);
  const edgeById = useMemo(() => new Map(edges.map((e) => [e.id, e] as const)), [edges]);
  const elementLabel = (key: string | null): string => {
    if (!key) return '—';
    if (key.startsWith('node:')) {
      const n = nodeById.get(key.slice('node:'.length));
      return n ? getNodeDisplayName(n) : key;
    }
    const e = edgeById.get(key.slice('edge:'.length));
    if (!e) return key;
    const a = nodeById.get(e.source);
    const b = nodeById.get(e.target);
    return `${a ? getNodeDisplayName(a) : e.source} → ${b ? getNodeDisplayName(b) : e.target}`;
  };

  let onPathCount = 0;
  let offPathCount = 0;
  for (const v of hits.values()) {
    if (v.onPath) onPathCount += 1;
    else offPathCount += 1;
  }

  const selectedSubHits = selected ? subHitIds(selected, hits) : [];
  const detailIds = selected ? [selected, ...selectedSubHits] : [];

  /** 1 セル（テクニックまたはサブ）。 */
  const cell = (id: string, isSub: boolean) => {
    const hit = hits.get(id);
    const subHit = isSub ? [] : subHitIds(id, hits);
    const tone = hit?.onPath
      ? 'bg-rose-600/80 text-white border-rose-400'
      : hit
        ? 'bg-rose-500/15 text-rose-100 border-rose-500/40'
        : 'bg-slate-800/60 text-slate-300 border-slate-700';
    return (
      <button
        type="button"
        key={id}
        title={localizedName(id, 'en')}
        onClick={() => setSelected(id)}
        className={`text-left rounded border px-1.5 py-1 text-xs leading-snug hover:brightness-125 ${tone} ${
          selected === id ? 'ring-2 ring-sky-400' : ''
        } ${isSub ? 'ml-2' : ''}`}
      >
        <span className="flex items-start justify-between gap-1">
          <span className="min-w-0 break-words">{localizedName(id, locale)}</span>
          {hit && (
            <span className="flex items-center gap-1 shrink-0">
              {hit.onPath && <span className="font-black">{stepText(hit.steps)}</span>}
              <span className={`w-2 h-2 rounded-full ${SEVERITY_DOT[hit.severity]}`} aria-hidden />
            </span>
          )}
        </span>
        <span className="flex items-center justify-between gap-1 opacity-80">
          <span>{id}</span>
          {subHit.length > 0 && <span className="font-bold">{t('panels.attackMatrix.subHit')}</span>}
        </span>
      </button>
    );
  };

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onMouseDown={(e) => {
        // 親（攻撃経路分析）の背景クリック閉じに伝えない
        e.stopPropagation();
        onClose();
      }}
    >
      <div
        className="w-[96vw] h-[92vh] overflow-hidden bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-5 flex flex-col gap-3"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">
            {t('panels.attackMatrix.title')}
          </h2>
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            aria-label={t('panels.common.close')}
          >
            <X size={16} />
          </button>
        </div>

        <div className="flex items-center gap-4 text-xs font-bold text-slate-400 flex-wrap">
          <span className="text-slate-300">
            {t('panels.attackMatrix.summary', { onPath: onPathCount, offPath: offPathCount })}
          </span>
          <span className="flex items-center gap-1">
            <span className="px-1.5 rounded bg-rose-600/80 text-white border border-rose-400">①</span>
            {t('panels.attackMatrix.legend.onPath')}
          </span>
          <span className="flex items-center gap-1">
            <span className="px-1.5 rounded bg-rose-500/15 border border-rose-500/40">&nbsp;</span>
            {t('panels.attackMatrix.legend.offPath')}
          </span>
          <span className="flex items-center gap-1">
            <span className="px-1.5 rounded bg-slate-800/60 border border-slate-700">&nbsp;</span>
            {t('panels.attackMatrix.legend.none')}
          </span>
          <span className="flex items-center gap-1.5">
            {t('panels.attackMatrix.legend.severity')}
            {SEVERITIES.map((s) => (
              <span key={s} className="flex items-center gap-0.5">
                <span className={`w-2 h-2 rounded-full ${SEVERITY_DOT[s]}`} aria-hidden />
                {s}
              </span>
            ))}
          </span>
          <span className="ml-auto flex items-center gap-2">
            <button
              type="button"
              onClick={() => setExpanded(new Set(withSubs.map((x) => x.id)))}
              className="px-2 py-1 rounded border border-slate-700 hover:border-slate-500"
            >
              {t('panels.attackMatrix.expandAll')}
            </button>
            <button
              type="button"
              onClick={() => setExpanded(new Set())}
              className="px-2 py-1 rounded border border-slate-700 hover:border-slate-500"
            >
              {t('panels.attackMatrix.collapseAll')}
            </button>
          </span>
        </div>

        <div className="flex gap-3 min-h-0 flex-1">
          <div className="overflow-auto flex-1 min-w-0 bg-slate-800/40 border border-slate-700 rounded-xl p-2">
            <div className="flex gap-2 items-start w-max">
              {ATTACK_MATRIX.tactics.map((tactic) => (
                <div key={tactic.id} className="w-44 shrink-0 flex flex-col gap-1">
                  <div className="rounded bg-slate-700 px-1.5 py-1 text-xs" title={tactic.name}>
                    <div className="font-black text-slate-100">{localizedName(tactic.id, locale)}</div>
                    <div className="text-slate-300">{tactic.id}</div>
                    <div className="text-slate-400">
                      {t('panels.attackMatrix.techniqueCount', { count: tactic.techniques.length })}
                    </div>
                  </div>
                  {tactic.techniques.map((tech) => (
                    <div key={tech.id} className="flex flex-col gap-1">
                      {cell(tech.id, false)}
                      {tech.subtechniques.length > 0 && (
                        <>
                          <button
                            type="button"
                            onClick={() => toggle(tech.id)}
                            aria-expanded={expanded.has(tech.id)}
                            className="ml-2 flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200"
                          >
                            {expanded.has(tech.id) ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                            {t('panels.attackMatrix.subToggle', { count: tech.subtechniques.length })}
                          </button>
                          {expanded.has(tech.id) && tech.subtechniques.map((s) => cell(s.id, true))}
                        </>
                      )}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>

          <div className="w-80 shrink-0 overflow-auto bg-slate-800/40 border border-slate-700 rounded-xl p-3 text-xs flex flex-col gap-2">
            <div className="font-black uppercase tracking-widest text-slate-400">
              {t('panels.attackMatrix.detail.heading')}
            </div>
            {!selected && <div className="text-slate-500">{t('panels.attackMatrix.detail.hint')}</div>}
            {selected && (
              <>
                <div className="font-bold text-slate-200" title={localizedName(selected, 'en')}>
                  {selected} {localizedName(selected, locale)}
                </div>
                {!hits.has(selected) && selectedSubHits.length > 0 && (
                  <div className="text-slate-400">{t('panels.attackMatrix.detail.subHit')}</div>
                )}
                {detailIds.every((id) => !hits.has(id)) && (
                  <div className="text-slate-500">{t('panels.attackMatrix.detail.none')}</div>
                )}
                {detailIds.map((id) => {
                  const h = hits.get(id);
                  if (!h) return null;
                  return (
                    <div key={id} className="flex flex-col gap-1.5">
                      {id !== selected && (
                        <div className="font-bold text-slate-300" title={localizedName(id, 'en')}>
                          {id} {localizedName(id, locale)}
                        </div>
                      )}
                      {h.hits.map((hit) => (
                        <div
                          key={hit.threatId}
                          className="rounded border border-slate-700 bg-slate-900/60 p-2 flex flex-col gap-0.5"
                        >
                          <div className="text-slate-100 leading-snug">{hit.threatName}</div>
                          <div className="text-slate-400">{elementLabel(hit.elementKey)}</div>
                          <div className="text-slate-300 font-bold">
                            {hit.steps.length > 0
                              ? t('panels.attackMatrix.step', { steps: hit.steps.join('・') })
                              : t('panels.attackMatrix.detail.offPath')}
                          </div>
                        </div>
                      ))}
                    </div>
                  );
                })}
              </>
            )}
          </div>
        </div>

        <div className="text-xs text-slate-500">
          {t('panels.attackMatrix.footer', { version: ATTACK_MATRIX.version })}
          {locale === 'ja' && ` ／ ${t('panels.attackMatrix.unofficialJa')}`}
        </div>
      </div>
    </div>
  );
}
