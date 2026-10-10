import { useEffect, useMemo, useState } from 'react';
import { ClipboardCheck, Download, ExternalLink, X } from 'lucide-react';
import { useDiagramStore } from '../../core/state/diagramStore';
import { LAYER_KEYS, type LayerKey } from '../../core/model/types';
import { useCustomRulesStore, selectCustomLibraries } from '../../features/custom-rules/store';
import { mergeThreatRules } from '../../features/custom-rules/mergeRules';
import { computeLayerThreats } from '../../features/export/layerThreats';
import { reportFilename } from '../../features/export/exportFiles';
import { triggerDownload } from '../../features/export/download';
import { getThreatLibrary } from '../../threat-library/loader/bundledLibrary';
import { getChecklists } from '../../checklist/bundled';
import { evaluateChecklist, ITEM_STATUSES, type ItemResult } from '../../checklist/evaluate';
import { toChecklistCsv } from '../../checklist/report';
import { useLocale, useT } from '../../i18n';
import {
  CHECKLIST_STATUS_BADGE,
  CHECKLIST_STATUS_DESC_KEY,
  CHECKLIST_STATUS_ICON,
  CHECKLIST_STATUS_LABEL_KEY,
} from './checklistStatusStyle';

/**
 * 注意喚起チェックリストモーダル。構成図の現状を項目ごとに判定して一覧する（読み取り専用）。
 * 判定は構成図に基づく。実機の点検の代わりではない旨を常に冒頭に出す。
 */
export function ChecklistModal() {
  const isOpen = useDiagramStore((s) => s.isChecklistOpen);
  const close = useDiagramStore((s) => s.closeChecklist);
  const t = useT();
  const [locale] = useLocale();
  const checklists = useMemo(() => getChecklists(locale), [locale]);
  const [checklistId, setChecklistId] = useState<string>('');
  const [layer, setLayer] = useState<LayerKey>('L1');

  const layers = useDiagramStore((s) => s.layers);
  const manualThreats = useDiagramStore((s) => s.manualThreats);
  const suppressions = useDiagramStore((s) => s.suppressions);
  const riskScores = useDiagramStore((s) => s.riskScores);
  const controlStatuses = useDiagramStore((s) => s.controlStatuses);
  const projectMeta = useDiagramStore((s) => s.projectMeta);
  const customLibraries = useCustomRulesStore(selectCustomLibraries);

  // 開くたびに、チェックリストは先頭（新しい順）、レイヤーはアクティブなレイヤーに合わせる。
  useEffect(() => {
    if (!isOpen) return;
    setChecklistId(checklists[0]?.checklist.id ?? '');
    setLayer(useDiagramStore.getState().activeLayer);
  }, [isOpen, checklists]);

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, close]);

  const checklist = checklists.find((c) => c.checklist.id === checklistId) ?? checklists[0];
  const layerData = layers[layer];

  const result = useMemo(() => {
    if (!isOpen || !checklist || layerData.nodes.length === 0) return null;
    const merged = mergeThreatRules(getThreatLibrary(locale).rules, customLibraries);
    // チェックリストは表示中の framework に左右されず、全 framework の検出で判定する。
    const [item] = computeLayerThreats(
      {
        layers,
        manualThreats,
        suppressions,
        riskScores,
        controlStatuses,
        activeFramework: 'ALL',
        projectMeta,
      },
      merged,
      [layer],
    );
    return evaluateChecklist({
      checklist,
      nodes: layerData.nodes,
      threats: item.threats,
      asOf: new Date().toISOString().slice(0, 10),
    });
  }, [
    isOpen,
    checklist,
    layer,
    layerData.nodes,
    layers,
    manualThreats,
    suppressions,
    riskScores,
    controlStatuses,
    projectMeta,
    customLibraries,
    locale,
  ]);

  if (!isOpen || !checklist) return null;

  const selectNode = (id: string) => {
    const s = useDiagramStore.getState();
    if (s.activeLayer !== layer) s.setActiveLayer(layer);
    useDiagramStore.getState().selectNode(id);
    close();
  };

  const handleCsv = () => {
    if (!result) return;
    const slug = reportFilename(projectMeta.systemName, layer).replace(
      /^threat-report/,
      `checklist-${checklist.checklist.id}`,
    );
    triggerDownload(
      `${slug}.csv`,
      toChecklistCsv({ result, project: projectMeta, layer, locale }),
      'text/csv;charset=utf-8',
      true,
    );
  };

  const src = checklist.checklist.source;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-150"
      onMouseDown={close}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={t('checklist.title')}
        className="w-[960px] max-w-[94vw] h-[86vh] bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl flex flex-col overflow-hidden"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <ClipboardCheck size={16} className="text-emerald-400" />
            <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">
              {t('checklist.title')}
            </h2>
          </div>
          <button
            onClick={close}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            aria-label={t('checklist.close')}
          >
            <X size={16} />
          </button>
        </div>

        <div className="flex-1 min-h-0 overflow-y-auto px-6 py-4 flex flex-col gap-4">
          <div className="flex flex-wrap items-end gap-4">
            {checklists.length > 1 && (
              <label className="flex flex-col gap-1 text-xs text-slate-400">
                {t('checklist.pick')}
                <select
                  value={checklist.checklist.id}
                  onChange={(e) => setChecklistId(e.target.value)}
                  className="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-slate-200"
                >
                  {checklists.map((c) => (
                    <option key={c.checklist.id} value={c.checklist.id}>
                      {c.checklist.title}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <label className="flex flex-col gap-1 text-xs text-slate-400">
              {t('checklist.layer')}
              <select
                value={layer}
                onChange={(e) => setLayer(e.target.value as LayerKey)}
                className="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-slate-200"
              >
                {LAYER_KEYS.map((k) => (
                  <option key={k} value={k} disabled={layers[k].nodes.length === 0}>
                    {t('checklist.layerNodes', { layer: k, count: layers[k].nodes.length })}
                  </option>
                ))}
              </select>
            </label>
            <button
              onClick={handleCsv}
              disabled={!result}
              className="ml-auto flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-bold bg-slate-800 border-slate-700 text-slate-200 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <Download size={12} className="text-emerald-400" />
              {t('checklist.csv')}
            </button>
          </div>

          <div className="flex flex-col gap-1.5 text-xs leading-relaxed">
            <h3 className="text-sm font-bold text-slate-100">{checklist.checklist.title}</h3>
            <p className="text-slate-400">
              {t('checklist.source', {
                publisher: src.publisher,
                title: src.title,
                date: src.publishedAt,
              })}
              <a
                href={src.url}
                target="_blank"
                rel="noopener noreferrer"
                className="ml-2 inline-flex items-center gap-1 text-sky-400 hover:text-sky-300"
              >
                <ExternalLink size={11} />
                {src.url}
              </a>
            </p>
            <p className="px-3 py-2 rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-200">
              {t('checklist.disclaimer')}
            </p>
          </div>

          {!result ? (
            <p className="text-xs text-slate-500">{t('checklist.empty')}</p>
          ) : (
            <>
              <ul className="flex flex-wrap gap-2" aria-label={t('checklist.title')}>
                {ITEM_STATUSES.map((s) => {
                  const Icon = CHECKLIST_STATUS_ICON[s];
                  return (
                    <li
                      key={s}
                      title={t(CHECKLIST_STATUS_DESC_KEY[s])}
                      className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-bold ${CHECKLIST_STATUS_BADGE[s]}`}
                    >
                      <Icon size={12} />
                      {t(CHECKLIST_STATUS_LABEL_KEY[s])} {result.summary[s]}
                    </li>
                  );
                })}
              </ul>

              {result.groups.map((g) => (
                <section key={g.group.id} className="flex flex-col gap-2">
                  <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">
                    {g.group.title}
                  </h3>
                  {g.items.map((r) => (
                    <ItemCard key={r.item.id} r={r} onSelectNode={selectNode} />
                  ))}
                </section>
              ))}

              <section className="flex flex-col gap-2">
                <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">
                  {t('checklist.stale.heading')}
                </h3>
                <p className="text-xs text-slate-500">
                  {t('checklist.stale.intro', {
                    days: result.checklist.staleDays,
                    asOf: result.asOf,
                  })}
                </p>
                {result.staleNodes.length === 0 ? (
                  <p className="text-xs text-slate-500">{t('checklist.stale.none')}</p>
                ) : (
                  <table className="w-full text-xs border border-slate-800 rounded-lg overflow-hidden">
                    <thead className="bg-slate-800/60 text-slate-400">
                      <tr>
                        <th className="text-left px-3 py-1.5 font-bold">{t('checklist.stale.col.node')}</th>
                        <th className="text-left px-3 py-1.5 font-bold">{t('checklist.stale.col.state')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.staleNodes.map((s) => (
                        <tr key={s.node.id} className="border-t border-slate-800">
                          <td className="px-3 py-1.5">
                            <button
                              onClick={() => selectNode(s.node.id)}
                              title={t('checklist.item.selectNode', { label: s.node.label })}
                              className="text-sky-300 hover:text-sky-200 hover:underline text-left"
                            >
                              {s.node.label}
                            </button>
                          </td>
                          <td className="px-3 py-1.5 text-slate-300">
                            {s.reason === 'unrecorded'
                              ? t('checklist.stale.unrecorded')
                              : t('checklist.stale.stale', {
                                  date: s.lastReviewedAt ?? '',
                                  days: s.daysSince ?? 0,
                                })}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </section>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function ItemCard({ r, onSelectNode }: { r: ItemResult; onSelectNode: (id: string) => void }) {
  const t = useT();
  const Icon = CHECKLIST_STATUS_ICON[r.status];
  const dim = r.status === 'notApplicable';
  return (
    <article
      className={`rounded-xl border border-slate-800 bg-slate-800/40 px-4 py-3 flex flex-col gap-1.5 ${
        dim ? 'opacity-60' : ''
      }`}
    >
      <div className="flex items-start gap-3">
        <span
          title={t(CHECKLIST_STATUS_DESC_KEY[r.status])}
          className={`shrink-0 flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-xs font-bold ${CHECKLIST_STATUS_BADGE[r.status]}`}
        >
          <Icon size={12} />
          {t(CHECKLIST_STATUS_LABEL_KEY[r.status])}
        </span>
        <h4 className="text-xs font-bold text-slate-100 leading-snug">
          <span className="font-mono text-slate-500 mr-2">{r.item.id}</span>
          {r.item.title}
        </h4>
      </div>
      {!dim && (
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="text-slate-500">{t('checklist.item.nodes')}:</span>
          {r.nodes.length === 0 ? (
            <span className="text-slate-500">{t('checklist.item.noNodes')}</span>
          ) : (
            r.nodes.map((n) => (
              <button
                key={n.id}
                onClick={() => onSelectNode(n.id)}
                title={t('checklist.item.selectNode', { label: n.label })}
                className="px-2 py-0.5 rounded-md border border-slate-700 bg-slate-800 text-sky-300 hover:text-sky-200 hover:border-slate-500"
              >
                {n.label}
              </button>
            ))
          )}
          {r.nodes.length > 0 && (
            <span className="ml-2 text-slate-500">
              {t('checklist.item.counts', {
                action: r.counts.action,
                unfilled: r.counts.unfilled,
                accepted: r.counts.accepted,
              })}
            </span>
          )}
        </div>
      )}
      <p className="text-xs text-slate-400 leading-relaxed">
        <span className="font-bold text-slate-300">{t('checklist.item.howTo')}: </span>
        {r.item.howTo}
      </p>
    </article>
  );
}
