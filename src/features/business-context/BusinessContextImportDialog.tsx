import { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';
import type { LayerKey } from '../../core/model/types';
import { useDiagramStore } from '../../core/state/diagramStore';
import { useT } from '../../i18n';
import { applyBusinessContext, type ApplyBusinessContextSummary } from './applyBusinessContext';
import {
  BUSINESS_CONTEXT_MAX_BYTES,
  parseBusinessContextTable,
  type BusinessContextTable,
} from './parseBusinessContextTable';

/**
 * プロジェクトメニューの「業務の文脈を取り込む」ダイアログ。表（CSV / JSON）をブラウザの中で読み、
 * 反映内容（ノード・重要度・図に無い参照）を確認してから全レイヤーに反映する。反映は Undo の対象。
 */

interface Preview {
  table: BusinessContextTable;
  summary: ApplyBusinessContextSummary;
}

export function BusinessContextImportDialog({ onClose }: { onClose: () => void }) {
  const t = useT();
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [done, setDone] = useState<number | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const read = async () => {
    setError(null);
    setPreview(null);
    setDone(null);
    if (!file) return;
    if (file.size > BUSINESS_CONTEXT_MAX_BYTES) {
      setError(t('businessContext.import.error.tooLarge', { max: BUSINESS_CONTEXT_MAX_BYTES / 1024 / 1024 }));
      return;
    }
    const parsed = parseBusinessContextTable(await file.text(), file.name);
    if (!parsed.ok) {
      setError(`${file.name}: ${parsed.error}`);
      return;
    }
    // 確認用：現在の図に当てた結果（反映はしない）
    const { layers } = useDiagramStore.getState();
    const { summary } = applyBusinessContext(layers, parsed.rows, { now: new Date(), source: parsed.source });
    setPreview({ table: parsed, summary });
  };

  const apply = () => {
    if (!preview) return;
    const store = useDiagramStore.getState();
    // 確認の間に図が変わっても、最新の図に対して反映し直す
    const r = applyBusinessContext(store.layers, preview.table.rows, { now: new Date(), source: preview.table.source });
    if (r.summary.applied.length === 0) return;
    store.recordHistory();
    useDiagramStore.setState({ layers: r.layers as Record<LayerKey, (typeof store.layers)[LayerKey]> });
    setDone(r.summary.applied.length);
    setPreview(null);
  };

  const nodeName = (n: { seq?: number; nodeId: string; label?: string }) =>
    `${n.seq !== undefined ? `C${n.seq}` : n.nodeId}${n.label ? ` ${n.label}` : ''}`;

  const s = preview?.summary;
  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={onClose}
      role="presentation"
    >
      <div
        role="dialog"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
        className="w-[560px] max-w-[92vw] max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 flex flex-col gap-4"
      >
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">{t('businessContext.import.title')}</h2>
          <button type="button" onClick={onClose} aria-label={t('businessContext.import.close')} className="text-slate-400 hover:text-slate-100">
            <X size={16} />
          </button>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">{t('businessContext.import.hint')}</p>
        <label className="block text-xs text-slate-300">
          <span className="font-bold">{t('businessContext.import.pick')}</span>
          <input
            type="file"
            accept=".csv,text/csv,application/json,.json"
            data-testid="business-context-file"
            onChange={(e) => {
              setFile(e.target.files?.[0] ?? null);
              setPreview(null);
              setError(null);
              setDone(null);
            }}
            className="block w-full mt-1 text-xs text-slate-300"
          />
        </label>
        <div className="flex gap-2">
          <button
            type="button"
            disabled={!file}
            onClick={() => void read()}
            className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed text-xs font-bold text-white transition-colors"
          >
            {t('businessContext.import.read')}
          </button>
        </div>
        {error && (
          <p role="alert" className="text-xs text-rose-300 leading-relaxed">
            {error}
          </p>
        )}
        {s && (
          <div className="space-y-2" data-testid="business-context-preview">
            <p className="text-xs text-slate-200 leading-relaxed">
              {t('businessContext.import.summary', {
                rows: s.rows,
                applied: s.applied.length,
                skipped: s.skipped.length,
                unknown: s.unknownRefs.length,
                ambiguous: s.ambiguousRefs.length,
              })}
            </p>
            <p className="text-xs text-slate-400">
              {t('businessContext.import.basis', { basis: t(`businessContext.import.basis.${s.basis}`) })}
            </p>
            <ul className="space-y-1 text-xs text-slate-300">
              {s.applied.map((a) => (
                <li key={`${a.layer}:${a.nodeId}`}>
                  {t('businessContext.import.nodeLine', {
                    node: nodeName(a),
                    criticality: a.criticality,
                    how:
                      a.criticalitySource === 'declared' || a.share === undefined
                        ? t('businessContext.import.how.declared')
                        : t('businessContext.import.how.derived', { share: (a.share * 100).toFixed(1) }),
                  })}
                </li>
              ))}
              {s.skipped.map((k) => (
                <li key={`${k.layer}:${k.nodeId}`} className="text-amber-300">
                  {t('businessContext.import.skippedLine', { node: nodeName(k) })}
                </li>
              ))}
            </ul>
            {s.unknownRefs.length > 0 && (
              <p className="text-xs text-amber-300 leading-relaxed">
                {t('businessContext.import.unknown', { refs: s.unknownRefs.join(', ') })}
              </p>
            )}
            {s.ambiguousRefs.length > 0 && (
              <p className="text-xs text-amber-300 leading-relaxed">
                {t('businessContext.import.ambiguous', { refs: s.ambiguousRefs.join(', ') })}
              </p>
            )}
            {s.notes.map((n) => (
              <p key={n} className="text-xs text-slate-400 leading-relaxed">
                {t('businessContext.import.note', { note: n })}
              </p>
            ))}
            {s.applied.length === 0 ? (
              <p className="text-xs text-slate-400">{t('businessContext.import.nothing')}</p>
            ) : (
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={apply}
                  className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-bold text-white"
                >
                  {t('businessContext.import.apply')}
                </button>
                <button
                  type="button"
                  onClick={onClose}
                  className="px-3 py-1.5 rounded-lg bg-slate-700 hover:bg-slate-600 text-xs font-bold text-slate-100"
                >
                  {t('businessContext.import.cancel')}
                </button>
              </div>
            )}
          </div>
        )}
        {done !== null && (
          <p role="status" className="text-xs text-emerald-300 leading-relaxed">
            {t('businessContext.import.done', { count: done })}
          </p>
        )}
      </div>
    </div>,
    document.body,
  );
}
