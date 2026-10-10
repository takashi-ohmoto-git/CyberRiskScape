import { useEffect, useState } from 'react';
import { Download, Loader2, X } from 'lucide-react';
import { useDiagramStore } from '../../core/state/diagramStore';
import { LAYER_KEYS, type LayerKey } from '../../core/model/types';
import { useT, type TranslationKey } from '../../i18n';
import { exportPdf, exportPng } from '../../features/export/exportFiles';

/**
 * 遅延チャンク（PDF/PNG 処理）の読み込み失敗か。開いたままのタブで新しい版がデプロイされると
 * 古いハッシュのチャンクが消えて起きる。文言はブラウザごとに異なる（Chrome / Firefox / Safari）。
 */
function isChunkLoadError(e: unknown): boolean {
  const message = e instanceof Error ? e.message : String(e);
  return /dynamically imported module|Importing a module script failed/i.test(message);
}

const LAYER_DESCRIPTION_KEYS: Record<LayerKey, TranslationKey> = {
  L0: 'project.sidebar.layerDesc.L0',
  L1: 'project.sidebar.layerDesc.L1',
  L2: 'project.sidebar.layerDesc.L2',
  L3: 'project.sidebar.layerDesc.L3',
  PQC: 'project.sidebar.layerDesc.PQC',
};

/**
 * PDF / PNG エクスポートのレイヤー選択モーダル。`TemplateModal` と同じパターン
 * （Esc / 背景クリックで閉じる）。ノードが無いレイヤーは選べない。
 * 生成中は閉じられない・再実行できない。失敗はモーダル内にインライン表示する。
 */
export function ExportLayersModal() {
  const t = useT();
  const mode = useDiagramStore((s) => s.exportModalMode);
  const close = useDiagramStore((s) => s.closeExportModal);
  const layers = useDiagramStore((s) => s.layers);
  const [selected, setSelected] = useState<Set<LayerKey>>(new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // 開くたびに初期化：ノードのある全レイヤーを選択。
  useEffect(() => {
    if (!mode) return;
    const s = useDiagramStore.getState();
    setSelected(new Set(LAYER_KEYS.filter((k) => s.layers[k].nodes.length > 0)));
    setBusy(false);
    setError(null);
  }, [mode]);

  useEffect(() => {
    if (!mode) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !busy) close();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [mode, busy, close]);

  if (!mode) return null;

  const toggle = (k: LayerKey) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });

  const handleExport = async () => {
    const keys = LAYER_KEYS.filter((k) => selected.has(k));
    if (keys.length === 0 || busy) return;
    setBusy(true);
    setError(null);
    try {
      if (mode === 'pdf') await exportPdf(keys);
      else await exportPng(keys);
      close();
    } catch (e) {
      console.error('[export] failed', e);
      setError(
        isChunkLoadError(e)
          ? t('project.exportModal.errorReload')
          : t('project.exportModal.error', { message: e instanceof Error ? e.message : String(e) }),
      );
      setBusy(false);
    }
  };

  const guard = () => {
    if (!busy) close();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-150"
      onMouseDown={guard}
    >
      <div
        role="dialog"
        aria-modal="true"
        className="w-[480px] max-w-[92vw] max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 flex flex-col gap-4"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">
            {mode === 'pdf' ? t('project.exportModal.titlePdf') : t('project.exportModal.titlePng')}
          </h2>
          <button
            onClick={guard}
            disabled={busy}
            className="text-slate-500 hover:text-slate-200 transition-colors disabled:opacity-40"
            aria-label={t('project.common.close')}
          >
            <X size={16} />
          </button>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed">
          {mode === 'pdf' ? t('project.exportModal.introPdf') : t('project.exportModal.introPng')}
        </p>

        <div className="flex flex-col gap-2">
          {LAYER_KEYS.map((k) => {
            const count = layers[k].nodes.length;
            const empty = count === 0;
            return (
              <label
                key={k}
                className={`flex items-start gap-3 p-2.5 rounded-lg border text-xs transition-colors ${
                  empty
                    ? 'bg-slate-800/40 border-slate-800 text-slate-600 cursor-not-allowed'
                    : 'bg-slate-800 border-slate-700 text-slate-200 hover:border-slate-500 cursor-pointer'
                }`}
              >
                <input
                  type="checkbox"
                  className="mt-0.5 accent-blue-500"
                  checked={selected.has(k)}
                  disabled={empty || busy}
                  onChange={() => toggle(k)}
                />
                <span className="flex flex-col gap-0.5 min-w-0">
                  <span className="font-bold">
                    {k}
                    <span className="ml-2 font-normal text-slate-500">
                      {empty
                        ? t('project.exportModal.emptyLayer')
                        : t('project.exportModal.nodeCount', { count })}
                    </span>
                  </span>
                  <span className="text-slate-500 leading-snug">{t(LAYER_DESCRIPTION_KEYS[k])}</span>
                </span>
              </label>
            );
          })}
        </div>

        {error && (
          <p role="alert" className="text-xs text-rose-400 leading-relaxed break-words">
            {error}
          </p>
        )}

        <div className="flex items-center justify-end gap-2 pt-2">
          {selected.size === 0 && (
            <span className="mr-auto text-xs text-slate-500">{t('project.exportModal.noneSelected')}</span>
          )}
          <button
            onClick={guard}
            disabled={busy}
            className="px-4 py-2 text-xs font-bold uppercase tracking-wider text-slate-300 hover:text-white transition-colors disabled:opacity-40"
          >
            {t('project.common.cancel')}
          </button>
          <button
            onClick={handleExport}
            disabled={selected.size === 0 || busy}
            className="flex items-center gap-2 px-4 py-2 text-xs font-bold uppercase tracking-wider bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
            {busy ? t('project.exportModal.busy') : t('project.exportModal.export')}
          </button>
        </div>
      </div>
    </div>
  );
}
