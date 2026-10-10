import { useEffect, useState } from 'react';
import { Copy, X } from 'lucide-react';
import { useDiagramStore } from '../../core/state/diagramStore';
import { LAYER_KEYS, type LayerData, type LayerKey } from '../../core/model/types';
import { useT } from '../../i18n';

const elementCount = (l: LayerData): number =>
  l.nodes.length + l.edges.length + l.boundaries.length + l.annotations.length;

/**
 * レイヤーの下書き複製モーダル。アクティブレイヤーが複製元で、複製先をアクティブ以外から選ぶ。
 * 複製先が空でなければ置換の警告を出す（confirm() は使わずモーダル内で完結）。
 */
export function CopyLayerModal() {
  const t = useT();
  const isOpen = useDiagramStore((s) => s.isCopyLayerOpen);
  const close = useDiagramStore((s) => s.closeCopyLayer);
  const copyLayer = useDiagramStore((s) => s.copyLayer);
  const layers = useDiagramStore((s) => s.layers);
  const from = useDiagramStore((s) => s.activeLayer);
  const [to, setTo] = useState<LayerKey | null>(null);

  // 開くたびに複製先の選択を初期化。
  useEffect(() => {
    if (isOpen) setTo(null);
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, close]);

  if (!isOpen) return null;

  const targetCount = to ? elementCount(layers[to]) : 0;

  const handleCopy = () => {
    if (!to) return;
    copyLayer(from, to);
    close();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-150"
      onMouseDown={close}
    >
      <div
        role="dialog"
        aria-modal="true"
        className="w-[480px] max-w-[92vw] max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 flex flex-col gap-4"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">
            {t('project.copyLayer.title')}
          </h2>
          <button
            onClick={close}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            aria-label={t('project.common.close')}
          >
            <X size={16} />
          </button>
        </div>

        <p className="text-xs text-slate-400">
          {t('project.copyLayer.source')}：
          <span className="ml-1 font-bold text-slate-200">{from}</span>
          <span className="ml-2 text-slate-500">
            {t('project.copyLayer.elementCount', { count: elementCount(layers[from]) })}
          </span>
        </p>

        <div className="flex flex-col gap-2">
          <span className="text-xs font-bold text-slate-400">{t('project.copyLayer.target')}</span>
          {LAYER_KEYS.filter((k) => k !== from).map((k) => {
            const count = elementCount(layers[k]);
            return (
              <label
                key={k}
                className="flex items-center gap-3 p-2.5 rounded-lg border text-xs bg-slate-800 border-slate-700 text-slate-200 hover:border-slate-500 cursor-pointer"
              >
                <input
                  type="radio"
                  name="copy-layer-target"
                  className="accent-blue-500"
                  checked={to === k}
                  onChange={() => setTo(k)}
                />
                <span className="font-bold">{k}</span>
                <span className="text-slate-500">
                  {count === 0
                    ? t('project.copyLayer.emptyLayer')
                    : t('project.copyLayer.elementCount', { count })}
                </span>
              </label>
            );
          })}
        </div>

        {to && targetCount > 0 && (
          <p role="alert" className="text-xs text-amber-400 leading-relaxed">
            {t('project.copyLayer.overwriteWarning', { count: targetCount })}
          </p>
        )}

        <p className="text-xs text-slate-500 leading-relaxed">{t('project.copyLayer.note')}</p>

        <div className="flex items-center justify-end gap-2 pt-2">
          <button
            onClick={close}
            className="px-4 py-2 text-xs font-bold uppercase tracking-wider text-slate-300 hover:text-white transition-colors"
          >
            {t('project.common.cancel')}
          </button>
          <button
            onClick={handleCopy}
            disabled={!to}
            className="flex items-center gap-2 px-4 py-2 text-xs font-bold uppercase tracking-wider bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Copy size={14} />
            {t('project.copyLayer.confirm')}
          </button>
        </div>
      </div>
    </div>
  );
}
