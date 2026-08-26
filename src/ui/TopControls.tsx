import {
  BarChart3,
  Library,
  Maximize,
  Minimize,
  Redo2,
  Scan,
  ScanSearch,
  Undo2,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';
import {
  selectCanRedo,
  selectCanUndo,
  useDiagramStore,
} from '../core/state/diagramStore';
import { FRAMEWORK_VIEWS, FRAMEWORK_VIEW_LABELS } from './frameworkLabels';
import { useT } from '../i18n';

export function TopControls() {
  const t = useT();
  const activeFramework = useDiagramStore((s) => s.activeFramework);
  const isFocusMode = useDiagramStore((s) => s.isFocusMode);
  const setActiveFramework = useDiagramStore((s) => s.setActiveFramework);
  const toggleFocusMode = useDiagramStore((s) => s.toggleFocusMode);
  const openAnalytics = useDiagramStore((s) => s.openAnalytics);
  const openComplianceMap = useDiagramStore((s) => s.openComplianceMap);
  const openLibraryInspector = useDiagramStore((s) => s.openLibraryInspector);
  const canUndo = useDiagramStore(selectCanUndo);
  const canRedo = useDiagramStore(selectCanRedo);
  const undo = useDiagramStore((s) => s.undo);
  const redo = useDiagramStore((s) => s.redo);
  const scale = useDiagramStore((s) => s.viewport.scale);
  const zoomIn = useDiagramStore((s) => s.zoomIn);
  const zoomOut = useDiagramStore((s) => s.zoomOut);
  const resetZoom = useDiagramStore((s) => s.resetZoom);
  const fitToContent = useDiagramStore((s) => s.fitToContent);

  return (
    <>
    <div className="absolute top-6 left-6 z-10 flex gap-4">
      <div className="flex gap-2 bg-slate-900/90 backdrop-blur-xl p-1.5 rounded-2xl border border-slate-700 shadow-2xl">
        {FRAMEWORK_VIEWS.map((f) => (
          <button
            key={f}
            onClick={() => setActiveFramework(f)}
            className={`px-6 py-2 rounded-xl text-xs font-black transition-all ${
              activeFramework === f
                ? 'bg-blue-600 text-white shadow-lg'
                : 'hover:bg-slate-800 text-slate-500'
            }`}
          >
            {FRAMEWORK_VIEW_LABELS[f]}
          </button>
        ))}
      </div>

      <div className="flex gap-1 bg-slate-900/90 backdrop-blur-xl p-1.5 rounded-2xl border border-slate-700 shadow-2xl">
        <button
          onClick={undo}
          disabled={!canUndo}
          className="flex items-center justify-center p-2 rounded-xl text-slate-400 hover:bg-slate-800 hover:text-slate-100 transition-all active:scale-95 disabled:opacity-30 disabled:hover:bg-transparent disabled:cursor-not-allowed"
          title="元に戻す (Ctrl+Z)"
        >
          <Undo2 size={18} />
        </button>
        <button
          onClick={redo}
          disabled={!canRedo}
          className="flex items-center justify-center p-2 rounded-xl text-slate-400 hover:bg-slate-800 hover:text-slate-100 transition-all active:scale-95 disabled:opacity-30 disabled:hover:bg-transparent disabled:cursor-not-allowed"
          title="やり直し (Ctrl+Shift+Z)"
        >
          <Redo2 size={18} />
        </button>
      </div>

      <button
        onClick={openAnalytics}
        className="flex items-center justify-center bg-slate-900/90 backdrop-blur-xl p-2.5 rounded-2xl border border-slate-700 shadow-2xl hover:bg-slate-800 text-slate-400 hover:text-emerald-400 transition-all active:scale-95"
        title="Analytics（アクティブレイヤーの分析）を開く"
      >
        <BarChart3 size={18} />
      </button>

      <button
        onClick={openComplianceMap}
        className="flex items-center justify-center bg-slate-900/90 backdrop-blur-xl p-2.5 rounded-2xl border border-slate-700 shadow-2xl hover:bg-slate-800 text-slate-400 hover:text-emerald-400 transition-all active:scale-95"
        title="コンプライアンスマップを開く"
      >
        <Library size={18} />
      </button>

      <button
        onClick={openLibraryInspector}
        className="flex items-center justify-center bg-slate-900/90 backdrop-blur-xl p-2.5 rounded-2xl border border-slate-700 shadow-2xl hover:bg-slate-800 text-slate-400 hover:text-emerald-400 transition-all active:scale-95"
        title={t('topbar.libraryInspector')}
      >
        <ScanSearch size={18} />
      </button>

      <button
        onClick={toggleFocusMode}
        className="flex items-center justify-center bg-slate-900/90 backdrop-blur-xl p-2.5 rounded-2xl border border-slate-700 shadow-2xl hover:bg-slate-800 text-slate-400 transition-all active:scale-95"
        title={isFocusMode ? t('topbar.showSidebar') : t('topbar.focusMode')}
      >
        {isFocusMode ? <Minimize size={18} /> : <Maximize size={18} />}
      </button>
    </div>

    {/* ズームコントロール（右下）。−／倍率%（クリックで 100%）／＋／全体表示 */}
    <div className="absolute bottom-6 right-6 z-10 flex items-center gap-1 bg-slate-900/90 backdrop-blur-xl p-1.5 rounded-2xl border border-slate-700 shadow-2xl">
      <button
        onClick={zoomOut}
        className="flex items-center justify-center p-2 rounded-xl text-slate-400 hover:bg-slate-800 hover:text-slate-100 transition-all active:scale-95"
        title="縮小"
      >
        <ZoomOut size={18} />
      </button>
      <button
        onClick={resetZoom}
        className="min-w-[3.5rem] px-2 py-1 rounded-xl text-xs font-black tabular-nums text-slate-300 hover:bg-slate-800 hover:text-slate-100 transition-all active:scale-95"
        title="100% に戻す"
      >
        {Math.round(scale * 100)}%
      </button>
      <button
        onClick={zoomIn}
        className="flex items-center justify-center p-2 rounded-xl text-slate-400 hover:bg-slate-800 hover:text-slate-100 transition-all active:scale-95"
        title="拡大"
      >
        <ZoomIn size={18} />
      </button>
      <div className="w-px h-5 bg-slate-700 mx-0.5" />
      <button
        onClick={fitToContent}
        className="flex items-center justify-center p-2 rounded-xl text-slate-400 hover:bg-slate-800 hover:text-slate-100 transition-all active:scale-95"
        title="全体表示（Fit）"
      >
        <Scan size={18} />
      </button>
    </div>
    </>
  );
}
