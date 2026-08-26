import { useEffect, useRef, useState } from 'react';
import { Download, Upload, X } from 'lucide-react';
import {
  selectActiveBoundaries,
  selectActiveEdges,
  selectActiveNodes,
  useDiagramStore,
} from '../../core/state/diagramStore';
import { triggerDownload } from '../../features/export/download';
import {
  parseTemplateFromJson,
  serializeTemplateToJson,
  type ParseTemplateResult,
} from '../../features/templates/io';

type Tab = 'export' | 'import';

/** テンプレートのファイル名（拡張子なし）。例: `template_注文系_L1_2026-06-03`。 */
function templateFilename(name: string, layer: string): string {
  // 英数 . - と、ひらがな / カタカナ（長音符含む）/ 漢字 を残し、他は _ に潰す。
  const slug = name.trim().replace(/[^\w.\-぀-ゟ゠-ヿ一-鿿]+/gu, '_').slice(0, 60);
  const date = new Date().toISOString().slice(0, 10);
  return ['template', slug, layer, date].filter(Boolean).join('_');
}

/**
 * Template（Import / Export）モーダル。`ProjectEditModal` と同じパターン
 * （Esc / 背景クリックで閉じる）。
 *
 * - Export：現在のアクティブレイヤーの図に任意の名称を付けて JSON ダウンロード。
 * - Import：JSON を検証し、アクティブレイヤーを**置換適用**（既存要素ありなら確認）。
 */
export function TemplateModal() {
  const isOpen = useDiagramStore((s) => s.isTemplateModalOpen);
  const close = useDiagramStore((s) => s.closeTemplate);
  const activeLayer = useDiagramStore((s) => s.activeLayer);
  const projectName = useDiagramStore((s) => s.projectMeta.name);
  const nodes = useDiagramStore(selectActiveNodes);
  const edges = useDiagramStore(selectActiveEdges);
  const boundaries = useDiagramStore(selectActiveBoundaries);
  const importTemplate = useDiagramStore((s) => s.importTemplateToActiveLayer);

  const [tab, setTab] = useState<Tab>('export');
  const [name, setName] = useState('');
  const [parsed, setParsed] = useState<ParseTemplateResult | null>(null);
  const [importedFileName, setImportedFileName] = useState<string | null>(null);
  /** 既存要素ありの置換に対するインライン確認待ち（ブラウザダイアログを使わない方針）。 */
  const [confirming, setConfirming] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const activeCount = nodes.length + edges.length + boundaries.length;

  // 開くたびに初期化。名称の既定はプロジェクト名 or レイヤー名。
  useEffect(() => {
    if (!isOpen) return;
    setTab('export');
    setName(projectName.trim() !== '' ? projectName.trim() : `${activeLayer} テンプレート`);
    setParsed(null);
    setImportedFileName(null);
    setConfirming(false);
  }, [isOpen, projectName, activeLayer]);

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, close]);

  if (!isOpen) return null;

  const handleExport = () => {
    const trimmed = name.trim();
    if (trimmed === '') return;
    const s = useDiagramStore.getState();
    const layer = s.layers[s.activeLayer];
    const json = serializeTemplateToJson(trimmed, layer);
    triggerDownload(`${templateFilename(trimmed, s.activeLayer)}.json`, json, 'application/json');
  };

  const handleFile = async (file: File) => {
    const text = await file.text();
    setParsed(parseTemplateFromJson(text));
    setImportedFileName(file.name);
    setConfirming(false);
  };

  const handleApplyImport = () => {
    if (!parsed || !parsed.ok) return;
    // 既存要素がある初回クリックはインライン確認に切り替える（実行は次クリック）。
    if (activeCount > 0 && !confirming) {
      setConfirming(true);
      return;
    }
    importTemplate(parsed.layer);
    close();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-150"
      onMouseDown={close}
    >
      <div
        className="w-[560px] max-w-[92vw] max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 flex flex-col gap-4"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">Template</h2>
          <button
            onClick={close}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            aria-label="閉じる"
          >
            <X size={16} />
          </button>
        </div>

        {/* タブ切替 */}
        <div className="grid grid-cols-2 gap-2">
          {(['export', 'import'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-2 py-2 rounded-lg text-[11px] font-black border transition-all ${
                tab === t
                  ? 'bg-blue-600 border-blue-400 text-white'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              {t === 'export' ? 'Export（書き出し）' : 'Import（読み込み）'}
            </button>
          ))}
        </div>

        {tab === 'export' ? (
          <div className="flex flex-col gap-4">
            <p className="text-[11px] text-slate-400 leading-relaxed">
              現在のアクティブレイヤー（<span className="font-bold text-slate-200">{activeLayer}</span>
              ・{activeCount} 件）の図をテンプレートとして書き出します。
            </p>
            <label className="flex flex-col gap-1.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
                テンプレート名 <span className="text-rose-400">*</span>
              </span>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="例: 標準 Web 三層構成"
                className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors"
              />
            </label>
            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={close}
                className="px-4 py-2 text-xs font-bold uppercase tracking-wider text-slate-300 hover:text-white transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={handleExport}
                disabled={name.trim() === ''}
                className="flex items-center gap-2 px-4 py-2 text-xs font-bold uppercase tracking-wider bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <Download size={14} />
                ダウンロード
              </button>
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-4">
            <p className="text-[11px] text-slate-400 leading-relaxed">
              テンプレート JSON を読み込み、アクティブレイヤー（
              <span className="font-bold text-slate-200">{activeLayer}</span>）に
              <span className="font-bold text-amber-300"> 置き換え </span>
              で適用します。既存要素があるときは確認します。
            </p>

            <input
              ref={fileInputRef}
              type="file"
              accept="application/json,.json"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) void handleFile(file);
                e.target.value = '';
              }}
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              className="flex items-center justify-center gap-2 px-4 py-3 text-xs font-bold uppercase tracking-wider bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-lg transition-colors"
            >
              <Upload size={14} />
              JSON ファイルを選択
            </button>

            {importedFileName && parsed && (
              <div className="rounded-lg border border-slate-700 bg-slate-800/60 p-3 text-[11px]">
                <p className="text-slate-500 mb-1 truncate">{importedFileName}</p>
                {parsed.ok ? (
                  <p className="text-slate-200">
                    「<span className="font-bold">{parsed.name}</span>」 — ノード{' '}
                    {parsed.layer.nodes.length} / エッジ {parsed.layer.edges.length} / 境界{' '}
                    {parsed.layer.boundaries.length}
                  </p>
                ) : (
                  <p className="text-rose-400 break-words">{parsed.error}</p>
                )}
              </div>
            )}

            {confirming && (
              <div className="rounded-lg border border-amber-600/60 bg-amber-900/20 p-3 text-[11px] text-amber-200 leading-relaxed">
                {activeLayer} には既に {activeCount} 件の要素があります。これらを破棄してテンプレートで
                置き換えます。「置き換える」を押すと適用します（元に戻すで復元できます）。
              </div>
            )}

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={close}
                className="px-4 py-2 text-xs font-bold uppercase tracking-wider text-slate-300 hover:text-white transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={handleApplyImport}
                disabled={!parsed || !parsed.ok}
                className={`px-4 py-2 text-xs font-bold uppercase tracking-wider text-white rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
                  confirming ? 'bg-amber-600 hover:bg-amber-500' : 'bg-blue-600 hover:bg-blue-500'
                }`}
              >
                {confirming ? '置き換える' : activeCount > 0 ? '置き換えて適用' : '適用'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
