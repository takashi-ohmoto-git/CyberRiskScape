import { useMemo, useState, type ReactNode } from 'react';
import {
  Download,
  FilePlus,
  FileText,
  FolderKanban,
  FolderOpen,
  Layers,
  Layers3,
  Library as LibraryIcon,
  Lock,
  Minus,
  Pencil,
  Plus,
  Save,
  Square,
  type LucideIcon,
} from 'lucide-react';
import type { BoundaryTypeId, LayerKey, ThreatView } from '../core/model/types';
import { LAYER_KEYS } from '../core/model/types';
import { BOUNDARY_TYPES } from '../core/constants/boundaryTypes';
import {
  selectActiveBoundaries,
  selectActiveEdges,
  selectActiveNodes,
  useDiagramStore,
} from '../core/state/diagramStore';
import { useCustomRulesStore } from '../features/custom-rules/store';
import { componentRegistry } from '../component-library/defaultRegistry';
import { renderIcon } from '../component-library/iconRegistry';
import { saveProject } from '../features/persistence/repository';
import { buildThreatReport, toCsv, toJson, toDCRHThreatModelMarkdown } from '../features/export/threatReport';
import { triggerDownload } from '../features/export/download';

const BOUNDARY_SECTION_KEY = 'BOUNDARIES';
const LIBRARY_MANAGER_KEY = '__LIBRARY_MANAGER__';
const PROJECT_SECTION_KEY = '__PROJECT__';
const LAYER_SUBMENU_KEY = '__LAYERS__';
const REPORT_SUBMENU_KEY = '__REPORT__';

/** レポートのファイル名（拡張子なし）。例: `threat-report_CreditScoringAPI_L1_2026-06-03`。 */
function reportFilename(systemName: string, layer: LayerKey): string {
  const slug = systemName.trim().replace(/[^\w.-]+/g, '_').slice(0, 60);
  const date = new Date().toISOString().slice(0, 10);
  return ['threat-report', slug, layer, date].filter(Boolean).join('_');
}

const LAYER_DESCRIPTIONS: Record<LayerKey, string> = {
  L0: 'ビジネスロジック中心（ビジネスサイドが記載）',
  L1: '詳細設計（セキュリティ担当者、通常はここまで）',
  L2: '機密性が高い場合の追加詳細',
  L3: '更に厳密な内容',
};

interface LeftSidebarProps {
  /** アクティブレイヤー＋アクティブ framework の脅威ビュー（Report 出力に使用）。 */
  threats: ThreatView[];
}

export function LeftSidebar({ threats }: LeftSidebarProps) {
  const addNode = useDiagramStore((s) => s.addNode);
  const addBoundary = useDiagramStore((s) => s.addBoundary);
  const disabledLibraryIds = useDiagramStore((s) => s.disabledLibraryIds);
  const toggleLibrary = useDiagramStore((s) => s.toggleLibrary);
  const openProjectEdit = useDiagramStore((s) => s.openProjectEdit);
  const openTemplate = useDiagramStore((s) => s.openTemplate);
  const openProjectFile = useDiagramStore((s) => s.openProjectFile);
  const openNewProjectConfirm = useDiagramStore((s) => s.openNewProjectConfirm);
  const projectName = useDiagramStore((s) => s.projectMeta.name);
  const activeFramework = useDiagramStore((s) => s.activeFramework);
  const activeLayer = useDiagramStore((s) => s.activeLayer);
  const setActiveLayer = useDiagramStore((s) => s.setActiveLayer);
  const layers = useDiagramStore((s) => s.layers);
  const [openSections, setOpenSections] = useState<Set<string>>(new Set([PROJECT_SECTION_KEY]));
  const [saveState, setSaveState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');

  const handleSaveNow = async () => {
    setSaveState('saving');
    try {
      const s = useDiagramStore.getState();
      await saveProject({
        layers: s.layers,
        activeLayer: s.activeLayer,
        idCounters: s.idCounters,
        activeFramework: s.activeFramework,
        disabledLibraryIds: s.disabledLibraryIds,
        projectMeta: s.projectMeta,
        manualThreats: s.manualThreats,
        suppressions: s.suppressions,
        dreadScores: s.dreadScores,
        controlStatuses: s.controlStatuses,
      });
      setSaveState('saved');
      setTimeout(() => setSaveState('idle'), 1500);
    } catch (e) {
      console.error('[persistence] manual save failed', e);
      setSaveState('error');
      setTimeout(() => setSaveState('idle'), 2000);
    }
  };

  const handleExportReport = (format: 'csv' | 'json' | 'DCRH-threat-model') => {
    const s = useDiagramStore.getState();
    const input = {
      threats,
      nodes: selectActiveNodes(s),
      edges: selectActiveEdges(s),
      boundaries: selectActiveBoundaries(s),
      projectMeta: s.projectMeta,
      framework: s.activeFramework,
      layer: s.activeLayer,
    };
    const base = reportFilename(s.projectMeta.systemName, s.activeLayer);
    if (format === 'csv') {
      triggerDownload(`${base}.csv`, toCsv(buildThreatReport(input)), 'text/csv;charset=utf-8', true);
    } else if (format === 'json') {
      triggerDownload(`${base}.json`, toJson(buildThreatReport(input)), 'application/json');
    } else {
      const date = new Date().toISOString().slice(0, 10);
      triggerDownload(
        `${base}.md`,
        toDCRHThreatModelMarkdown(input, date),
        'text/markdown;charset=utf-8',
      );
    }
  };

  const sections = useMemo(
    () => componentRegistry.listByCategory(disabledLibraryIds),
    [disabledLibraryIds],
  );
  const libraries = useMemo(() => componentRegistry.getLibraries(), []);
  const customLibraryCount = useCustomRulesStore((s) => s.libraries.length);
  const openCustomRulesManager = useCustomRulesStore((s) => s.openManager);

  const toggleSection = (key: string) => {
    setOpenSections((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const renderToggleIcon = (isOpen: boolean) =>
    isOpen ? (
      <Minus size={12} className="text-slate-400" />
    ) : (
      <Plus size={12} className="text-slate-400" />
    );

  const saveLabel =
    saveState === 'saving'
      ? '保存中…'
      : saveState === 'saved'
        ? '保存しました'
        : saveState === 'error'
          ? '保存に失敗'
          : 'SAVE';

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 p-6 flex flex-col gap-6 z-40 shadow-2xl overflow-y-auto animate-in slide-in-from-left duration-300">
      {/* ── PROJECT セクション ────────────────────────── */}
      <div>
        <button
          onClick={() => toggleSection(PROJECT_SECTION_KEY)}
          className="w-full flex items-center justify-between mb-2 group"
          aria-expanded={openSections.has(PROJECT_SECTION_KEY)}
        >
          <span className="flex items-center gap-2">
            <FolderKanban className="text-emerald-500" size={20} />
            <h2 className="text-sm font-bold uppercase tracking-widest text-slate-400 group-hover:text-slate-200 transition-colors">
              Project
            </h2>
          </span>
          {renderToggleIcon(openSections.has(PROJECT_SECTION_KEY))}
        </button>
        {openSections.has(PROJECT_SECTION_KEY) && (
          <div className="space-y-1.5">
            <ProjectMenuItem
              icon={Pencil}
              label={projectName.trim().length > 0 ? projectName : 'プロジェクト未設定'}
              onClick={openProjectEdit}
            />

            {/* 深度レイヤー — 展開すると L0/L1/L2/L3 切替 */}
            <div>
              <ProjectMenuItem
                icon={Layers3}
                label={`深度レイヤー（${activeLayer}）`}
                onClick={() => toggleSection(LAYER_SUBMENU_KEY)}
                rightIcon={renderToggleIcon(openSections.has(LAYER_SUBMENU_KEY))}
              />
              {openSections.has(LAYER_SUBMENU_KEY) && (
                <div className="mt-1.5 ml-3 pl-3 border-l border-slate-700 space-y-1">
                  {LAYER_KEYS.map((key) => {
                    const isActive = key === activeLayer;
                    const layer = layers[key];
                    const count =
                      layer.nodes.length + layer.edges.length + layer.boundaries.length;
                    return (
                      <button
                        key={key}
                        onClick={() => setActiveLayer(key)}
                        className={`w-full flex items-center gap-2 p-2 rounded-lg transition-all border text-[10px] font-bold text-left ${
                          isActive
                            ? 'bg-emerald-700/30 border-emerald-600 text-emerald-200'
                            : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
                        }`}
                        title={LAYER_DESCRIPTIONS[key]}
                      >
                        <span
                          className={`shrink-0 inline-block w-1.5 h-1.5 rounded-full ${
                            isActive ? 'bg-emerald-400' : 'bg-slate-600'
                          }`}
                        />
                        <span className="font-black tracking-wider">{key}</span>
                        <span className="flex-1 truncate text-slate-500 font-normal">
                          {LAYER_DESCRIPTIONS[key]}
                        </span>
                        <span className="text-[9px] text-slate-500 shrink-0">{count}</span>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Report — 展開すると CSV / JSON ダウンロード（表示中の脅威一覧が対象） */}
            <div>
              <ProjectMenuItem
                icon={FileText}
                label="Report"
                onClick={() => toggleSection(REPORT_SUBMENU_KEY)}
                rightIcon={renderToggleIcon(openSections.has(REPORT_SUBMENU_KEY))}
              />
              {openSections.has(REPORT_SUBMENU_KEY) && (
                <div className="mt-1.5 ml-3 pl-3 border-l border-slate-700 space-y-1.5">
                  <p className="text-[9px] text-slate-500 leading-snug">
                    表示中の脅威一覧（{activeLayer} / {activeFramework}・{threats.length} 件）を出力
                  </p>
                  <button
                    onClick={() => handleExportReport('csv')}
                    className="w-full flex items-center gap-2 p-2 rounded-lg transition-all border text-[10px] font-bold text-left bg-slate-800 border-slate-700 text-slate-200 hover:bg-slate-700"
                  >
                    <Download size={12} className="text-emerald-400 shrink-0" />
                    CSV ダウンロード
                  </button>
                  <button
                    onClick={() => handleExportReport('json')}
                    className="w-full flex items-center gap-2 p-2 rounded-lg transition-all border text-[10px] font-bold text-left bg-slate-800 border-slate-700 text-slate-200 hover:bg-slate-700"
                  >
                    <Download size={12} className="text-emerald-400 shrink-0" />
                    JSON ダウンロード
                  </button>
                  <button
                    onClick={() => handleExportReport('DCRH-threat-model')}
                    className="w-full flex items-center gap-2 p-2 rounded-lg transition-all border text-[10px] font-bold text-left bg-slate-800 border-slate-700 text-slate-200 hover:bg-slate-700"
                  >
                    <Download size={12} className="text-emerald-400 shrink-0" />
                    DCRH THREAT_MODEL.md（Anthropic 公式互換）
                  </button>
                </div>
              )}
            </div>
            <ProjectMenuItem icon={LibraryIcon} label="Template" onClick={openTemplate} />
            <ProjectMenuItem icon={FilePlus} label="新規作成" onClick={openNewProjectConfirm} />
            <ProjectMenuItem icon={FolderOpen} label="ファイル（保存 / 開く）" onClick={openProjectFile} />
            <ProjectMenuItem
              icon={Save}
              label={saveLabel}
              onClick={saveState === 'saving' ? undefined : handleSaveNow}
            />
          </div>
        )}
      </div>

      {/* ── LIBRARY セクション ────────────────────────── */}
      <div className="flex items-center gap-2 mb-2">
        <Layers className="text-blue-500" size={20} />
        <h2 className="text-sm font-bold uppercase tracking-widest text-slate-400">Library</h2>
      </div>

      <div className="space-y-4">
        {sections.map(({ category, components }) => {
          const isOpen = openSections.has(category.id);
          return (
            <div key={category.id}>
              <button
                onClick={() => toggleSection(category.id)}
                className="w-full flex items-center justify-between text-[10px] text-slate-500 hover:text-slate-300 font-bold uppercase mb-2 transition-colors"
                aria-expanded={isOpen}
              >
                <span>{category.label}</span>
                {renderToggleIcon(isOpen)}
              </button>
              {isOpen && (
                <div className="space-y-1.5">
                  {components.map((comp) => (
                    <button
                      key={comp.id}
                      onClick={() => addNode(comp.id)}
                      className="w-full flex items-center gap-3 p-2 bg-slate-800 hover:bg-slate-700 rounded-lg transition-all border border-slate-700 text-[11px] font-bold group"
                      title={comp.description}
                    >
                      <div className={`${comp.color} p-1.5 rounded-md text-white`}>
                        {renderIcon(comp.icon, { size: 14 })}
                      </div>
                      {comp.label}
                      <Plus size={12} className="ml-auto opacity-40 group-hover:opacity-100" />
                    </button>
                  ))}
                </div>
              )}
            </div>
          );
        })}

        <div>
          <button
            onClick={() => toggleSection(BOUNDARY_SECTION_KEY)}
            className="w-full flex items-center justify-between text-[10px] text-slate-500 hover:text-slate-300 font-bold uppercase mb-2 transition-colors"
            aria-expanded={openSections.has(BOUNDARY_SECTION_KEY)}
          >
            <span>Trust Boundaries</span>
            {renderToggleIcon(openSections.has(BOUNDARY_SECTION_KEY))}
          </button>
          {openSections.has(BOUNDARY_SECTION_KEY) && (
            <div className="space-y-1.5">
              {Object.entries(BOUNDARY_TYPES).map(([key, boundary]) => (
                <button
                  key={key}
                  onClick={() => addBoundary(key as BoundaryTypeId)}
                  className="w-full flex items-center gap-3 p-2 bg-slate-800 hover:bg-slate-700 rounded-lg transition-all border border-slate-700 text-[11px] font-bold group"
                >
                  <div className="bg-slate-600 p-1.5 rounded-md">
                    <Square size={14} className={boundary.isDashed ? 'stroke-dasharray-2' : ''} />
                  </div>
                  {boundary.name}
                  <Plus size={12} className="ml-auto opacity-40 group-hover:opacity-100" />
                </button>
              ))}
            </div>
          )}
        </div>

        {/* ── ライブラリ管理 ────────────────────────────── */}
        <div>
          <button
            onClick={() => toggleSection(LIBRARY_MANAGER_KEY)}
            className="w-full flex items-center justify-between text-[10px] text-slate-500 hover:text-slate-300 font-bold uppercase mb-2 transition-colors"
            aria-expanded={openSections.has(LIBRARY_MANAGER_KEY)}
          >
            <span className="flex items-center gap-1.5">
              <LibraryIcon size={12} /> Libraries ({libraries.length})
            </span>
            {renderToggleIcon(openSections.has(LIBRARY_MANAGER_KEY))}
          </button>
          {openSections.has(LIBRARY_MANAGER_KEY) && (
            <div className="space-y-1.5">
              {libraries.map((lib) => {
                const isDisabled = disabledLibraryIds.has(lib.id);
                const isLocked = lib.builtin === true;
                return (
                  <button
                    key={lib.id}
                    onClick={() => !isLocked && toggleLibrary(lib.id)}
                    disabled={isLocked}
                    className={`w-full flex items-center gap-2 p-2 rounded-lg transition-all border text-[10px] font-bold text-left ${
                      isDisabled
                        ? 'bg-slate-900 border-slate-800 text-slate-600'
                        : 'bg-slate-800 border-slate-700 text-slate-200 hover:bg-slate-700'
                    } ${isLocked ? 'cursor-not-allowed opacity-80' : 'cursor-pointer'}`}
                    title={
                      isLocked
                        ? `${lib.title} (built-in / cannot disable)`
                        : `${lib.title} v${lib.version} — click to ${isDisabled ? 'enable' : 'disable'}`
                    }
                  >
                    {isLocked && <Lock size={10} className="text-slate-500 shrink-0" />}
                    <span className="flex-1 truncate">{lib.title}</span>
                    <span className="text-[9px] text-slate-500 shrink-0">v{lib.version}</span>
                    {!isLocked && (
                      <span
                        className={`shrink-0 inline-block w-2 h-2 rounded-full ${
                          isDisabled ? 'bg-slate-600' : 'bg-emerald-500'
                        }`}
                      />
                    )}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* ── カスタム脅威ルール（全プロジェクト共通） ──────── */}
        <div>
          <button
            onClick={openCustomRulesManager}
            className="w-full flex items-center justify-between text-[10px] text-slate-500 hover:text-slate-300 font-bold uppercase mb-2 transition-colors"
          >
            <span className="flex items-center gap-1.5">
              <LibraryIcon size={12} /> Custom Rules ({customLibraryCount})
            </span>
            <Plus size={12} className="text-slate-400" />
          </button>
        </div>
      </div>

      <div className="mt-auto p-4 bg-slate-800/50 rounded-2xl border border-slate-700">
        <p className="text-[10px] text-slate-500 font-bold uppercase mb-2">Usage</p>
        <ul className="text-[10px] space-y-2 text-slate-400">
          <li className="flex gap-2">🔹 パーツを選択して "Create Link" で接続</li>
          <li className="flex gap-2">🔹 コネクタを中継点として利用可能</li>
        </ul>
      </div>
    </aside>
  );
}

interface ProjectMenuItemProps {
  icon: LucideIcon;
  label: string;
  onClick?: () => void;
  disabled?: boolean;
  note?: string;
  rightIcon?: ReactNode;
}

function ProjectMenuItem({
  icon: Icon,
  label,
  onClick,
  disabled,
  note,
  rightIcon,
}: ProjectMenuItemProps) {
  return (
    <button
      type="button"
      onClick={disabled ? undefined : onClick}
      disabled={disabled}
      className={`w-full flex items-center gap-3 p-2 rounded-lg transition-all border text-[11px] font-bold text-left ${
        disabled
          ? 'bg-slate-900 border-slate-800 text-slate-600 cursor-not-allowed'
          : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-100 cursor-pointer'
      }`}
      title={disabled && note ? `${label}（${note}）` : label}
    >
      <div
        className={`p-1.5 rounded-md ${
          disabled ? 'bg-slate-800 text-slate-600' : 'bg-emerald-700 text-white'
        }`}
      >
        <Icon size={14} />
      </div>
      <span className="flex-1 truncate">{label}</span>
      {note && (
        <span className="text-[9px] uppercase tracking-wider text-slate-500 shrink-0">
          {note}
        </span>
      )}
      {rightIcon}
    </button>
  );
}
