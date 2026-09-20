import { useCallback, useEffect, useState } from 'react';
import { FolderOpen, HardDriveDownload, RefreshCw, Save, X } from 'lucide-react';
import { useDiagramStore } from '../../core/state/diagramStore';
import { BRANDING } from '../../core/branding';
import { useT } from '../../i18n';
import { serializeProject } from '../../features/persistence/serialize';
import { hydrateFromPersisted } from '../../features/persistence/hydrate';
import {
  ensurePermission,
  getSavedDirectoryHandle,
  isFileSystemAccessSupported,
  listProjectFiles,
  pickDirectory,
  projectFilename,
  readProjectFile,
  writeProjectFile,
} from '../../features/persistence/fileSystem';

type Tab = 'save' | 'open';
type Status = { kind: 'idle' | 'ok' | 'error'; message: string };

const IDLE: Status = { kind: 'idle', message: '' };

/**
 * プロジェクトのファイル保存/読込モーダル（FS Access API のフォルダ方式）。
 * `TemplateModal` と同じ枠（Esc / 背景クリックで閉じる）を踏襲。
 *
 * - 一度選んだ「保存先フォルダ」は IndexedDB に記憶し、以降そこへ保存・一覧・読込。
 * - 権限はセッションを跨ぐと失われるため、必要時に再接続（権限要求）する。
 * - IndexedDB 自動保存は別系統で継続（本機能はファイル入出力のみ）。
 */
export function ProjectFileModal() {
  const t = useT();
  const isOpen = useDiagramStore((s) => s.isProjectFileModalOpen);
  const close = useDiagramStore((s) => s.closeProjectFile);
  const projectName = useDiagramStore((s) => s.projectMeta.name);

  const supported = isFileSystemAccessSupported();
  const [tab, setTab] = useState<Tab>('save');
  const [dir, setDir] = useState<FileSystemDirectoryHandle | null>(null);
  /** 権限を失っていて再接続（権限要求のユーザー操作）が必要な状態。 */
  const [needsReconnect, setNeedsReconnect] = useState(false);
  const [files, setFiles] = useState<string[]>([]);
  const [filename, setFilename] = useState('');
  const [overwriting, setOverwriting] = useState(false);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<Status>(IDLE);

  /** フォルダ内の .json 一覧を取得（権限が無ければ再接続待ちにする）。 */
  const refresh = useCallback(async (handle: FileSystemDirectoryHandle) => {
    const granted = (await handle.queryPermission?.({ mode: 'readwrite' })) === 'granted';
    if (!granted) {
      setNeedsReconnect(true);
      setFiles([]);
      return;
    }
    setNeedsReconnect(false);
    setFiles(await listProjectFiles(handle));
  }, []);

  // 開くたびに初期化し、記憶済みフォルダを復元する。
  useEffect(() => {
    if (!isOpen) return;
    setTab('save');
    setFilename(projectFilename(projectName));
    setOverwriting(false);
    setStatus(IDLE);
    setNeedsReconnect(false);
    if (!supported) return;
    void (async () => {
      const handle = await getSavedDirectoryHandle();
      setDir(handle);
      if (handle) await refresh(handle);
    })();
  }, [isOpen, projectName, supported, refresh]);

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, close]);

  if (!isOpen) return null;

  const handlePick = async () => {
    setStatus(IDLE);
    try {
      const handle = await pickDirectory();
      if (!handle) return; // ユーザーキャンセル
      setDir(handle);
      await refresh(handle);
    } catch (e) {
      setStatus({
        kind: 'error',
        message: t('project.fileModal.pickFailed', { message: (e as Error).message }),
      });
    }
  };

  const handleReconnect = async () => {
    if (!dir) return;
    setStatus(IDLE);
    const ok = await ensurePermission(dir);
    if (!ok) {
      setStatus({ kind: 'error', message: t('project.fileModal.permissionDenied') });
      return;
    }
    await refresh(dir);
  };

  const handleSave = async () => {
    if (!dir) return;
    const name = filename.trim().endsWith('.json') ? filename.trim() : `${filename.trim()}.json`;
    if (name === '.json' || name.trim() === '') return;
    // 既存ファイルへの上書きは初回クリックで確認に切り替える。
    if (files.includes(name) && !overwriting) {
      setOverwriting(true);
      return;
    }
    setBusy(true);
    setStatus(IDLE);
    try {
      if (!(await ensurePermission(dir))) {
        setStatus({ kind: 'error', message: t('project.fileModal.permissionDenied') });
        return;
      }
      const s = useDiagramStore.getState();
      const project = serializeProject({
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
      await writeProjectFile(dir, name, project);
      await refresh(dir);
      setOverwriting(false);
      setStatus({ kind: 'ok', message: t('project.fileModal.saved', { name }) });
    } catch (e) {
      setStatus({
        kind: 'error',
        message: t('project.fileModal.saveFailed', { message: (e as Error).message }),
      });
    } finally {
      setBusy(false);
    }
  };

  const handleOpen = async (name: string) => {
    if (!dir) return;
    setBusy(true);
    setStatus(IDLE);
    try {
      if (!(await ensurePermission(dir))) {
        setStatus({ kind: 'error', message: t('project.fileModal.permissionDenied') });
        return;
      }
      const project = await readProjectFile(dir, name);
      if (!project) {
        setStatus({
          kind: 'error',
          message: t('projectFile.loadFailed', { name, brand: BRANDING.name }),
        });
        return;
      }
      hydrateFromPersisted(project);
      close();
    } catch (e) {
      setStatus({
        kind: 'error',
        message: t('project.fileModal.readFailed', { message: (e as Error).message }),
      });
    } finally {
      setBusy(false);
    }
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
          <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">
            {t('project.fileModal.title')}
          </h2>
          <button
            onClick={close}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            aria-label={t('project.common.close')}
          >
            <X size={16} />
          </button>
        </div>

        {!supported ? (
          <p className="text-[12px] text-amber-200 leading-relaxed rounded-lg border border-amber-600/60 bg-amber-900/20 p-3">
            {t('project.fileModal.unsupported')}
          </p>
        ) : (
          <>
            {/* 保存先フォルダ */}
            <div className="rounded-lg border border-slate-700 bg-slate-800/60 p-3 flex items-center gap-3">
              <FolderOpen size={16} className="text-emerald-400 shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-xs uppercase tracking-wider text-slate-500">
                  {t('project.fileModal.saveFolder')}
                </p>
                <p className="text-[12px] text-slate-200 truncate">
                  {dir ? dir.name : t('project.fileModal.notSelected')}
                  {needsReconnect && (
                    <span className="text-amber-300">{t('project.fileModal.needsReconnect')}</span>
                  )}
                </p>
              </div>
              {dir && needsReconnect && (
                <button
                  onClick={handleReconnect}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold uppercase bg-amber-600 hover:bg-amber-500 text-white rounded-lg transition-colors"
                >
                  <RefreshCw size={12} />
                  {t('project.fileModal.connect')}
                </button>
              )}
              <button
                onClick={handlePick}
                className="px-3 py-1.5 text-xs font-bold uppercase bg-slate-700 hover:bg-slate-600 text-slate-100 rounded-lg transition-colors"
              >
                {dir ? t('project.fileModal.change') : t('project.fileModal.select')}
              </button>
            </div>

            {/* タブ切替 */}
            <div className="grid grid-cols-2 gap-2">
              {(['save', 'open'] as const).map((tabKey) => (
                <button
                  key={tabKey}
                  onClick={() => {
                    setTab(tabKey);
                    setStatus(IDLE);
                    setOverwriting(false);
                  }}
                  className={`px-2 py-2 rounded-lg text-xs font-black border transition-all ${
                    tab === tabKey
                      ? 'bg-blue-600 border-blue-400 text-white'
                      : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                  }`}
                >
                  {tabKey === 'save' ? t('project.fileModal.tabSave') : t('project.fileModal.tabOpen')}
                </button>
              ))}
            </div>

            {tab === 'save' ? (
              <div className="flex flex-col gap-4">
                <label className="flex flex-col gap-1.5">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
                    {t('project.fileModal.filenameLabel')}
                  </span>
                  <input
                    type="text"
                    value={filename}
                    onChange={(e) => {
                      setFilename(e.target.value);
                      setOverwriting(false);
                    }}
                    placeholder={t('project.fileModal.filenamePlaceholder')}
                    className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors"
                  />
                </label>
                {overwriting && (
                  <div className="rounded-lg border border-amber-600/60 bg-amber-900/20 p-3 text-xs text-amber-200 leading-relaxed">
                    {t('project.fileModal.overwriteWarning')}
                  </div>
                )}
                <div className="flex justify-end gap-2 pt-2">
                  <button
                    onClick={close}
                    className="px-4 py-2 text-xs font-bold uppercase tracking-wider text-slate-300 hover:text-white transition-colors"
                  >
                    {t('project.common.cancel')}
                  </button>
                  <button
                    onClick={handleSave}
                    disabled={!dir || busy || filename.trim() === ''}
                    className={`flex items-center gap-2 px-4 py-2 text-xs font-bold uppercase tracking-wider text-white rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
                      overwriting ? 'bg-amber-600 hover:bg-amber-500' : 'bg-blue-600 hover:bg-blue-500'
                    }`}
                  >
                    <Save size={14} />
                    {overwriting ? t('project.fileModal.overwriteButton') : t('project.common.save')}
                  </button>
                </div>
              </div>
            ) : (
              <div className="flex flex-col gap-3">
                {!dir ? (
                  <p className="text-xs text-slate-400">
                    {t('project.fileModal.selectFolderFirst')}
                  </p>
                ) : needsReconnect ? (
                  <p className="text-xs text-amber-200">
                    {t('project.fileModal.reconnectNeeded')}
                  </p>
                ) : files.length === 0 ? (
                  <p className="text-xs text-slate-400">
                    {t('project.fileModal.noFiles')}
                  </p>
                ) : (
                  <ul className="flex flex-col gap-1.5 max-h-[40vh] overflow-y-auto">
                    {files.map((name) => (
                      <li key={name}>
                        <button
                          onClick={() => void handleOpen(name)}
                          disabled={busy}
                          className="w-full flex items-center gap-2 p-2.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-left text-[12px] text-slate-200 transition-colors disabled:opacity-40"
                        >
                          <HardDriveDownload size={14} className="text-emerald-400 shrink-0" />
                          <span className="flex-1 truncate">{name}</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </>
        )}

        {status.kind !== 'idle' && (
          <p
            className={`text-xs leading-relaxed break-words ${
              status.kind === 'ok' ? 'text-emerald-300' : 'text-rose-400'
            }`}
          >
            {status.message}
          </p>
        )}
      </div>
    </div>
  );
}
