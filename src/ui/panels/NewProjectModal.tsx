import { useEffect, useState } from 'react';
import { FilePlus, Save, X } from 'lucide-react';
import { useDiagramStore } from '../../core/state/diagramStore';
import { serializeProject } from '../../features/persistence/serialize';
import {
  ensurePermission,
  getSavedDirectoryHandle,
  isFileSystemAccessSupported,
  listProjectFiles,
  pickDirectory,
  projectFilename,
  writeProjectFile,
} from '../../features/persistence/fileSystem';
import { triggerDownload } from '../../features/export/download';

type Status = { kind: 'idle' | 'error'; message: string };

const IDLE: Status = { kind: 'idle', message: '' };

/** 既存ファイルと衝突しない名前を返す（`project.json` → `project_2.json` …）。 */
function uniqueFilename(existing: string[], base: string): string {
  if (!existing.includes(base)) return base;
  const stem = base.replace(/\.json$/, '');
  for (let i = 2; ; i++) {
    const candidate = `${stem}_${i}.json`;
    if (!existing.includes(candidate)) return candidate;
  }
}

/**
 * 新規プロジェクト作成の確認モーダル。
 * 現在の作業内容をファイルへ保存するか確認してから、まっさらな新規プロジェクトへ
 * 置き換える。保存は `ProjectFileModal` と同じ保存先フォルダ（FS Access API）を使い、
 * 非対応ブラウザでは JSON ダウンロードにフォールバックする。
 */
export function NewProjectModal() {
  const isOpen = useDiagramStore((s) => s.isNewProjectConfirmOpen);
  const close = useDiagramStore((s) => s.closeNewProjectConfirm);
  const newProject = useDiagramStore((s) => s.newProject);

  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<Status>(IDLE);

  useEffect(() => {
    if (!isOpen) return;
    setBusy(false);
    setStatus(IDLE);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, close]);

  if (!isOpen) return null;

  /** 現在のプロジェクトをファイルへ保存する。成功で true、ユーザーキャンセルで false。 */
  const saveCurrentToFile = async (): Promise<boolean> => {
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
    const base = projectFilename(s.projectMeta.name);
    if (!isFileSystemAccessSupported()) {
      // 非対応ブラウザ（Firefox / Safari）はダウンロード保存にフォールバック
      triggerDownload(base, JSON.stringify(project, null, 2), 'application/json');
      return true;
    }
    let dir = await getSavedDirectoryHandle();
    if (dir && !(await ensurePermission(dir))) dir = null;
    if (!dir) {
      dir = await pickDirectory();
      if (!dir) return false; // ユーザーキャンセル
      if (!(await ensurePermission(dir))) {
        throw new Error('フォルダへのアクセスが許可されませんでした。');
      }
    }
    // 同名ファイルを黙って上書きしないよう、衝突時は連番を付ける
    const name = uniqueFilename(await listProjectFiles(dir), base);
    await writeProjectFile(dir, name, project);
    return true;
  };

  const handleSaveAndCreate = async () => {
    setBusy(true);
    setStatus(IDLE);
    try {
      const saved = await saveCurrentToFile();
      if (!saved) return; // キャンセル時はモーダルを開いたまま
      newProject();
    } catch (e) {
      setStatus({ kind: 'error', message: `保存に失敗: ${(e as Error).message}` });
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
        className="w-[480px] max-w-[92vw] bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 flex flex-col gap-4"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">
            新規プロジェクト
          </h2>
          <button
            onClick={close}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            aria-label="閉じる"
          >
            <X size={16} />
          </button>
        </div>

        <p className="text-[12px] text-slate-300 leading-relaxed">
          現在の作業内容を消去して、まっさらな新規プロジェクトを作成します。
          作成する前に、現在のプロジェクトをファイルへ保存しますか？
        </p>
        <p className="text-[11px] text-amber-200 leading-relaxed rounded-lg border border-amber-600/60 bg-amber-900/20 p-3">
          保存せずに作成すると、現在の図・手動脅威・DREAD 評価などは失われます。
        </p>

        {status.kind === 'error' && (
          <p className="text-[11px] leading-relaxed break-words text-rose-400">{status.message}</p>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <button
            onClick={close}
            disabled={busy}
            className="px-4 py-2 text-xs font-bold uppercase tracking-wider text-slate-300 hover:text-white transition-colors disabled:opacity-40"
          >
            キャンセル
          </button>
          <button
            onClick={() => newProject()}
            disabled={busy}
            className="flex items-center gap-2 px-4 py-2 text-xs font-bold uppercase tracking-wider text-white rounded-lg transition-colors bg-slate-700 hover:bg-slate-600 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <FilePlus size={14} />
            保存せずに作成
          </button>
          <button
            onClick={() => void handleSaveAndCreate()}
            disabled={busy}
            className="flex items-center gap-2 px-4 py-2 text-xs font-bold uppercase tracking-wider text-white rounded-lg transition-colors bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Save size={14} />
            {busy ? '保存中…' : '保存して作成'}
          </button>
        </div>
      </div>
    </div>
  );
}
