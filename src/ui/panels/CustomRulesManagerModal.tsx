import { useEffect, useRef, useState } from 'react';
import {
  ChevronDown,
  ChevronRight,
  Copy,
  Download,
  FileUp,
  Pencil,
  Plus,
  Trash2,
  X,
} from 'lucide-react';
import { useCustomRulesStore } from '../../features/custom-rules/store';
import { createEmptyLibrary, type CustomRuleLibrary } from '../../features/custom-rules/schema';
import { parseLibraryFromJson, serializeLibraryToJson } from '../../features/custom-rules/io';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';
import type { ThreatRule } from '../../threat-library/schema/threatRule';
import { RuleEditorModal } from './RuleEditorModal';
import { BundledRulePicker } from './rule-editor/BundledRulePicker';

/** 出荷ルールの id 集合（カスタム id の衝突検査に使う、mergeRules と同じ優先順位）。 */
const BUNDLED_RULE_IDS: ReadonlySet<string> = new Set(
  BUNDLED_THREAT_LIBRARY.rules.map((r) => r.id),
);

/** 編集中ルールを除く全予約 id（出荷 + 他の有効ライブラリ + 同一ライブラリの他ルール）。 */
function buildReservedIds(
  libraries: CustomRuleLibrary[],
  targetLibId: string,
  editingRuleId: string | null,
): Set<string> {
  const ids = new Set<string>(BUNDLED_RULE_IDS);
  for (const lib of libraries) {
    const sameLib = lib.id === targetLibId;
    // 衝突源は「出荷」「有効な他ライブラリ」「同一ライブラリ（編集対象自身を除く）」。
    if (!sameLib && !lib.enabled) continue;
    for (const rule of lib.rules) {
      if (sameLib && rule.id === editingRuleId) continue;
      ids.add(rule.id);
    }
  }
  return ids;
}

/** JSON テキストをファイルとしてダウンロードさせる（DOM 副作用）。 */
function downloadJson(filename: string, text: string): void {
  const blob = new Blob([text], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/** ファイル名に使えない文字を安全化する。 */
function safeFilename(name: string): string {
  return name.replace(/[^\w.-]+/g, '_').slice(0, 80) || 'rule-library';
}

/**
 * カスタム脅威ルールライブラリの管理モーダル（Phase C）。
 * 一覧・新規作成・有効/無効・削除・JSON インポート/エクスポートを行う。
 * 各ルールの編集（フォーム）は Phase D で追加予定。
 */
export function CustomRulesManagerModal() {
  const isOpen = useCustomRulesStore((s) => s.isManagerOpen);
  const close = useCustomRulesStore((s) => s.closeManager);
  const libraries = useCustomRulesStore((s) => s.libraries);
  const upsertLibrary = useCustomRulesStore((s) => s.upsertLibrary);
  const deleteLibrary = useCustomRulesStore((s) => s.deleteLibrary);
  const toggleLibrary = useCustomRulesStore((s) => s.toggleLibrary);

  const [newName, setNewName] = useState('');
  const [importError, setImportError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());
  const [editing, setEditing] = useState<{ libraryId: string; rule: ThreatRule | null } | null>(
    null,
  );
  /** 出荷ルール複製ピッカーの対象ライブラリ id（null = 閉）。 */
  const [cloneTargetLibId, setCloneTargetLibId] = useState<string | null>(null);

  const toggleExpand = (id: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  /** ルールを保存（同 id があれば置換、なければ追加）してライブラリを upsert。 */
  const handleSaveRule = (rule: ThreatRule) => {
    if (!editing) return;
    const lib = libraries.find((l) => l.id === editing.libraryId);
    if (!lib) return;
    const editingId = editing.rule?.id ?? null;
    const exists = lib.rules.some((r) => r.id === editingId);
    const rules = exists
      ? lib.rules.map((r) => (r.id === editingId ? rule : r))
      : [...lib.rules, rule];
    upsertLibrary({ ...lib, rules });
    setEditing(null);
  };

  const handleDeleteRule = (lib: CustomRuleLibrary, ruleId: string) => {
    upsertLibrary({ ...lib, rules: lib.rules.filter((r) => r.id !== ruleId) });
  };

  /** 出荷ルールを複製してエディタを開く（id を一意化し、新規ルールとして扱う）。 */
  const handlePickBundled = (rule: ThreatRule) => {
    if (!cloneTargetLibId) return;
    const reserved = buildReservedIds(libraries, cloneTargetLibId, null);
    let id = `${rule.id}-copy`;
    for (let n = 2; reserved.has(id); n++) id = `${rule.id}-copy-${n}`;
    const clone: ThreatRule = { ...structuredClone(rule), id };
    setEditing({ libraryId: cloneTargetLibId, rule: clone });
    setCloneTargetLibId(null);
  };

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, close]);

  if (!isOpen) return null;

  const handleCreate = () => {
    const name = newName.trim();
    if (name === '') return;
    upsertLibrary(createEmptyLibrary(name));
    setNewName('');
  };

  const handleExport = (lib: CustomRuleLibrary) => {
    downloadJson(`${safeFilename(lib.name)}.json`, serializeLibraryToJson(lib));
  };

  const handleImportFile = async (file: File) => {
    setImportError(null);
    const text = await file.text();
    const result = parseLibraryFromJson(text);
    if (result.ok) {
      upsertLibrary(result.library);
    } else {
      setImportError(`${file.name}: ${result.error}`);
    }
  };

  return (
    <>
      <div
        className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-150"
        onMouseDown={close}
      >
        <div
          className="w-[640px] max-w-[94vw] max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 flex flex-col gap-4"
          onMouseDown={(e) => e.stopPropagation()}
        >
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">
            カスタム脅威ルール
          </h2>
          <button
            onClick={close}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            aria-label="閉じる"
          >
            <X size={16} />
          </button>
        </div>

        <p className="text-[11px] text-slate-500 leading-relaxed">
          ここで作成・取り込んだルールは<strong className="text-slate-400">全プロジェクト共通</strong>
          で評価されます（出荷ルールとは別系統のユーザーデータ）。
        </p>

        {/* 新規作成 / インポート */}
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="text"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
            placeholder="新規ライブラリ名"
            className="flex-1 min-w-[180px] bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
          />
          <button
            onClick={handleCreate}
            disabled={newName.trim() === ''}
            className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-[11px] font-black uppercase tracking-wider px-3 py-2 rounded-lg transition-colors"
          >
            <Plus size={14} /> 作成
          </button>
          <button
            onClick={() => fileInputRef.current?.click()}
            className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-[11px] font-black uppercase tracking-wider px-3 py-2 rounded-lg transition-colors"
          >
            <FileUp size={14} /> JSON インポート
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept="application/json,.json"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) void handleImportFile(file);
              e.target.value = ''; // 同じファイルを再選択できるようにリセット
            }}
          />
        </div>

        {importError && (
          <p className="text-[11px] text-rose-400 bg-rose-500/10 border border-rose-500/30 rounded-lg px-3 py-2 leading-relaxed">
            インポート失敗 — {importError}
          </p>
        )}

        {/* ライブラリ一覧 */}
        {libraries.length === 0 ? (
          <p className="text-xs text-slate-600 py-8 text-center">
            まだカスタムルールライブラリはありません。
          </p>
        ) : (
          <div className="space-y-2">
            {libraries.map((lib) => {
              const isOpen = expanded.has(lib.id);
              return (
                <div
                  key={lib.id}
                  className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden"
                >
                  <div className="flex items-center gap-2 px-3 py-2.5">
                    <button
                      onClick={() => toggleExpand(lib.id)}
                      title={isOpen ? '折りたたむ' : 'ルールを表示'}
                      className="shrink-0 p-1 text-slate-400 hover:text-slate-100"
                    >
                      {isOpen ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                    </button>
                    <button
                      onClick={() => toggleLibrary(lib.id)}
                      title={lib.enabled ? '有効（クリックで無効化）' : '無効（クリックで有効化）'}
                      className={`shrink-0 inline-block w-2.5 h-2.5 rounded-full ${
                        lib.enabled ? 'bg-emerald-500' : 'bg-slate-600'
                      }`}
                    />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-bold text-slate-100 truncate">{lib.name}</p>
                      <p className="text-[10px] text-slate-500 uppercase tracking-wider">
                        ルール {lib.rules.length} 件 {lib.enabled ? '' : '· 無効'}
                      </p>
                    </div>
                    <button
                      onClick={() => handleExport(lib)}
                      title="JSON エクスポート"
                      className="shrink-0 p-2 text-slate-400 hover:text-slate-100 transition-colors"
                    >
                      <Download size={15} />
                    </button>
                    <button
                      onClick={() => deleteLibrary(lib.id)}
                      title="削除"
                      className="shrink-0 p-2 text-rose-400 hover:text-rose-300 transition-colors"
                    >
                      <Trash2 size={15} />
                    </button>
                  </div>

                  {isOpen && (
                    <div className="border-t border-slate-700/70 px-3 py-2.5 space-y-1.5">
                      {lib.rules.map((rule) => {
                        const isEdge = rule.appliesTo.kind === 'edge';
                        return (
                          <div
                            key={rule.id}
                            className="flex items-center gap-2 bg-slate-900/50 rounded-lg px-2.5 py-1.5"
                          >
                            <span
                              className="shrink-0 text-[9px] font-black uppercase tracking-wider px-1.5 py-0.5 rounded bg-slate-700/70 text-slate-300"
                              title={isEdge ? 'エッジルール' : 'ノードルール'}
                            >
                              {isEdge ? 'edge' : 'node'}
                            </span>
                            <div className="flex-1 min-w-0">
                              <p className="text-[12px] text-slate-200 truncate font-mono">
                                {rule.id}
                              </p>
                              <p className="text-[10px] text-slate-500 truncate">
                                {rule.framework} · {rule.category} · {rule.severity}
                              </p>
                            </div>
                            <button
                              onClick={() => setEditing({ libraryId: lib.id, rule })}
                              title="編集"
                              className="shrink-0 p-1.5 text-slate-400 hover:text-slate-100"
                            >
                              <Pencil size={13} />
                            </button>
                            <button
                              onClick={() => handleDeleteRule(lib, rule.id)}
                              title="ルールを削除"
                              className="shrink-0 p-1.5 text-rose-400 hover:text-rose-300"
                            >
                              <Trash2 size={13} />
                            </button>
                          </div>
                        );
                      })}
                      <div className="flex items-center gap-4 pt-1">
                        <button
                          onClick={() => setEditing({ libraryId: lib.id, rule: null })}
                          className="flex items-center gap-1 text-[11px] font-bold text-blue-400 hover:text-blue-300"
                        >
                          <Plus size={13} /> ルールを追加
                        </button>
                        <button
                          onClick={() => setCloneTargetLibId(lib.id)}
                          className="flex items-center gap-1 text-[11px] font-bold text-slate-400 hover:text-slate-200"
                        >
                          <Copy size={13} /> 出荷ルールから複製
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        <p className="text-[10px] text-slate-600 leading-relaxed">
          ライブラリを展開してルール（エッジ／ノード）を追加・編集できます。JSON
          インポートでの取り込みも引き続き利用できます。
        </p>
        </div>
      </div>

      {editing &&
        (() => {
          const lib = libraries.find((l) => l.id === editing.libraryId);
          const isExisting = !!editing.rule && !!lib?.rules.some((r) => r.id === editing.rule!.id);
          return (
            <RuleEditorModal
              initialRule={editing.rule}
              isExisting={isExisting}
              reservedIds={buildReservedIds(
                libraries,
                editing.libraryId,
                isExisting ? editing.rule!.id : null,
              )}
              onSave={handleSaveRule}
              onClose={() => setEditing(null)}
            />
          );
        })()}

      {cloneTargetLibId && (
        <BundledRulePicker onPick={handlePickBundled} onClose={() => setCloneTargetLibId(null)} />
      )}
    </>
  );
}
