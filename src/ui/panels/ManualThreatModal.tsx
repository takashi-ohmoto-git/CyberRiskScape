import { useEffect, useMemo, useState } from 'react';
import { X } from 'lucide-react';
import {
  selectActiveManualThreats,
  selectActiveNodes,
  selectPrimaryNodeId,
  useDiagramStore,
} from '../../core/state/diagramStore';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import { componentRegistry } from '../../component-library/defaultRegistry';
import type { ComponentTypeId, Framework, Severity } from '../../core/model/types';
import { FRAMEWORK_VIEW_LABELS, MANUAL_THREAT_FRAMEWORKS } from '../frameworkLabels';

interface ManualThreatDraft {
  /** 対象の符号化値。'' = 全体 / 'type:<id>' = コンポーネント型 / 'node:<id>' = 配置済みノード。 */
  target: string;
  /** 紐付けるフレームワーク。ALL ビューでの新規作成時のみピッカーで選択可能。 */
  framework: Framework;
  category: string;
  severity: Severity;
  description: string;
  mitigation: string;
}

const EMPTY_DRAFT: ManualThreatDraft = {
  target: '',
  framework: 'STRIDE',
  category: '',
  severity: 'Medium',
  description: '',
  mitigation: '',
};

function encodeTarget(m: { targetType?: ComponentTypeId; nodeId?: string }): string {
  if (m.targetType) return `type:${m.targetType}`;
  if (m.nodeId) return `node:${m.nodeId}`;
  return '';
}

function decodeTarget(v: string): { nodeId?: string; targetType?: ComponentTypeId } {
  if (v.startsWith('type:')) return { targetType: v.slice(5) };
  if (v.startsWith('node:')) return { nodeId: v.slice(5) };
  return {};
}

const SEVERITY_OPTIONS: { val: Severity; label: string; activeClass: string }[] = [
  { val: 'Low', label: 'Low', activeClass: 'bg-blue-600 border-blue-400 text-white' },
  { val: 'Medium', label: 'Medium', activeClass: 'bg-blue-600 border-blue-400 text-white' },
  { val: 'High', label: 'High', activeClass: 'bg-orange-500 border-orange-300 text-white' },
  { val: 'Critical', label: 'Critical', activeClass: 'bg-rose-600 border-rose-400 text-white' },
];

/**
 * 手動脅威シナリオの追加／編集モーダル。`ProjectEditModal` と同じパターン
 * （Esc / 背景クリックで閉じる）。framework は作成時のアクティブ値に固定する。
 *
 * 対象は 3 種から選ぶ：プロジェクト全体 / コンポーネント型（同型ノード全てに適用する
 * プロジェクトローカルなカスタムルール）/ 配置済みノード（特定インスタンス）。
 */
export function ManualThreatModal() {
  const isOpen = useDiagramStore((s) => s.isManualThreatModalOpen);
  const editingId = useDiagramStore((s) => s.editingManualThreatId);
  const activeFramework = useDiagramStore((s) => s.activeFramework);
  const selectedNodeId = useDiagramStore(selectPrimaryNodeId);
  const disabledLibraryIds = useDiagramStore((s) => s.disabledLibraryIds);
  const nodes = useDiagramStore(selectActiveNodes);
  const manualThreats = useDiagramStore(selectActiveManualThreats);
  const addManualThreat = useDiagramStore((s) => s.addManualThreat);
  const updateManualThreat = useDiagramStore((s) => s.updateManualThreat);
  const close = useDiagramStore((s) => s.closeManualThreatEditor);

  const typeSections = useMemo(
    () => componentRegistry.listByCategory(disabledLibraryIds),
    [disabledLibraryIds],
  );

  const editing = editingId ? (manualThreats.find((m) => m.id === editingId) ?? null) : null;
  // ALL ビューでの新規作成時のみ framework ピッカーを表示する。編集時・特定ビュー時は固定。
  const showFrameworkPicker = !editing && activeFramework === 'ALL';

  const [draft, setDraft] = useState<ManualThreatDraft>(EMPTY_DRAFT);

  // モーダルが開かれるたびに、編集対象 or 新規初期値をフォームへ反映する。
  useEffect(() => {
    if (!isOpen) return;
    if (editing) {
      setDraft({
        target: encodeTarget(editing),
        framework: editing.framework,
        category: editing.category,
        severity: editing.severity,
        description: editing.description,
        mitigation: editing.mitigation ?? '',
      });
    } else {
      // 特定ビューなら現在の framework に固定。ALL ビューはピッカー初期値（STRIDE）。
      const initialFramework: Framework =
        activeFramework === 'ALL' ? 'STRIDE' : activeFramework;
      setDraft({
        ...EMPTY_DRAFT,
        framework: initialFramework,
        target: selectedNodeId ? `node:${selectedNodeId}` : '',
      });
    }
  }, [isOpen, editing, selectedNodeId, activeFramework]);

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, close]);

  if (!isOpen) return null;

  const canSave = draft.category.trim() !== '' && draft.description.trim() !== '';

  const handleSave = () => {
    if (!canSave) return;
    const payload = {
      framework: draft.framework,
      ...decodeTarget(draft.target),
      category: draft.category.trim(),
      severity: draft.severity,
      description: draft.description.trim(),
      mitigation: draft.mitigation.trim() === '' ? undefined : draft.mitigation.trim(),
    };
    if (editingId) updateManualThreat(editingId, payload);
    else addManualThreat(payload);
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
          <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">
            {editingId ? 'シナリオを編集' : 'シナリオを追加'}
          </h2>
          <button
            onClick={close}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            aria-label="閉じる"
          >
            <X size={16} />
          </button>
        </div>

        {showFrameworkPicker ? (
          <div className="flex flex-col gap-1.5">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
              フレームワーク
            </span>
            <div className="grid grid-cols-3 gap-2">
              {MANUAL_THREAT_FRAMEWORKS.map((fw) => {
                const selected = draft.framework === fw;
                return (
                  <button
                    key={fw}
                    onClick={() => setDraft((p) => ({ ...p, framework: fw }))}
                    className={`px-2 py-2 rounded-lg text-[11px] font-black border transition-all ${
                      selected
                        ? 'bg-blue-600 border-blue-400 text-white'
                        : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                    }`}
                  >
                    {FRAMEWORK_VIEW_LABELS[fw]}
                  </button>
                );
              })}
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-wider">
            <span className="text-slate-500">フレームワーク</span>
            <span className="bg-slate-800 border border-slate-700 text-slate-300 px-2 py-0.5 rounded">
              {FRAMEWORK_VIEW_LABELS[draft.framework]}
            </span>
            <span className="text-slate-600 normal-case font-normal">作成時に固定されます</span>
          </div>
        )}

        <label className="flex flex-col gap-1.5">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
            脅威カテゴリ / タイトル <span className="text-rose-400">*</span>
          </span>
          <input
            type="text"
            value={draft.category}
            onChange={(e) => setDraft((p) => ({ ...p, category: e.target.value }))}
            placeholder="例: 内部不正による顧客データ持ち出し"
            className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors"
          />
        </label>

        <div className="flex flex-col gap-1.5">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
            深刻度
          </span>
          <div className="grid grid-cols-4 gap-2">
            {SEVERITY_OPTIONS.map((opt) => {
              const selected = draft.severity === opt.val;
              return (
                <button
                  key={opt.val}
                  onClick={() => setDraft((p) => ({ ...p, severity: opt.val }))}
                  className={`px-2 py-2 rounded-lg text-xs font-black border transition-all ${
                    selected
                      ? opt.activeClass
                      : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                  }`}
                >
                  {opt.label}
                </button>
              );
            })}
          </div>
        </div>

        <label className="flex flex-col gap-1.5">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
            対象
          </span>
          <select
            value={draft.target}
            onChange={(e) => setDraft((p) => ({ ...p, target: e.target.value }))}
            className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500 transition-colors"
          >
            <option value="">プロジェクト全体（ノード未指定）</option>
            {typeSections.map((s) => (
              <optgroup key={s.category.id} label={`型: ${s.category.label}（同型ノード全てに適用）`}>
                {s.components.map((c) => (
                  <option key={c.id} value={`type:${c.id}`}>
                    {c.label}
                  </option>
                ))}
              </optgroup>
            ))}
            {nodes.length > 0 && (
              <optgroup label="配置済みノード（このインスタンスのみ）">
                {nodes.map((n) => (
                  <option key={n.id} value={`node:${n.id}`}>
                    {getNodeDisplayName(n)}
                  </option>
                ))}
              </optgroup>
            )}
          </select>
          <span className="text-[9px] text-slate-500 leading-relaxed">
            型を選ぶと、アクティブレイヤー上の同型ノード全てに適用されるプロジェクトローカルな
            カスタムルールになります。
          </span>
        </label>

        <label className="flex flex-col gap-1.5">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
            脅威の内容 <span className="text-rose-400">*</span>
          </span>
          <textarea
            rows={4}
            value={draft.description}
            onChange={(e) => setDraft((p) => ({ ...p, description: e.target.value }))}
            placeholder="想定される攻撃シナリオ・前提条件・影響を記述します。"
            className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors resize-y"
          />
        </label>

        <label className="flex flex-col gap-1.5">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
            緩和策（任意）
          </span>
          <textarea
            rows={3}
            value={draft.mitigation}
            onChange={(e) => setDraft((p) => ({ ...p, mitigation: e.target.value }))}
            placeholder="この脅威への対策・統制を記述します。"
            className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors resize-y"
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
            onClick={handleSave}
            disabled={!canSave}
            className="px-4 py-2 text-xs font-bold uppercase tracking-wider bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            保存
          </button>
        </div>
      </div>
    </div>
  );
}
