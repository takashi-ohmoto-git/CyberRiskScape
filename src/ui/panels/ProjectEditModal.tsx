import { useEffect, useState } from 'react';
import { X } from 'lucide-react';
import { useDiagramStore } from '../../core/state/diagramStore';
import type { ProjectMeta } from '../../core/model/types';

export function ProjectEditModal() {
  const isOpen = useDiagramStore((s) => s.isProjectEditOpen);
  const projectMeta = useDiagramStore((s) => s.projectMeta);
  const setProjectMeta = useDiagramStore((s) => s.setProjectMeta);
  const closeProjectEdit = useDiagramStore((s) => s.closeProjectEdit);

  const [draft, setDraft] = useState<ProjectMeta>(projectMeta);

  // モーダルが開かれるたびに、ストアの最新値をフォームに反映する
  useEffect(() => {
    if (isOpen) setDraft(projectMeta);
  }, [isOpen, projectMeta]);

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeProjectEdit();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, closeProjectEdit]);

  if (!isOpen) return null;

  const handleSave = () => {
    setProjectMeta(draft);
    closeProjectEdit();
  };

  const update = <K extends keyof ProjectMeta>(field: K, value: ProjectMeta[K]) =>
    setDraft((prev) => ({ ...prev, [field]: value }));

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-150"
      onMouseDown={closeProjectEdit}
    >
      <div
        className="w-[560px] max-w-[92vw] max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 flex flex-col gap-4"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">
            Project Edit
          </h2>
          <button
            onClick={closeProjectEdit}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            aria-label="閉じる"
          >
            <X size={16} />
          </button>
        </div>

        <Field
          label="プロジェクト名"
          value={draft.name}
          onChange={(v) => update('name', v)}
          placeholder="例: 与信判定サービス 脅威モデリング"
        />
        <Field
          label="システム名称"
          value={draft.systemName}
          onChange={(v) => update('systemName', v)}
          placeholder="例: CreditScoringAPI v2"
        />
        <FieldArea
          label="システム目的"
          value={draft.purpose}
          onChange={(v) => update('purpose', v)}
          placeholder="このシステムが解決する課題・提供する価値を簡潔に。"
        />
        <FieldArea
          label="ビジネスインパクト"
          value={draft.businessImpact}
          onChange={(v) => update('businessImpact', v)}
          placeholder="停止・侵害が発生した場合の事業影響（金額・期間・対象顧客数など）。"
        />
        <FieldArea
          label="セキュリティ目標"
          value={draft.securityObjectives}
          onChange={(v) => update('securityObjectives', v)}
          placeholder="守るべき機密性・完全性・可用性などの到達目標。脅威の優先度付けの基準になります。"
        />

        <div className="flex justify-end gap-2 pt-2">
          <button
            onClick={closeProjectEdit}
            className="px-4 py-2 text-xs font-bold uppercase tracking-wider text-slate-300 hover:text-white transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={handleSave}
            className="px-4 py-2 text-xs font-bold uppercase tracking-wider bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
          >
            保存
          </button>
        </div>
      </div>
    </div>
  );
}

interface FieldProps {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}

function Field({ label, value, onChange, placeholder }: FieldProps) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
        {label}
      </span>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors"
      />
    </label>
  );
}

function FieldArea({ label, value, onChange, placeholder }: FieldProps) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
        {label}
      </span>
      <textarea
        rows={3}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors resize-y"
      />
    </label>
  );
}
