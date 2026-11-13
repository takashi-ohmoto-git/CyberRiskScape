import { useEffect, useState } from 'react';
import { X } from 'lucide-react';
import { useDiagramStore } from '../../core/state/diagramStore';
import {
  BUSINESS_CRITICALITIES,
  PROJECT_LIFECYCLES,
  type BusinessCriticality,
  type ProjectLifecycle,
  type ProjectMeta,
} from '../../core/model/types';
import { useT } from '../../i18n';
import type { TranslationKey } from '../../i18n';

const CRITICALITY_KEYS: Record<BusinessCriticality, TranslationKey> = {
  High: 'project.editModal.criticality.high',
  Medium: 'project.editModal.criticality.medium',
  Low: 'project.editModal.criticality.low',
};

const LIFECYCLE_KEYS: Record<ProjectLifecycle, TranslationKey> = {
  development: 'project.editModal.lifecycle.development',
  production: 'project.editModal.lifecycle.production',
  legacy: 'project.editModal.lifecycle.legacy',
  retiring: 'project.editModal.lifecycle.retiring',
  retired: 'project.editModal.lifecycle.retired',
};

const LIFECYCLE_HINT_KEYS: Record<ProjectLifecycle, TranslationKey> = {
  development: 'project.editModal.lifecycleHint.development',
  production: 'project.editModal.lifecycleHint.production',
  legacy: 'project.editModal.lifecycleHint.legacy',
  retiring: 'project.editModal.lifecycleHint.retiring',
  retired: 'project.editModal.lifecycleHint.retired',
};

export function ProjectEditModal() {
  const t = useT();
  const isOpen = useDiagramStore((s) => s.isProjectEditOpen);
  const projectMeta = useDiagramStore((s) => s.projectMeta);
  const projectId = useDiagramStore((s) => s.projectId);
  const regenerateProjectId = useDiagramStore((s) => s.regenerateProjectId);
  const setProjectMeta = useDiagramStore((s) => s.setProjectMeta);
  const closeProjectEdit = useDiagramStore((s) => s.closeProjectEdit);

  const [draft, setDraft] = useState<ProjectMeta>(projectMeta);
  const [confirmingRegenerate, setConfirmingRegenerate] = useState(false);

  // モーダルが開かれるたびに、ストアの最新値をフォームに反映する
  useEffect(() => {
    if (isOpen) setDraft(projectMeta);
    else setConfirmingRegenerate(false);
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

  // 空文字は保存せず undefined にする（組織と運用の任意項目用）
  const updateOptional = (
    field: 'organizationName' | 'organizationCode' | 'department' | 'externalSystemId',
    value: string,
  ) => update(field, value === '' ? undefined : value);

  const copyProjectId = () => {
    try {
      void navigator.clipboard?.writeText(projectId)?.catch(() => undefined);
    } catch {
      // クリップボードが使えない環境では何もしない
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-150"
      onMouseDown={closeProjectEdit}
    >
      <div
        className="w-[92vw] max-w-5xl max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 flex flex-col gap-4"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">
              Project Edit
            </h2>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
                {t('project.editModal.projectIdLabel')}
              </span>
              <code className="font-mono text-xs text-slate-200 break-all">{projectId}</code>
              <button
                type="button"
                onClick={copyProjectId}
                className="px-3 py-1.5 text-xs font-bold uppercase bg-slate-700 hover:bg-slate-600 text-slate-100 rounded-lg transition-colors"
              >
                {t('project.editModal.projectIdCopy')}
              </button>
              {!confirmingRegenerate && (
                <button
                  type="button"
                  onClick={() => setConfirmingRegenerate(true)}
                  className="px-3 py-1.5 text-xs font-bold uppercase bg-slate-700 hover:bg-slate-600 text-slate-100 rounded-lg transition-colors"
                >
                  {t('project.editModal.projectIdRegenerate')}
                </button>
              )}
            </div>
          </div>
          <button
            onClick={closeProjectEdit}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            aria-label={t('project.common.close')}
          >
            <X size={16} />
          </button>
        </div>
        {confirmingRegenerate && (
          <div className="rounded-lg border border-amber-600/60 bg-amber-900/20 p-3 text-xs text-amber-200 leading-relaxed flex flex-col gap-2">
            <p>{t('project.editModal.projectIdRegenerateConfirm')}</p>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => {
                  regenerateProjectId();
                  setConfirmingRegenerate(false);
                }}
                className="px-3 py-1.5 text-xs font-bold uppercase bg-amber-600 hover:bg-amber-500 text-white rounded-lg transition-colors"
              >
                {t('project.editModal.projectIdRegenerateExecute')}
              </button>
              <button
                type="button"
                onClick={() => setConfirmingRegenerate(false)}
                className="px-3 py-1.5 text-xs font-bold uppercase text-slate-300 hover:text-white transition-colors"
              >
                {t('project.common.cancel')}
              </button>
            </div>
          </div>
        )}

        <div className="flex flex-col gap-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">
            {t('project.editModal.basicSectionTitle')}
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Field
              label={t('project.editModal.nameLabel')}
              value={draft.name}
              onChange={(v) => update('name', v)}
              placeholder={t('project.editModal.namePlaceholder')}
            />
            <Field
              label={t('project.editModal.systemNameLabel')}
              value={draft.systemName}
              onChange={(v) => update('systemName', v)}
              placeholder={t('project.editModal.systemNamePlaceholder')}
            />
          </div>
        </div>

        <div className="flex flex-col gap-4 border-t border-slate-700 pt-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">
            {t('project.editModal.purposeSectionTitle')}
          </h3>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <FieldArea
              label={t('project.editModal.purposeLabel')}
              value={draft.purpose}
              onChange={(v) => update('purpose', v)}
              placeholder={t('project.editModal.purposePlaceholder')}
            />
            <FieldArea
              label={t('project.editModal.businessImpactLabel')}
              value={draft.businessImpact}
              onChange={(v) => update('businessImpact', v)}
              placeholder={t('project.editModal.businessImpactPlaceholder')}
            />
            <FieldArea
              label={t('project.editModal.securityObjectivesLabel')}
              value={draft.securityObjectives}
              onChange={(v) => update('securityObjectives', v)}
              placeholder={t('project.editModal.securityObjectivesPlaceholder')}
            />
          </div>
        </div>

        <div className="flex flex-col gap-4 border-t border-slate-700 pt-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">
            {t('project.editModal.peopleSectionTitle')}
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <Field
              label={t('project.editModal.ownerLabel')}
              value={draft.owner ?? ''}
              onChange={(v) => update('owner', v)}
              placeholder={t('project.editModal.ownerPlaceholder')}
              maxLength={200}
            />
            <Field
              label={t('project.editModal.reviewerLabel')}
              value={draft.reviewer ?? ''}
              onChange={(v) => update('reviewer', v)}
              placeholder={t('project.editModal.reviewerPlaceholder')}
              maxLength={200}
            />
            <Field
              label={t('project.editModal.contributorsLabel')}
              value={draft.contributors ?? ''}
              onChange={(v) => update('contributors', v)}
              placeholder={t('project.editModal.contributorsPlaceholder')}
              maxLength={1000}
            />
          </div>
        </div>

        <div className="flex flex-col gap-4 border-t border-slate-700 pt-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">
            {t('project.editModal.organizationSectionTitle')}
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <Field
              label={t('project.editModal.organizationNameLabel')}
              value={draft.organizationName ?? ''}
              onChange={(v) => updateOptional('organizationName', v)}
              placeholder={t('project.editModal.organizationNamePlaceholder')}
              maxLength={200}
            />
            <Field
              label={t('project.editModal.organizationCodeLabel')}
              value={draft.organizationCode ?? ''}
              onChange={(v) => updateOptional('organizationCode', v)}
              placeholder={t('project.editModal.organizationCodePlaceholder')}
              maxLength={100}
            />
            <Field
              label={t('project.editModal.departmentLabel')}
              value={draft.department ?? ''}
              onChange={(v) => updateOptional('department', v)}
              placeholder={t('project.editModal.departmentPlaceholder')}
              maxLength={200}
            />
            <Field
              label={t('project.editModal.externalSystemIdLabel')}
              value={draft.externalSystemId ?? ''}
              onChange={(v) => updateOptional('externalSystemId', v)}
              placeholder={t('project.editModal.externalSystemIdPlaceholder')}
              maxLength={200}
            />
            <SelectField
              label={t('project.editModal.criticalityLabel')}
              value={draft.criticality ?? ''}
              unsetLabel={t('project.editModal.unset')}
              options={BUSINESS_CRITICALITIES.map((c) => ({ value: c, label: t(CRITICALITY_KEYS[c]) }))}
              onChange={(v) => update('criticality', v === '' ? undefined : (v as BusinessCriticality))}
            />
            <div className="flex flex-col gap-1.5">
              <SelectField
                label={t('project.editModal.lifecycleLabel')}
                value={draft.lifecycle ?? ''}
                unsetLabel={t('project.editModal.unset')}
                options={PROJECT_LIFECYCLES.map((l) => ({ value: l, label: t(LIFECYCLE_KEYS[l]) }))}
                onChange={(v) => update('lifecycle', v === '' ? undefined : (v as ProjectLifecycle))}
              />
              {draft.lifecycle && (
                <p className="text-xs text-slate-400 leading-relaxed">
                  {t(LIFECYCLE_HINT_KEYS[draft.lifecycle])}
                </p>
              )}
            </div>
          </div>
        </div>

        <div className="flex flex-col gap-4 border-t border-slate-700 pt-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">
            {t('project.editModal.assumptionsSectionTitle')}
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <FieldArea
              label={t('project.editModal.assumptionsLabel')}
              value={draft.assumptions ?? ''}
              onChange={(v) => update('assumptions', v)}
              placeholder={t('project.editModal.assumptionsPlaceholder')}
              maxLength={4000}
            />
            <FieldArea
              label={t('project.editModal.externalDependenciesLabel')}
              value={draft.externalDependencies ?? ''}
              onChange={(v) => update('externalDependencies', v)}
              placeholder={t('project.editModal.externalDependenciesPlaceholder')}
              maxLength={4000}
            />
          </div>
        </div>

        <div className="flex justify-end gap-2 pt-2">
          <button
            onClick={closeProjectEdit}
            className="px-4 py-2 text-xs font-bold uppercase tracking-wider text-slate-300 hover:text-white transition-colors"
          >
            {t('project.common.cancel')}
          </button>
          <button
            onClick={handleSave}
            className="px-4 py-2 text-xs font-bold uppercase tracking-wider bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
          >
            {t('project.common.save')}
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
  maxLength?: number;
}

function Field({ label, value, onChange, placeholder, maxLength }: FieldProps) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
        {label}
      </span>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        maxLength={maxLength}
        className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors"
      />
    </label>
  );
}

interface SelectFieldProps {
  label: string;
  value: string;
  unsetLabel: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
}

function SelectField({ label, value, unsetLabel, options, onChange }: SelectFieldProps) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
        {label}
      </span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500 transition-colors"
      >
        <option value="">{unsetLabel}</option>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

function FieldArea({ label, value, onChange, placeholder, maxLength }: FieldProps) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
        {label}
      </span>
      <textarea
        rows={3}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        maxLength={maxLength}
        className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors resize-y"
      />
    </label>
  );
}
