import { useEffect, useState } from 'react';
import { Plus, Trash2, X } from 'lucide-react';
import {
  FrameworkSchema,
  SeveritySchema,
  type ComplianceRef,
  type Reference,
  type ThreatRule,
} from '../../threat-library/schema/threatRule';
import {
  draftToRule,
  emptyDraft,
  ruleToDraft,
  type RuleDraft,
} from '../../features/custom-rules/editor/draft';
import { ConditionGroup } from './rule-editor/ConditionGroup';
import { NodeTargetEditor } from './rule-editor/NodeTargetEditor';
import { SeverityBranchEditor } from './rule-editor/SeverityBranchEditor';

/**
 * ワークフロー形式ルールエディタ（§2.25 Phase D / D2）。
 *
 * ルールを「① 対象 → ② マッチ条件 → ③ 重大度分岐」の縦パイプラインとして編集する。
 * draft は `ThreatRule` 由来（[[draft]]）で、保存時に `draftToRule`＝`ThreatRuleSchema`
 * で検証する。**D2 は Edge ルールのみ対応**（Node は D3）。
 */
export function RuleEditorModal({
  initialRule,
  isExisting,
  reservedIds,
  onSave,
  onClose,
}: {
  /** null = 新規作成。既存ルール or 複製元なら ruleToDraft で初期化。 */
  initialRule: ThreatRule | null;
  /** true = ライブラリ内の既存ルールを編集中（タイトル表示用）。複製は false。 */
  isExisting?: boolean;
  /** 衝突検査用の予約 id（出荷 + 他有効ライブラリ + 同一ライブラリの他ルール）。 */
  reservedIds: ReadonlySet<string>;
  onSave: (rule: ThreatRule) => void;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState<RuleDraft>(() =>
    initialRule ? ruleToDraft(initialRule) : emptyDraft('edge'),
  );
  const [issues, setIssues] = useState<string[]>([]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const patch = (p: Partial<RuleDraft>) => setDraft((d) => ({ ...d, ...p }));

  const handleSave = () => {
    const result = draftToRule(draft);
    if (!result.ok) {
      setIssues(result.issues);
      return;
    }
    if (reservedIds.has(result.rule.id)) {
      setIssues([
        `id "${result.rule.id}" は既存ルール（出荷 / 他の有効ライブラリ / 同一ライブラリ）と重複しています。一意な id にしてください。`,
      ]);
      return;
    }
    onSave(result.rule);
  };

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 backdrop-blur-sm animate-in fade-in duration-150"
      onMouseDown={onClose}
    >
      <div
        className="w-[760px] max-w-[96vw] max-h-[92vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 flex flex-col gap-5"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">
            {isExisting ? 'ルール編集' : '新規ルール'}
          </h2>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200" aria-label="閉じる">
            <X size={16} />
          </button>
        </div>

        {/* メタ情報 */}
        <Section step="基本" title="ルール情報">
          <div className="grid grid-cols-2 gap-3">
            <Field label="id（一意）">
              <input
                value={draft.id}
                onChange={(e) => patch({ id: e.target.value })}
                placeholder="my-rule-001"
                className={inputCls}
              />
            </Field>
            <Field label="脅威名（タイトル・任意）">
              <input
                value={draft.name}
                onChange={(e) => patch({ name: e.target.value })}
                placeholder="間接プロンプトインジェクション 等"
                className={inputCls}
              />
            </Field>
            <Field label="カテゴリ（分類）">
              <input
                value={draft.category}
                onChange={(e) => patch({ category: e.target.value })}
                placeholder="Tampering 等"
                className={inputCls}
              />
            </Field>
            <Field label="フレームワーク">
              <select
                value={draft.framework}
                onChange={(e) => patch({ framework: e.target.value as RuleDraft['framework'] })}
                className={inputCls}
              >
                {FrameworkSchema.options.map((f) => (
                  <option key={f} value={f}>
                    {f}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="重大度（デフォルト）">
              <select
                value={draft.severity}
                onChange={(e) => patch({ severity: e.target.value as RuleDraft['severity'] })}
                className={inputCls}
              >
                {SeveritySchema.options.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <Field label="説明（{{sourceName}} / {{targetName}} 等のトークン可）">
            <textarea
              value={draft.description}
              onChange={(e) => patch({ description: e.target.value })}
              rows={2}
              className={`${inputCls} resize-y`}
            />
          </Field>
          <Field label="緩和策（[Foundation] / [Enterprise] / [Advanced] markup 可）">
            <textarea
              value={draft.mitigation}
              onChange={(e) => patch({ mitigation: e.target.value })}
              rows={2}
              placeholder="空 = 未設定"
              className={`${inputCls} resize-y`}
            />
          </Field>
        </Section>

        {/* ① 対象 */}
        <Section step="①" title="対象">
          <div className="flex gap-1.5">
            <KindButton active={draft.kind === 'edge'} onClick={() => patch({ kind: 'edge' })}>
              エッジ（接続）
            </KindButton>
            <KindButton active={draft.kind === 'node'} onClick={() => patch({ kind: 'node' })}>
              ノード（コンポーネント）
            </KindButton>
          </div>
        </Section>

        {draft.kind === 'edge' ? (
          <>
            <Section step="②" title="マッチ条件（発火するか）">
              <ConditionGroup edge={draft.edge} onChange={(edge) => patch({ edge })} />
            </Section>
            <Section step="③" title="重大度の分岐（任意）">
              <SeverityBranchEditor
                conditions={draft.edge.conditions}
                defaultSeverity={draft.severity}
                defaultDescription={draft.description}
                onChange={(conditions) => patch({ edge: { ...draft.edge, conditions } })}
              />
            </Section>
          </>
        ) : (
          <Section step="②" title="マッチ条件（対象ノード）">
            <NodeTargetEditor node={draft.node} onChange={(node) => patch({ node })} />
          </Section>
        )}

        {/* 出典・コンプライアンス */}
        <Section step="出典" title="参照・コンプライアンス（任意）">
          <RepeatableRows<Reference>
            label="references（出典）"
            rows={draft.references}
            cols={[
              { key: 'title', placeholder: 'タイトル' },
              { key: 'url', placeholder: 'https://…（任意）' },
            ]}
            onChange={(references) => patch({ references })}
            makeEmpty={() => ({ title: '' })}
          />
          <RepeatableRows<ComplianceRef>
            label="complianceRefs（規制対応）"
            rows={draft.complianceRefs}
            cols={[
              { key: 'standard', placeholder: 'nist-ai-rmf 等' },
              { key: 'ref', placeholder: 'GOVERN 1.1 等' },
            ]}
            onChange={(complianceRefs) => patch({ complianceRefs })}
            makeEmpty={() => ({ standard: '', ref: '' })}
          />
        </Section>

        {issues.length > 0 && (
          <div className="text-[11px] text-rose-400 bg-rose-500/10 border border-rose-500/30 rounded-lg px-3 py-2 leading-relaxed">
            <p className="font-bold mb-1">保存できません：</p>
            <ul className="list-disc list-inside space-y-0.5">
              {issues.map((m, i) => (
                <li key={i}>{m}</li>
              ))}
            </ul>
          </div>
        )}

        <div className="flex justify-end gap-2 pt-1">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-[11px] font-black uppercase tracking-wider bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200"
          >
            キャンセル
          </button>
          <button
            onClick={handleSave}
            className="px-4 py-2 rounded-lg text-[11px] font-black uppercase tracking-wider bg-blue-600 hover:bg-blue-500 text-white"
          >
            保存
          </button>
        </div>
      </div>
    </div>
  );
}

const inputCls =
  'w-full bg-slate-800 border border-slate-700 rounded-md px-2.5 py-1.5 text-[12px] text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500';

function Section({
  step,
  title,
  children,
}: {
  step: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <span className="inline-flex items-center justify-center min-w-[24px] h-6 px-1.5 rounded-md bg-blue-600/20 text-blue-300 text-[11px] font-black">
          {step}
        </span>
        <h3 className="text-[12px] font-bold text-slate-200 uppercase tracking-wider">{title}</h3>
      </div>
      <div className="flex flex-col gap-3 pl-1">{children}</div>
    </section>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[11px] text-slate-500">{label}</span>
      {children}
    </label>
  );
}

function KindButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`px-3 py-1.5 rounded-md text-[11px] font-bold border transition-colors ${
        active
          ? 'bg-blue-600 border-blue-500 text-white'
          : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
      }`}
    >
      {children}
    </button>
  );
}

/** {title,url} / {standard,ref} のような小さな繰り返し行エディタ。 */
function RepeatableRows<T extends Record<string, string | undefined>>({
  label,
  rows,
  cols,
  onChange,
  makeEmpty,
}: {
  label: string;
  rows: T[];
  cols: { key: keyof T & string; placeholder: string }[];
  onChange: (rows: T[]) => void;
  makeEmpty: () => T;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-[11px] text-slate-500">{label}</span>
      {rows.map((row, i) => (
        <div key={i} className="flex gap-1.5 items-center">
          {cols.map((c) => (
            <input
              key={c.key}
              value={row[c.key] ?? ''}
              onChange={(e) => {
                const v = e.target.value;
                onChange(rows.map((r, idx) => (idx === i ? { ...r, [c.key]: v } : r)));
              }}
              placeholder={c.placeholder}
              className={inputCls}
            />
          ))}
          <button
            type="button"
            onClick={() => onChange(rows.filter((_, idx) => idx !== i))}
            className="shrink-0 p-1.5 text-rose-400 hover:text-rose-300"
            title="行を削除"
          >
            <Trash2 size={13} />
          </button>
        </div>
      ))}
      <button
        type="button"
        onClick={() => onChange([...rows, makeEmpty()])}
        className="self-start flex items-center gap-1 text-[11px] font-bold text-blue-400 hover:text-blue-300"
      >
        <Plus size={13} /> 行を追加
      </button>
    </div>
  );
}
