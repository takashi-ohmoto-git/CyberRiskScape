import { ArrowDown, ArrowUp, Plus, Trash2 } from 'lucide-react';
import { SeveritySchema } from '../../../threat-library/schema/threatRule';
import {
  emptyLeaf,
  type ConditionCaseDraft,
  type RuleDraft,
} from '../../../features/custom-rules/editor/draft';
import { EdgeWhenLeafEditor } from './EdgeWhenLeafEditor';

/**
 * ③ severity 分岐（§2.25 Phase D）。`conditions[]` の first-match-wins を
 * if / elif / else の縦フローとして編集する（上から順に評価、最初に一致した
 * ケースで severity / description を上書き）。
 *
 * - 各ケースは `when`（リーフ）＋ 上書きする severity / description。
 * - severity '' = 据え置き、description 空 = 据え置き（最低どちらか 1 つが必要）。
 * - 末尾の「else（デフォルト）」はルール本体の severity / description。
 */
export function SeverityBranchEditor({
  conditions,
  defaultSeverity,
  defaultDescription,
  onChange,
}: {
  conditions: ConditionCaseDraft[];
  defaultSeverity: RuleDraft['severity'];
  defaultDescription: string;
  onChange: (next: ConditionCaseDraft[]) => void;
}) {
  const setCase = (i: number, next: ConditionCaseDraft) =>
    onChange(conditions.map((c, idx) => (idx === i ? next : c)));

  const addCase = () =>
    onChange([...conditions, { when: emptyLeaf(), severity: '', description: '' }]);

  const removeCase = (i: number) => onChange(conditions.filter((_, idx) => idx !== i));

  const move = (i: number, delta: number) => {
    const j = i + delta;
    if (j < 0 || j >= conditions.length) return;
    const next = [...conditions];
    [next[i], next[j]] = [next[j], next[i]];
    onChange(next);
  };

  return (
    <div className="flex flex-col gap-2">
      <p className="text-[11px] text-slate-500 leading-relaxed">
        上から順に評価し、最初に一致したケースで重大度・説明を上書きします（任意）。どのケースにも
        一致しなければ下の「デフォルト」が使われます。
      </p>

      {conditions.map((c, i) => (
        <div key={i} className="bg-slate-900/60 border border-slate-700/70 rounded-lg p-3 flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase tracking-wider text-amber-400 font-bold">
              {i === 0 ? 'if' : 'else if'} #{i + 1}
            </span>
            <div className="flex items-center gap-0.5">
              <button
                type="button"
                onClick={() => move(i, -1)}
                disabled={i === 0}
                title="上へ"
                className="p-1 text-slate-400 hover:text-slate-100 disabled:opacity-30"
              >
                <ArrowUp size={13} />
              </button>
              <button
                type="button"
                onClick={() => move(i, 1)}
                disabled={i === conditions.length - 1}
                title="下へ"
                className="p-1 text-slate-400 hover:text-slate-100 disabled:opacity-30"
              >
                <ArrowDown size={13} />
              </button>
              <button
                type="button"
                onClick={() => removeCase(i)}
                title="ケースを削除"
                className="p-1 text-rose-400 hover:text-rose-300"
              >
                <Trash2 size={13} />
              </button>
            </div>
          </div>

          <EdgeWhenLeafEditor leaf={c.when} onChange={(when) => setCase(i, { ...c, when })} />

          <div className="grid grid-cols-[120px_1fr] gap-2 items-center">
            <span className="text-[11px] text-slate-500">→ 重大度</span>
            <select
              value={c.severity}
              onChange={(e) =>
                setCase(i, { ...c, severity: e.target.value as ConditionCaseDraft['severity'] })
              }
              className="bg-slate-800 border border-slate-700 rounded-md px-2 py-1 text-[12px] text-slate-100 focus:outline-none focus:border-blue-500"
            >
              <option value="">（据え置き）</option>
              {SeveritySchema.options.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-[120px_1fr] gap-2 items-start">
            <span className="text-[11px] text-slate-500 pt-1">→ 説明（上書き）</span>
            <textarea
              value={c.description}
              onChange={(e) => setCase(i, { ...c, description: e.target.value })}
              rows={2}
              placeholder="空 = 据え置き"
              className="bg-slate-800 border border-slate-700 rounded-md px-2 py-1 text-[12px] text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 resize-y"
            />
          </div>
        </div>
      ))}

      <div className="bg-slate-800/40 border border-dashed border-slate-700 rounded-lg p-3">
        <span className="text-[10px] uppercase tracking-wider text-slate-500 font-bold">
          else（デフォルト）
        </span>
        <p className="text-[12px] text-slate-300 mt-1">
          重大度 <span className="font-bold">{defaultSeverity}</span> ／{' '}
          {defaultDescription.trim() === '' ? (
            <span className="text-slate-600">説明未設定</span>
          ) : (
            defaultDescription
          )}
        </p>
      </div>

      <button
        type="button"
        onClick={addCase}
        className="self-start flex items-center gap-1 text-[11px] font-bold text-amber-400 hover:text-amber-300"
      >
        <Plus size={13} /> 分岐ケースを追加
      </button>
    </div>
  );
}
