import { Plus, Trash2 } from 'lucide-react';
import {
  emptyLeaf,
  type EdgeDraft,
  type EdgeMode,
} from '../../../features/custom-rules/editor/draft';
import { useT, type TranslationKey } from '../../../i18n';
import { EdgeWhenLeafEditor } from './EdgeWhenLeafEditor';

/**
 * ②マッチ条件（§2.25 Phase D）。`when` / `allOf` / `anyOf` のモード切替と
 * リーフ列の追加/削除を担う。
 *
 * - `when`：単一リーフ。
 * - `allOf`：全リーフの AND（最低 2）。
 * - `anyOf`：いずれかのリーフの OR（最低 2）。
 */
const MODES: { value: EdgeMode; labelKey: TranslationKey; hintKey: TranslationKey }[] = [
  { value: 'when', labelKey: 'ruleEditor.condition.mode.when.label', hintKey: 'ruleEditor.condition.mode.when.hint' },
  { value: 'allOf', labelKey: 'ruleEditor.condition.mode.allOf.label', hintKey: 'ruleEditor.condition.mode.allOf.hint' },
  { value: 'anyOf', labelKey: 'ruleEditor.condition.mode.anyOf.label', hintKey: 'ruleEditor.condition.mode.anyOf.hint' },
];

export function ConditionGroup({
  edge,
  onChange,
}: {
  edge: EdgeDraft;
  onChange: (next: EdgeDraft) => void;
}) {
  const t = useT();
  const setMode = (mode: EdgeMode) => {
    let leaves = edge.leaves;
    if (mode === 'when') {
      leaves = [leaves[0] ?? emptyLeaf()];
    } else if (leaves.length < 2) {
      leaves = [...leaves];
      while (leaves.length < 2) leaves.push(emptyLeaf());
    }
    onChange({ ...edge, mode, leaves });
  };

  const setLeaf = (i: number, next: Parameters<typeof EdgeWhenLeafEditor>[0]['leaf']) =>
    onChange({ ...edge, leaves: edge.leaves.map((l, idx) => (idx === i ? next : l)) });

  const addLeaf = () => onChange({ ...edge, leaves: [...edge.leaves, emptyLeaf()] });
  const removeLeaf = (i: number) =>
    onChange({ ...edge, leaves: edge.leaves.filter((_, idx) => idx !== i) });

  const multi = edge.mode !== 'when';

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap gap-1.5">
        {MODES.map((m) => (
          <button
            key={m.value}
            type="button"
            onClick={() => setMode(m.value)}
            title={t(m.hintKey)}
            className={`px-2.5 py-1 rounded-md text-xs font-bold border transition-colors ${
              edge.mode === m.value
                ? 'bg-blue-600 border-blue-500 text-white'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
            }`}
          >
            {t(m.labelKey)}
          </button>
        ))}
      </div>

      <div className="flex flex-col gap-2">
        {edge.leaves.map((leaf, i) => (
          <div key={i} className="relative">
            {multi && (
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs uppercase tracking-wider text-slate-500">
                  {t('ruleEditor.condition.blockLabel', { index: i + 1 })}
                </span>
                <button
                  type="button"
                  onClick={() => removeLeaf(i)}
                  disabled={edge.leaves.length <= 2}
                  title={edge.leaves.length <= 2 ? t('ruleEditor.condition.minBlocks') : t('ruleEditor.condition.deleteBlock')}
                  className="p-1 text-rose-400 hover:text-rose-300 disabled:opacity-30 disabled:cursor-not-allowed"
                >
                  <Trash2 size={13} />
                </button>
              </div>
            )}
            <EdgeWhenLeafEditor leaf={leaf} onChange={(next) => setLeaf(i, next)} />
          </div>
        ))}
      </div>

      {multi && (
        <button
          type="button"
          onClick={addLeaf}
          className="self-start flex items-center gap-1 text-xs font-bold text-blue-400 hover:text-blue-300"
        >
          <Plus size={13} /> {t('ruleEditor.condition.addBlock')}
        </button>
      )}
    </div>
  );
}
