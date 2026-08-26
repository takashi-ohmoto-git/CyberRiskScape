/**
 * ルールエディタ共通：列挙値の複数選択チップ群（§2.25 Phase D）。
 * 選択 = OR。空選択はその軸を未指定（= 出力しない）として扱う。
 */
export function ChipGroup<T extends string>({
  options,
  selected,
  onToggle,
  optionLabel,
}: {
  options: readonly T[];
  selected: readonly T[];
  onToggle: (value: T) => void;
  optionLabel?: (value: T) => string;
}) {
  return (
    <div className="flex flex-wrap gap-1">
      {options.map((o) => {
        const on = selected.includes(o);
        return (
          <button
            key={o}
            type="button"
            onClick={() => onToggle(o)}
            className={`px-2 py-0.5 rounded-md text-[11px] font-medium border transition-colors ${
              on
                ? 'bg-blue-600 border-blue-500 text-white'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
            }`}
          >
            {optionLabel ? optionLabel(o) : o}
          </button>
        );
      })}
    </div>
  );
}

/** 配列内の値をトグルする純粋ヘルパ（選択 UI 共通）。 */
export function toggleInArray<T>(arr: readonly T[], value: T): T[] {
  return arr.includes(value) ? arr.filter((x) => x !== value) : [...arr, value];
}
