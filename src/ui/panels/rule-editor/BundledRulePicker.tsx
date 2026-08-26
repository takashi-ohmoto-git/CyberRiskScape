import { useEffect, useMemo, useState } from 'react';
import { X } from 'lucide-react';
import { BUNDLED_THREAT_LIBRARY } from '../../../threat-library/loader/bundledLibrary';
import type { ThreatRule } from '../../../threat-library/schema/threatRule';

/**
 * 出荷（bundled）ルールの複製ピッカー（§2.25 Phase D / D4）。
 *
 * 出荷ルールは読み取り専用だが、ここで選択すると複製してカスタムライブラリの
 * 新規ルールとして編集できる（id は呼び出し側で一意化）。
 */
export function BundledRulePicker({
  onPick,
  onClose,
}: {
  onPick: (rule: ThreatRule) => void;
  onClose: () => void;
}) {
  const [query, setQuery] = useState('');

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const rules = BUNDLED_THREAT_LIBRARY.rules;
    if (q === '') return rules;
    return rules.filter(
      (r) =>
        r.id.toLowerCase().includes(q) ||
        r.category.toLowerCase().includes(q) ||
        (r.name?.toLowerCase().includes(q) ?? false) ||
        r.description.toLowerCase().includes(q),
    );
  }, [query]);

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 backdrop-blur-sm animate-in fade-in duration-150"
      onMouseDown={onClose}
    >
      <div
        className="w-[680px] max-w-[96vw] max-h-[88vh] overflow-hidden bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 flex flex-col gap-4"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">
            出荷ルールを複製
          </h2>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200" aria-label="閉じる">
            <X size={16} />
          </button>
        </div>

        <input
          autoFocus
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="id / カテゴリ / 説明で検索"
          className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
        />

        <div className="overflow-y-auto space-y-1.5 pr-1">
          {filtered.length === 0 ? (
            <p className="text-xs text-slate-600 py-8 text-center">該当するルールがありません。</p>
          ) : (
            filtered.map((rule) => (
              <button
                key={rule.id}
                onClick={() => onPick(rule)}
                className="w-full text-left flex items-center gap-2 bg-slate-800/50 hover:bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 transition-colors"
              >
                <span className="shrink-0 text-[9px] font-black uppercase tracking-wider px-1.5 py-0.5 rounded bg-slate-700/70 text-slate-300">
                  {rule.appliesTo.kind}
                </span>
                <div className="flex-1 min-w-0">
                  <p className="text-[12px] text-slate-200 truncate font-mono">{rule.id}</p>
                  <p className="text-[10px] text-slate-500 truncate">
                    {rule.framework} · {rule.category}
                    {rule.name ? ` · ${rule.name}` : ''} · {rule.severity}
                  </p>
                </div>
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
