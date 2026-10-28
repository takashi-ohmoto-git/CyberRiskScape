import { useState } from 'react';
import { Check, ChevronDown, ChevronRight, Copy, ListTree } from 'lucide-react';
import type { DiagramNode } from '../../core/model/types';
import { useT, type TranslationKey } from '../../i18n';

/**
 * ノードのインベントリ（依存パッケージ・環境変数の取り込み結果）を読み取り専用で表示する。
 * inventory を持たないノードには何も出さない。
 */
export function InventorySection({ node }: { node: DiagramNode }) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const inventory = node.inventory;
  if (!inventory) return null;

  const json = JSON.stringify(inventory, null, 2);
  const copy = () => {
    void navigator.clipboard
      ?.writeText(json)
      .then(() => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1500);
      })
      .catch(() => undefined);
  };

  return (
    <div className="bg-slate-800/50 rounded-2xl border border-slate-700">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full px-4 py-3 flex items-center justify-between text-xs font-bold text-slate-300 hover:text-slate-100 transition-colors"
        aria-expanded={open}
      >
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-left">
          <ListTree size={14} className="text-blue-500 shrink-0" /> {t('panels.inventory.title')}
          <span className="text-xs font-black px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300">
            {t(`panels.inventory.kind.${inventory.kind}` as TranslationKey)}
          </span>
          <span className="text-xs font-normal text-slate-400">
            {inventory.source} / {t('panels.inventory.count', { count: inventory.items.length })} /{' '}
            {inventory.collectedAt}
          </span>
        </span>
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-2">
          {inventory.kind === 'env' && (
            <p className="text-xs text-slate-500 leading-relaxed">{t('panels.inventory.envNote')}</p>
          )}
          <pre
            tabIndex={0}
            className="max-h-64 overflow-auto bg-slate-900 border border-slate-700 rounded-lg p-3 text-xs font-mono text-slate-200 whitespace-pre"
          >
            {json}
          </pre>
          <button
            onClick={copy}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-700 hover:bg-slate-600 text-xs font-bold text-slate-100 transition-colors"
          >
            {copied ? <Check size={12} /> : <Copy size={12} />}
            {t(copied ? 'panels.inventory.copied' : 'panels.inventory.copy')}
          </button>
        </div>
      )}
    </div>
  );
}
