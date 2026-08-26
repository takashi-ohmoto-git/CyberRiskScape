import { useEffect, useMemo, useState } from 'react';
import { ExternalLink, Library, ShieldCheck, X } from 'lucide-react';
import { useDiagramStore } from '../../core/state/diagramStore';
import { BUNDLED_COMPLIANCE_MAP } from '../../compliance/loader/bundledComplianceMap';
import type { ComplianceItem, StandardId } from '../../compliance/schema/complianceItem';
import { ZeroTrustForAiAgents } from './ZeroTrustForAiAgents';

/** 規格リストの一番上に固定表示する「Zero Trust for AI Agents」ビューのセンチネル ID。 */
const ZERO_TRUST_VIEW = '__zero-trust-ai-agents__' as const;

/**
 * コンプライアンスマップ閲覧モーダル。
 * `BUNDLED_COMPLIANCE_MAP` の規格メタと items を、左ペイン（規格選択）＋
 * 右ペイン（items 一覧）で閲覧できる読み取り専用ビューア。
 */
export function ComplianceMapModal() {
  const isOpen = useDiagramStore((s) => s.isComplianceMapOpen);
  const closeComplianceMap = useDiagramStore((s) => s.closeComplianceMap);

  const standardIds = useMemo(
    () => Array.from(BUNDLED_COMPLIANCE_MAP.standards.keys()),
    [],
  );
  const [selectedId, setSelectedId] = useState<StandardId | typeof ZERO_TRUST_VIEW | null>(
    ZERO_TRUST_VIEW,
  );
  const [filter, setFilter] = useState('');

  // モーダルが閉じた状態から開かれたら、選択を先頭エントリにリセットし検索もクリアする
  useEffect(() => {
    if (isOpen) {
      setSelectedId(ZERO_TRUST_VIEW);
      setFilter('');
    }
  }, [isOpen, standardIds]);

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeComplianceMap();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, closeComplianceMap]);

  if (!isOpen) return null;

  const isZeroTrust = selectedId === ZERO_TRUST_VIEW;
  const standardId = isZeroTrust ? null : selectedId;
  const selectedStandard = standardId
    ? BUNDLED_COMPLIANCE_MAP.standards.get(standardId)
    : undefined;
  const selectedItems = standardId
    ? (BUNDLED_COMPLIANCE_MAP.itemsByStandard.get(standardId) ?? [])
    : [];

  const q = filter.trim().toLowerCase();
  const filteredItems = q
    ? selectedItems.filter(
        (i) =>
          i.ref.toLowerCase().includes(q) ||
          i.title.toLowerCase().includes(q) ||
          i.summary.toLowerCase().includes(q),
      )
    : selectedItems;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-150"
      onMouseDown={closeComplianceMap}
    >
      <div
        className="w-[1040px] max-w-[94vw] h-[80vh] bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl flex flex-col overflow-hidden"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Library size={16} className="text-emerald-400" />
            <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">
              Compliance Map
            </h2>
            <span className="text-[10px] text-slate-500 ml-2">
              {standardIds.length} 規格 / 合計 {BUNDLED_COMPLIANCE_MAP.index.size} 項目
            </span>
          </div>
          <button
            onClick={closeComplianceMap}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            aria-label="閉じる"
          >
            <X size={16} />
          </button>
        </div>

        <div className="flex-1 min-h-0 flex">
          <aside className="w-[260px] shrink-0 border-r border-slate-800 overflow-y-auto py-2">
            <button
              onClick={() => setSelectedId(ZERO_TRUST_VIEW)}
              className={`w-full text-left px-4 py-3 border-l-2 transition-colors ${
                isZeroTrust
                  ? 'border-emerald-500 bg-emerald-500/5'
                  : 'border-transparent hover:bg-slate-800/60'
              }`}
            >
              <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-500 mb-0.5">
                <ShieldCheck size={11} className="text-emerald-400" />
                FRAMEWORK
              </div>
              <div className="text-xs font-bold text-slate-100 leading-tight">
                Zero Trust for AI Agents
              </div>
              <div className="text-[10px] text-slate-500 mt-1">Anthropic eBook (2026)</div>
            </button>
            <div className="my-1 mx-4 border-t border-slate-800" />
            {standardIds.map((id) => {
              const meta = BUNDLED_COMPLIANCE_MAP.standards.get(id);
              const count = BUNDLED_COMPLIANCE_MAP.itemsByStandard.get(id)?.length ?? 0;
              const isActive = id === selectedId;
              return (
                <button
                  key={id}
                  onClick={() => setSelectedId(id)}
                  className={`w-full text-left px-4 py-3 border-l-2 transition-colors ${
                    isActive
                      ? 'border-emerald-500 bg-emerald-500/5'
                      : 'border-transparent hover:bg-slate-800/60'
                  }`}
                >
                  <div className="text-[10px] font-mono text-slate-500 mb-0.5">
                    {id}
                  </div>
                  <div className="text-xs font-bold text-slate-100 leading-tight">
                    {meta?.title ?? id}
                    {meta?.version && (
                      <span className="ml-1 text-slate-500 font-normal">
                        v{meta.version}
                      </span>
                    )}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1">{count} 項目</div>
                </button>
              );
            })}
          </aside>

          <section className="flex-1 min-w-0 flex flex-col">
            {isZeroTrust ? (
              <ZeroTrustForAiAgents />
            ) : selectedStandard ? (
              <>
                <div className="px-6 py-4 border-b border-slate-800">
                  <div className="flex items-baseline justify-between gap-4 flex-wrap">
                    <div>
                      <h3 className="text-base font-bold text-slate-100">
                        {selectedStandard.title}
                        {selectedStandard.version && (
                          <span className="ml-2 text-sm font-normal text-slate-500">
                            v{selectedStandard.version}
                          </span>
                        )}
                      </h3>
                      <div className="mt-1 flex items-center gap-3 text-[10px] text-slate-500">
                        <a
                          href={selectedStandard.url}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="inline-flex items-center gap-1 text-slate-400 hover:text-emerald-400 transition-colors"
                        >
                          公式情報 <ExternalLink size={10} />
                        </a>
                        {selectedStandard.license && (
                          <span>ライセンス: {selectedStandard.license}</span>
                        )}
                      </div>
                    </div>
                    <input
                      type="text"
                      value={filter}
                      onChange={(e) => setFilter(e.target.value)}
                      placeholder="ref / 名称 / 要約 で絞り込み"
                      className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors w-[260px]"
                    />
                  </div>
                  {selectedStandard.disclaimer && (
                    <p className="mt-3 text-[11px] text-slate-500 leading-relaxed border-l-2 border-slate-700 pl-3">
                      {selectedStandard.disclaimer}
                    </p>
                  )}
                </div>

                <div className="flex-1 overflow-y-auto px-6 py-4">
                  {filteredItems.length === 0 ? (
                    <p className="text-xs text-slate-500">該当する項目はありません。</p>
                  ) : (
                    <ul className="flex flex-col gap-2">
                      {filteredItems.map((item) => (
                        <ItemRow key={item.ref} item={item} />
                      ))}
                    </ul>
                  )}
                </div>
              </>
            ) : (
              <div className="flex-1 flex items-center justify-center text-xs text-slate-500">
                左のリストから規格を選択してください。
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}

function ItemRow({ item }: { item: ComplianceItem }) {
  return (
    <li className="p-3 rounded-lg bg-slate-800/40 border border-slate-800">
      <div className="flex items-baseline gap-3 flex-wrap">
        <span className="text-[11px] font-mono font-bold text-emerald-400 shrink-0">
          {item.ref}
        </span>
        <span className="text-xs font-bold text-slate-100">{item.title}</span>
        {item.url && (
          <a
            href={item.url}
            target="_blank"
            rel="noreferrer noopener"
            className="text-slate-500 hover:text-emerald-400 transition-colors"
            title="原文リンク"
          >
            <ExternalLink size={11} />
          </a>
        )}
      </div>
      <p className="mt-1.5 text-[11px] text-slate-400 leading-relaxed">{item.summary}</p>
      {item.relatedTo && item.relatedTo.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {item.relatedTo.map((rel) => (
            <span
              key={`${rel.standard}:${rel.ref}`}
              className="text-[10px] px-2 py-0.5 rounded bg-slate-700/40 text-slate-400 border border-slate-700"
              title="対応する他規格項目（クロスウォーク）"
            >
              {rel.standard} / {rel.ref}
            </span>
          ))}
        </div>
      )}
    </li>
  );
}
