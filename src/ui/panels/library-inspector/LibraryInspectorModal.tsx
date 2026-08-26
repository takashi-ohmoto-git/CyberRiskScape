import { useEffect, useMemo, useState } from 'react';
import { Search, ScanSearch, X } from 'lucide-react';
import { BUNDLED_THREAT_LIBRARY } from '../../../threat-library/loader/bundledLibrary';
import { selectCustomLibraries, useCustomRulesStore } from '../../../features/custom-rules/store';
import { mergeThreatRules } from '../../../features/custom-rules/mergeRules';
import type { Framework, Severity } from '../../../core/model/types';
import type { ThreatRule } from '../../../threat-library/schema/threatRule';
import { componentRegistry } from '../../../component-library/defaultRegistry';
import type { CategoryDefinition } from '../../../component-library/schema/component';
import { renderIcon } from '../../../component-library/iconRegistry';
import { FRAMEWORK_VIEW_LABELS } from '../../frameworkLabels';
import { useRuleLookup } from '../useRuleLookup';
import { RuleCard } from './RuleCard';
import { useT } from '../../../i18n';

/** severity の強さ順位。canonicalId 畳み込みの代表選定（最大値採用）に使う。buildThreatViews と同じ規則。 */
const SEVERITY_RANK: Record<Severity, number> = { Low: 0, Medium: 1, High: 2, Critical: 3 };

interface RuleGroup {
  representative: ThreatRule;
  members: ThreatRule[];
}

/** canonicalId を共有するルールを 1 枚に畳み込む。未指定ルールは単独グループのまま。 */
function groupByCanonical(rules: ThreatRule[]): RuleGroup[] {
  const membersByCanonical = new Map<string, ThreatRule[]>();
  for (const r of rules) {
    if (!r.canonicalId) continue;
    const arr = membersByCanonical.get(r.canonicalId) ?? [];
    arr.push(r);
    membersByCanonical.set(r.canonicalId, arr);
  }
  const seen = new Set<string>();
  const groups: RuleGroup[] = [];
  for (const r of rules) {
    if (!r.canonicalId) {
      groups.push({ representative: r, members: [r] });
      continue;
    }
    if (seen.has(r.canonicalId)) continue;
    seen.add(r.canonicalId);
    const members = membersByCanonical.get(r.canonicalId) ?? [r];
    const representative = members.reduce((a, b) =>
      SEVERITY_RANK[b.severity] > SEVERITY_RANK[a.severity] ? b : a,
    );
    groups.push({ representative, members });
  }
  return groups;
}

function collectNodeTypes(rules: readonly ThreatRule[]): string[] {
  const set = new Set<string>();
  for (const r of rules) {
    if (r.appliesTo.kind !== 'node') continue;
    if (r.appliesTo.nodeType) set.add(r.appliesTo.nodeType);
    if (r.appliesTo.anyOf) for (const leaf of r.appliesTo.anyOf) set.add(leaf.nodeType);
  }
  return Array.from(set);
}

function ruleAppliesToNodeType(rule: ThreatRule, type: string): boolean {
  if (rule.appliesTo.kind !== 'node') return false;
  if (rule.appliesTo.nodeType === type) return true;
  return rule.appliesTo.anyOf?.some((leaf) => leaf.nodeType === type) ?? false;
}

function isIntrinsic(rule: ThreatRule): boolean {
  return rule.appliesTo.kind === 'node' && rule.appliesTo.connection?.required === false;
}

type Selection = { kind: 'node'; type: string } | { kind: 'edge' };

const FRAMEWORK_OPTIONS: Framework[] = ['STRIDE', 'AI', 'AgenticAI'];
const SEVERITY_OPTIONS: Severity[] = ['Critical', 'High', 'Medium', 'Low'];

interface LibraryInspectorModalProps {
  onClose: () => void;
}

/**
 * 脅威ライブラリを閲覧専用で棚卸しするモーダル。キャンバスとは独立に「どのルールが・
 * どの条件で発火するか」を確認する用途（統計画面ではない）。AnalyticsModal の
 * レイアウトは踏襲せず、左＝ノード型ナビゲーション／右＝発火条件カード一覧の構成にする。
 */
export function LibraryInspectorModal({ onClose }: LibraryInspectorModalProps) {
  const t = useT();
  const customLibraries = useCustomRulesStore(selectCustomLibraries);
  const { getSource } = useRuleLookup();

  const merged = useMemo(
    () => mergeThreatRules(BUNDLED_THREAT_LIBRARY.rules, customLibraries),
    [customLibraries],
  );

  const nodeTypes = useMemo(() => collectNodeTypes(merged.rules), [merged.rules]);

  const [selection, setSelection] = useState<Selection | null>(() =>
    nodeTypes.length > 0 ? { kind: 'node', type: nodeTypes[0] } : { kind: 'edge' },
  );
  const [search, setSearch] = useState('');
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [frameworkFilter, setFrameworkFilter] = useState<'ALL' | Framework>('ALL');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | Severity>('ALL');

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const sourceOptions = useMemo(() => {
    const set = new Set<string>();
    for (const r of merged.rules) {
      const s = getSource(r.id);
      if (s) set.add(s);
    }
    return Array.from(set).sort((a, b) => a.localeCompare(b, 'ja'));
  }, [merged.rules, getSource]);

  const filteredRules = useMemo(() => {
    const q = search.trim().toLowerCase();
    return merged.rules.filter((r) => {
      if (frameworkFilter !== 'ALL' && r.framework !== frameworkFilter) return false;
      if (severityFilter !== 'ALL' && r.severity !== severityFilter) return false;
      if (sourceFilter !== 'ALL' && (getSource(r.id) ?? '') !== sourceFilter) return false;
      if (q) {
        const haystack = `${r.name ?? ''} ${r.category} ${r.id} ${r.description}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }, [merged.rules, frameworkFilter, severityFilter, sourceFilter, search, getSource]);

  const nodeTypeCounts = useMemo(
    () =>
      nodeTypes.map((type) => ({
        type,
        count: filteredRules.filter((r) => ruleAppliesToNodeType(r, type)).length,
      })),
    [nodeTypes, filteredRules],
  );

  const nodeTypeGroups = useMemo(() => {
    const categories = componentRegistry.getCategories();
    const byCategory = new Map<string, typeof nodeTypeCounts>();
    const uncategorized: typeof nodeTypeCounts = [];
    for (const entry of nodeTypeCounts) {
      const category = componentRegistry.get(entry.type)?.category;
      if (category && categories.some((c) => c.id === category)) {
        const arr = byCategory.get(category) ?? [];
        arr.push(entry);
        byCategory.set(category, arr);
      } else {
        uncategorized.push(entry);
      }
    }
    const sortByLabel = (items: typeof nodeTypeCounts) =>
      [...items].sort((a, b) =>
        (componentRegistry.get(a.type)?.label ?? a.type).localeCompare(
          componentRegistry.get(b.type)?.label ?? b.type,
          'ja',
        ),
      );
    const groups: Array<{ category: CategoryDefinition | null; items: typeof nodeTypeCounts }> = categories
      .filter((c) => byCategory.has(c.id))
      .map((category) => ({ category, items: sortByLabel(byCategory.get(category.id) ?? []) }));
    if (uncategorized.length > 0) {
      groups.push({ category: null, items: sortByLabel(uncategorized) });
    }
    return groups;
  }, [nodeTypeCounts]);

  const edgeRuleCount = useMemo(
    () => filteredRules.filter((r) => r.appliesTo.kind === 'edge').length,
    [filteredRules],
  );

  if (!selection) return null;

  let intrinsicGroups: RuleGroup[] = [];
  let conditionalGroups: RuleGroup[] = [];
  let edgeGroups: RuleGroup[] = [];
  let selectedTotal = 0;

  if (selection.kind === 'node') {
    const forType = filteredRules.filter((r) => ruleAppliesToNodeType(r, selection.type));
    selectedTotal = forType.length;
    intrinsicGroups = groupByCanonical(forType.filter(isIntrinsic));
    conditionalGroups = groupByCanonical(forType.filter((r) => !isIntrinsic(r)));
  } else {
    const edgeRules = filteredRules.filter((r) => r.appliesTo.kind === 'edge');
    selectedTotal = edgeRules.length;
    edgeGroups = groupByCanonical(edgeRules);
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-150"
      onMouseDown={onClose}
    >
      <div
        className="w-[1100px] max-w-[96vw] max-h-[90vh] overflow-hidden bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 flex flex-col gap-4"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <h2 className="text-base font-bold text-slate-200 flex items-center gap-2 shrink-0">
            <ScanSearch size={18} className="text-emerald-400" /> {t('libraryInspector.title')}
          </h2>
          <div className="flex items-center gap-2 flex-wrap flex-1 justify-end">
            <div className="relative">
              <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={t('libraryInspector.searchPlaceholder')}
                className="bg-slate-800 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500 transition-colors w-56"
              />
            </div>
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500 transition-colors"
            >
              <option value="ALL">{t('libraryInspector.filter.sourceAll')}</option>
              {sourceOptions.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <select
              value={frameworkFilter}
              onChange={(e) => setFrameworkFilter(e.target.value as 'ALL' | Framework)}
              className="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500 transition-colors"
            >
              <option value="ALL">{t('libraryInspector.filter.frameworkAll')}</option>
              {FRAMEWORK_OPTIONS.map((f) => (
                <option key={f} value={f}>
                  {FRAMEWORK_VIEW_LABELS[f]}
                </option>
              ))}
            </select>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value as 'ALL' | Severity)}
              className="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500 transition-colors"
            >
              <option value="ALL">{t('libraryInspector.filter.severityAll')}</option>
              {SEVERITY_OPTIONS.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <button
              onClick={onClose}
              className="text-slate-500 hover:text-slate-200 transition-colors"
              aria-label={t('libraryInspector.close')}
            >
              <X size={18} />
            </button>
          </div>
        </div>

        <div className="flex gap-4 flex-1 min-h-0">
          {/* 左列: ノード型ナビゲーション */}
          <div className="w-60 shrink-0 overflow-y-auto border-r border-slate-800 pr-3 space-y-1">
            <div className="text-xs font-black text-slate-500 uppercase tracking-widest mb-1.5">
              {t('libraryInspector.leftColumn.nodeTypesHeading')}
            </div>
            {nodeTypeGroups.map(({ category, items }) => (
              <div key={category?.id ?? '__uncategorized'} className="space-y-1">
                <div className="text-xs font-bold text-slate-600 uppercase tracking-widest mt-2 mb-1">
                  {category?.label ?? t('libraryInspector.leftColumn.uncategorized')}
                </div>
                {items.map(({ type, count }) => {
                  const cfg = componentRegistry.get(type);
                  const isSelected = selection.kind === 'node' && selection.type === type;
                  return (
                    <button
                      key={type}
                      onClick={() => setSelection({ kind: 'node', type })}
                      className={`w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-sm font-bold transition-colors ${
                        isSelected
                          ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40'
                          : 'text-slate-300 hover:bg-slate-800 border border-transparent'
                      }`}
                    >
                      <span className={`${cfg?.color ?? 'bg-slate-500'} p-1 rounded text-white shrink-0`}>
                        {renderIcon(cfg?.icon ?? { kind: 'builtin', name: 'box' }, { size: 11 })}
                      </span>
                      <span className="flex-1 text-left truncate">{cfg?.label ?? type}</span>
                      <span className="text-xs font-black text-slate-500">({count})</span>
                    </button>
                  );
                })}
              </div>
            ))}

            <div className="pt-2 mt-2 border-t border-slate-800">
              <button
                onClick={() => setSelection({ kind: 'edge' })}
                className={`w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-sm font-bold transition-colors ${
                  selection.kind === 'edge'
                    ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40'
                    : 'text-slate-300 hover:bg-slate-800 border border-transparent'
                }`}
              >
                <span className="text-left truncate">{t('libraryInspector.leftColumn.edgeRules')}</span>
                <span className="text-xs font-black text-slate-500">({edgeRuleCount})</span>
              </button>
            </div>
          </div>

          {/* 右ペイン: 発火条件カード */}
          <div className="flex-1 overflow-y-auto pr-1 space-y-4">
            <div className="text-xs font-black text-slate-500 uppercase tracking-widest">
              {selection.kind === 'node'
                ? t('libraryInspector.rightPane.nodeHeading', {
                    type: componentRegistry.get(selection.type)?.label ?? selection.type,
                    count: selectedTotal,
                  })
                : t('libraryInspector.rightPane.edgeHeading', { count: selectedTotal })}
            </div>

            {selectedTotal === 0 && (
              <p className="text-sm text-slate-500">{t('libraryInspector.rightPane.empty')}</p>
            )}

            {selection.kind === 'node' ? (
              <>
                {intrinsicGroups.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-xs font-black text-slate-500 uppercase tracking-widest">
                      {t('libraryInspector.section.intrinsic')} ({intrinsicGroups.length})
                    </div>
                    {intrinsicGroups.map((g) => (
                      <RuleCard
                        key={g.representative.canonicalId ?? g.representative.id}
                        rule={g.representative}
                        members={g.members}
                        getSource={getSource}
                        centerType={selection.type}
                      />
                    ))}
                  </div>
                )}
                {conditionalGroups.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-xs font-black text-slate-500 uppercase tracking-widest">
                      {t('libraryInspector.section.conditional')} ({conditionalGroups.length})
                    </div>
                    {conditionalGroups.map((g) => (
                      <RuleCard
                        key={g.representative.canonicalId ?? g.representative.id}
                        rule={g.representative}
                        members={g.members}
                        getSource={getSource}
                        centerType={selection.type}
                      />
                    ))}
                  </div>
                )}
              </>
            ) : (
              <div className="space-y-2">
                {edgeGroups.map((g) => (
                  <RuleCard
                    key={g.representative.canonicalId ?? g.representative.id}
                    rule={g.representative}
                    members={g.members}
                    getSource={getSource}
                  />
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
