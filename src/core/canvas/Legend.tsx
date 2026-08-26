import { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import {
  selectActiveBoundaries,
  selectActiveEdges,
  selectActiveNodes,
  useDiagramStore,
} from '../state/diagramStore';
import { componentRegistry } from '../../component-library/defaultRegistry';
import { renderIcon } from '../../component-library/iconRegistry';
import { BOUNDARY_TYPES } from '../constants/boundaryTypes';
import {
  presentBoundaryTypes,
  presentComponentTypes,
  presentEdgeNotations,
} from '../notation/legend';

/**
 * 凡例（Legend）。キャンバスで実際に使われているコンポーネント型・線記法・境界型だけを
 * 自動集計して表示する。「コンポーネント凡例 ＋ ネットワーク/データ凡例」に対応する。
 *
 * 記法の見た目は描画と同じスペック（`notation/edgeNotation`・`BOUNDARY_TYPES`）を参照し、
 * 図とズレない単一ソースを保つ。
 */
export function Legend() {
  const nodes = useDiagramStore(selectActiveNodes);
  const edges = useDiagramStore(selectActiveEdges);
  const boundaries = useDiagramStore(selectActiveBoundaries);
  const [collapsed, setCollapsed] = useState(false);

  // 描画前に「使われている記号」を集計。カテゴリ順→ラベル順でコンポーネントを安定整列する。
  const componentTypes = presentComponentTypes(nodes);
  const categoryOrder = new Map(componentRegistry.getCategories().map((c) => [c.id, c.order]));
  const components = componentTypes
    .map((type) => ({ type, def: componentRegistry.get(type) }))
    .sort((a, b) => {
      const ao = a.def ? (categoryOrder.get(a.def.category) ?? Number.MAX_SAFE_INTEGER) : Number.MAX_SAFE_INTEGER;
      const bo = b.def ? (categoryOrder.get(b.def.category) ?? Number.MAX_SAFE_INTEGER) : Number.MAX_SAFE_INTEGER;
      if (ao !== bo) return ao - bo;
      return (a.def?.label ?? a.type).localeCompare(b.def?.label ?? b.type, 'ja');
    });
  const edgeNotations = presentEdgeNotations(edges);
  const boundaryTypes = presentBoundaryTypes(boundaries);

  // 何も配置されていなければ凡例自体を出さない（空のパネルでキャンバスを汚さない）。
  if (components.length === 0 && edgeNotations.length === 0 && boundaryTypes.length === 0) {
    return null;
  }

  return (
    <div className="absolute bottom-6 left-6 z-10 w-56 bg-slate-900/90 backdrop-blur-xl rounded-2xl border border-slate-700 shadow-2xl text-slate-200">
      <button
        onClick={() => setCollapsed((v) => !v)}
        className="w-full flex items-center justify-between px-4 py-2.5 text-xs font-black uppercase tracking-widest text-slate-400 hover:text-slate-100 transition-colors"
        title={collapsed ? '凡例を開く' : '凡例を閉じる'}
      >
        凡例
        {collapsed ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
      </button>

      {!collapsed && (
        <div className="px-4 pb-3 space-y-3 max-h-[50vh] overflow-y-auto">
          {components.length > 0 && (
            <section className="space-y-1.5">
              <h4 className="text-[10px] font-black uppercase tracking-wider text-slate-500">
                コンポーネント
              </h4>
              {components.map(({ type, def }) => (
                <div key={type} className="flex items-center gap-2">
                  <span
                    className={`${def?.color ?? 'bg-slate-500'} p-1 rounded text-white flex items-center justify-center shrink-0`}
                  >
                    {renderIcon(def?.icon ?? { kind: 'builtin', name: 'box' }, { size: 12 })}
                  </span>
                  <span className="text-[11px] truncate" title={def?.label ?? type}>
                    {def?.label ?? type}
                  </span>
                </div>
              ))}
            </section>
          )}

          {edgeNotations.length > 0 && (
            <section className="space-y-1.5">
              <h4 className="text-[10px] font-black uppercase tracking-wider text-slate-500">
                データフロー
              </h4>
              {edgeNotations.map((entry) => (
                <div key={entry.id} className="flex items-center gap-2">
                  <svg width="28" height="10" className="shrink-0" aria-hidden>
                    <line
                      x1="1"
                      y1="5"
                      x2="27"
                      y2="5"
                      stroke={entry.swatch.stroke}
                      strokeWidth="2"
                      strokeDasharray={entry.swatch.dash}
                    />
                  </svg>
                  <span className="text-[11px] truncate" title={entry.label}>
                    {entry.label}
                  </span>
                </div>
              ))}
            </section>
          )}

          {boundaryTypes.length > 0 && (
            <section className="space-y-1.5">
              <h4 className="text-[10px] font-black uppercase tracking-wider text-slate-500">
                トラスト境界
              </h4>
              {boundaryTypes.map((type) => {
                const config = BOUNDARY_TYPES[type];
                return (
                  <div key={type} className="flex items-center gap-2">
                    <span
                      className={`w-6 h-4 shrink-0 border-2 border-slate-400 ${
                        config.isDashed ? 'border-dashed' : 'border-solid'
                      } ${config.rounded ? 'rounded-lg' : 'rounded-none'}`}
                    />
                    <span className="text-[11px] truncate" title={config.name}>
                      {config.name}
                    </span>
                  </div>
                );
              })}
            </section>
          )}
        </div>
      )}
    </div>
  );
}
