import { useEffect, useMemo, useState } from 'react';
import { BarChart3, ChevronDown, ChevronRight, X } from 'lucide-react';
import {
  selectActiveBoundaries,
  selectActiveEdges,
  selectActiveNodes,
  useDiagramStore,
} from '../../core/state/diagramStore';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import {
  DREAD_KEYS,
  dreadRank,
  dreadTotal,
  effectiveSeverity,
  type DreadKey,
} from '../../core/model/dread';
import {
  buildElementAnalytics,
  type ElementAnalyticsRow,
} from '../../features/analytics/buildElementAnalytics';
import {
  SEVERITY_BADGE_SUBTLE as SEVERITY_BADGE,
  SEVERITY_DOT,
} from '../../core/model/severityColors';
import { ControlStatusEditor } from './ControlStatusEditor';
import {
  CONTROL_STATUS_BADGE,
  CONTROL_STATUS_LABEL,
} from './controlStatusStyle';
import { RiskTreatmentEditor } from './RiskTreatmentEditor';
import { RISK_TREATMENT_BADGE, RISK_TREATMENT_LABEL } from './riskTreatmentStyle';
import type {
  ControlStatusValue,
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  DreadValue,
  Severity,
  ThreatView,
} from '../../core/model/types';

const SEVERITY_RANK: Record<Severity, number> = { Low: 1, Medium: 2, High: 3, Critical: 4 };

const KIND_LABEL: Record<ElementAnalyticsRow['kind'], string> = {
  node: 'Component',
  edge: 'Data Flow',
  boundary: 'Boundary',
};

/** DREAD 評価フォームの項目定義（表示ラベルと 1/2/3 の判断基準）。 */
const DREAD_CRITERIA: Record<DreadKey, { label: string; levels: [string, string, string] }> = {
  damage: {
    label: 'D: 損害（Damage）',
    levels: ['軽微な障害・限定的な情報露出', '一部データの漏えい・改ざん', '全データ侵害・システム全停止'],
  },
  reproducibility: {
    label: 'R: 再現性（Reproducibility）',
    levels: ['特定条件下でまれに成立', '条件が揃えば成立', '常に成立'],
  },
  exploitability: {
    label: 'E: 攻撃容易性（Exploitability）',
    levels: ['高度な技術・内部知識が必要', 'ツール・手順が一部公開', '既製ツールで容易に攻撃可能'],
  },
  affectedUsers: {
    label: 'A: 影響範囲（Affected Users）',
    levels: ['ごく一部のユーザー', '相当数のユーザー・テナント', '全ユーザー・管理者を含む'],
  },
  discoverability: {
    label: 'D: 発見容易性（Discoverability）',
    levels: ['内部知識がないと発見困難', '注意深い調査で発見可能', '外部から容易に発見可能'],
  },
};

const DREAD_LEVEL_LABEL = ['低', '中', '高'] as const;

/** 上部フィルタバーのプリセット種別（ローカル state のみ。保存機能はなし）。 */
type Preset = 'all' | 'highPlus' | 'withMit' | 'withoutMit';

const PRESET_LABEL: Record<Preset, string> = {
  all: '全件',
  highPlus: 'High 以上',
  withMit: '緩和策あり',
  withoutMit: '緩和策なし',
};

/** 対策ペインの実装状況グループ（未設定を含む。表示順は CONTROL_GROUP_ORDER）。 */
type ControlStatusGroup = ControlStatusValue | 'unset';

const CONTROL_GROUP_ORDER: ControlStatusGroup[] = [
  'required',
  'unset',
  'not-applicable',
  'rejected',
  'implemented',
];

const CONTROL_GROUP_LABEL: Record<ControlStatusGroup, string> = {
  unset: '未設定',
  required: CONTROL_STATUS_LABEL.required,
  implemented: CONTROL_STATUS_LABEL.implemented,
  'not-applicable': CONTROL_STATUS_LABEL['not-applicable'],
  rejected: CONTROL_STATUS_LABEL.rejected,
};

/** プリセット 1 件分の脅威マッチ判定。 */
function matchesPreset(t: ThreatView, preset: Preset): boolean {
  switch (preset) {
    case 'highPlus': {
      const sev = effectiveSeverity(t);
      return sev === 'High' || sev === 'Critical';
    }
    case 'withMit':
      return Boolean(t.mitigation);
    case 'withoutMit':
      return !t.mitigation;
    case 'all':
    default:
      return true;
  }
}

/**
 * Analytics モーダル（[[plan]] §2.26 Step 5）。IriusRisk 風の 3 ペイン構成。
 * 左: 要素→カテゴリ→脅威ツリー / 中央: 対策（緩和策）一覧 / 右: 選択脅威の詳細 + DREAD。
 * 脅威ビュー（`threats`）は App が算出済みのものを prop で受ける。
 */
export function AnalyticsModal({ threats }: { threats: ThreatView[] }) {
  const isOpen = useDiagramStore((s) => s.isAnalyticsOpen);
  const close = useDiagramStore((s) => s.closeAnalytics);
  const activeLayer = useDiagramStore((s) => s.activeLayer);
  const nodes = useDiagramStore(selectActiveNodes);
  const edges = useDiagramStore(selectActiveEdges);
  const boundaries = useDiagramStore(selectActiveBoundaries);
  const renumber = useDiagramStore((s) => s.renumberElementalIds);

  const [filter, setFilter] = useState('');
  const [preset, setPreset] = useState<Preset>('all');
  /** 選択中の脅威 id（左ツリー / 中央一覧 / 右詳細を連動させる）。 */
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null);
  /** ID 振り直しのインライン確認待ち（ブラウザダイアログを使わない方針）。 */
  const [confirmingRenumber, setConfirmingRenumber] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setFilter('');
      setPreset('all');
      setSelectedThreatId(null);
      setConfirmingRenumber(false);
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, close]);

  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.id, n] as const)), [nodes]);
  const edgeById = useMemo(() => new Map(edges.map((e) => [e.id, e] as const)), [edges]);
  const boundaryById = useMemo(
    () => new Map(boundaries.map((b) => [b.id, b] as const)),
    [boundaries],
  );

  const { rows, unassigned } = useMemo(
    () => buildElementAnalytics({ nodes, edges, boundaries, threats }),
    [nodes, edges, boundaries, threats],
  );

  const labelOf = (row: ElementAnalyticsRow): string => {
    if (row.kind === 'node') {
      const n = nodeById.get(row.id);
      return n ? getNodeDisplayName(n) : row.id;
    }
    if (row.kind === 'edge') {
      const e = edgeById.get(row.id);
      if (!e) return row.id;
      return edgeLabel(e, nodeById);
    }
    const b = boundaryById.get(row.id);
    return b ? boundaryLabel(b) : row.id;
  };

  // 検索文字列フィルタ（脅威 1 件単位）。要素ラベル・ElementalID は行側で付き合わせる。
  const q = filter.trim().toLowerCase();
  const matchesQuery = (t: ThreatView, elementLabel: string, elementalId = ''): boolean => {
    if (!q) return true;
    return (
      elementalId.toLowerCase().includes(q) ||
      elementLabel.toLowerCase().includes(q) ||
      t.category.toLowerCase().includes(q) ||
      (t.name?.toLowerCase().includes(q) ?? false) ||
      (t.description?.toLowerCase().includes(q) ?? false)
    );
  };

  // フィルタ（検索 AND プリセット）後の表示用ツリーを構築する。
  const tree = useMemo(() => {
    const out: {
      row: ElementAnalyticsRow;
      label: string;
      total: number;
      categories: { category: string; threats: ThreatView[] }[];
    }[] = [];
    for (const row of rows) {
      const label = labelOf(row);
      const kept = row.threats.filter(
        (t) => matchesPreset(t, preset) && matchesQuery(t, label, row.elementalId),
      );
      if (kept.length === 0) continue;
      // カテゴリ単位にまとめ、各カテゴリ内は実効 severity 降順。
      const byCat = new Map<string, ThreatView[]>();
      for (const t of kept) {
        const arr = byCat.get(t.category);
        if (arr) arr.push(t);
        else byCat.set(t.category, [t]);
      }
      const categories = [...byCat.entries()].map(([category, ts]) => ({
        category,
        threats: [...ts].sort(
          (a, b) => SEVERITY_RANK[effectiveSeverity(b)] - SEVERITY_RANK[effectiveSeverity(a)],
        ),
      }));
      out.push({ row, label, total: kept.length, categories });
    }
    return out;
    // labelOf / matchesQuery は rows/q/各 Map に依存。eslint 簡略化のため依存は実体で列挙。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, preset, q, nodeById, edgeById, boundaryById]);

  // 要素に紐づかない脅威（unassigned）も同じフィルタを通す。
  const visibleUnassigned = useMemo(
    () =>
      unassigned.filter(
        (t) => matchesPreset(t, preset) && matchesQuery(t, ''),
      ),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [unassigned, preset, q],
  );

  // 対策（中央ペイン）= フィルタ後の全脅威のうち mitigation を持つもの（出所ラベル付き）。
  const countermeasures = useMemo(() => {
    const list: { threat: ThreatView; elementLabel: string }[] = [];
    for (const t of tree) {
      for (const cat of t.categories) {
        for (const th of cat.threats) {
          if (th.mitigation) list.push({ threat: th, elementLabel: t.label });
        }
      }
    }
    for (const th of visibleUnassigned) {
      if (th.mitigation) list.push({ threat: th, elementLabel: '（要素に紐づかない脅威）' });
    }
    // 重大度降順で優先度の高い対策を上に。
    return list.sort(
      (a, b) =>
        SEVERITY_RANK[effectiveSeverity(b.threat)] - SEVERITY_RANK[effectiveSeverity(a.threat)],
    );
  }, [tree, visibleUnassigned]);

  // 対策を実装状況グループに振り分ける（未設定 → 必須 → 実装済み → 適用外 → 拒否）。
  const countermeasureGroups = useMemo(() => {
    const buckets: Record<ControlStatusGroup, { threat: ThreatView; elementLabel: string }[]> = {
      unset: [],
      required: [],
      implemented: [],
      'not-applicable': [],
      rejected: [],
    };
    for (const cm of countermeasures) {
      const g: ControlStatusGroup = cm.threat.controlStatus?.status ?? 'unset';
      buckets[g].push(cm);
    }
    return CONTROL_GROUP_ORDER.map((g) => ({ group: g, items: buckets[g] })).filter(
      (b) => b.items.length > 0,
    );
  }, [countermeasures]);

  // 選択中の脅威の実体を解決（id 一致）。どの要素（elementalID / ラベル）に
  // 属するかも併せて返し、右ペインで「今どの要素を編集中か」を明示する。
  const selectedThreat = useMemo(() => {
    if (!selectedThreatId) return null;
    for (const t of tree) {
      for (const cat of t.categories) {
        const hit = cat.threats.find((th) => th.id === selectedThreatId);
        if (hit) return { threat: hit, elementalId: t.row.elementalId, elementLabel: t.label };
      }
    }
    const u = visibleUnassigned.find((th) => th.id === selectedThreatId);
    return u ? { threat: u, elementalId: null, elementLabel: '要素に紐づかない脅威' } : null;
  }, [selectedThreatId, tree, visibleUnassigned]);

  if (!isOpen) return null;

  const totalThreats = rows.reduce((acc, r) => acc + r.threats.length, 0) + unassigned.length;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-150"
      onMouseDown={close}
    >
      <div
        className="w-[1320px] max-w-[96vw] h-[80vh] bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl flex flex-col overflow-hidden"
        onMouseDown={(e) => e.stopPropagation()}
      >
        {/* ヘッダ */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <BarChart3 size={16} className="text-emerald-400" />
            <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">
              Analytics
            </h2>
            <span className="text-[10px] text-slate-500 ml-2">
              レイヤー {activeLayer} / {rows.length} 要素 / 脅威 {totalThreats} 件
            </span>
          </div>
          <div className="flex items-center gap-3">
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="ElementalID / 名称 / カテゴリ"
              className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors w-[240px]"
            />
            <button
              onClick={() => setConfirmingRenumber(true)}
              disabled={confirmingRenumber}
              className="text-[11px] px-3 py-1.5 rounded-lg border border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500 transition-colors disabled:opacity-40 shrink-0"
              title="削除で生じた欠番を詰め、全レイヤーの ElementalID を 1 から振り直します"
            >
              ID を振り直す
            </button>
            <button
              onClick={close}
              className="text-slate-500 hover:text-slate-200 transition-colors"
              aria-label="閉じる"
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {confirmingRenumber && (
          <div className="flex items-center gap-3 px-6 py-3 bg-amber-500/10 border-b border-amber-500/30">
            <p className="text-[11px] text-amber-200 flex-1">
              全レイヤーの ElementalID（C / DF / Z）を 1
              から振り直します。過去のレポート等で参照した ID
              は別の要素を指す可能性があり、Undo 履歴もクリアされます。
            </p>
            <button
              onClick={() => {
                renumber();
                setConfirmingRenumber(false);
              }}
              className="text-[11px] px-3 py-1.5 rounded-lg bg-amber-500/20 border border-amber-500/40 text-amber-200 hover:bg-amber-500/30 transition-colors shrink-0"
            >
              振り直しを実行
            </button>
            <button
              onClick={() => setConfirmingRenumber(false)}
              className="text-[11px] px-3 py-1.5 rounded-lg border border-slate-700 text-slate-400 hover:text-slate-200 transition-colors shrink-0"
            >
              キャンセル
            </button>
          </div>
        )}

        {/* ① 上部フィルタバー（プリセットチップ） */}
        <div className="flex items-center gap-2 px-6 py-2.5 border-b border-slate-800 bg-slate-900/60">
          <span className="text-[10px] uppercase tracking-widest text-slate-500 mr-1">
            フィルタ
          </span>
          {(['all', 'highPlus', 'withMit', 'withoutMit'] as const).map((p) => (
            <button
              key={p}
              onClick={() => setPreset(p)}
              className={`text-[10px] px-2.5 py-1 rounded-full border transition-colors ${
                preset === p
                  ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-200'
                  : 'border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500'
              }`}
            >
              {PRESET_LABEL[p]}
            </button>
          ))}
        </div>

        {/* 3 ペイン本体 */}
        <div className="flex-1 flex min-h-0">
          {/* ② 左ペイン: 脅威ツリー */}
          <div className="w-[34%] min-w-0 border-r border-slate-800 overflow-y-auto px-3 py-3">
            {tree.length === 0 && visibleUnassigned.length === 0 ? (
              <p className="text-xs text-slate-500 px-2">該当する脅威はありません。</p>
            ) : (
              <ul className="flex flex-col gap-1.5">
                {tree.map((t) => (
                  <ElementTreeNode
                    key={`${t.row.kind}:${t.row.id}`}
                    row={t.row}
                    label={t.label}
                    total={t.total}
                    categories={t.categories}
                    selectedThreatId={selectedThreatId}
                    onSelect={setSelectedThreatId}
                  />
                ))}
                {visibleUnassigned.length > 0 && (
                  <UnassignedTreeNode
                    threats={visibleUnassigned}
                    selectedThreatId={selectedThreatId}
                    onSelect={setSelectedThreatId}
                  />
                )}
              </ul>
            )}
          </div>

          {/* ③ 中央ペイン: 対策一覧 */}
          <div className="w-[33%] min-w-0 border-r border-slate-800 overflow-y-auto px-3 py-3">
            <h3 className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2 px-1">
              対策 {countermeasures.length} 件
            </h3>
            {countermeasures.length === 0 ? (
              <p className="text-xs text-slate-500 px-1">緩和策のある脅威はありません。</p>
            ) : (
              <div className="flex flex-col gap-3">
                {countermeasureGroups.map(({ group, items }) => (
                  <div key={group}>
                    <div className="flex items-center gap-2 mb-1 px-1">
                      {group === 'unset' ? (
                        <span className="text-[10px] font-bold text-slate-500">
                          {CONTROL_GROUP_LABEL[group]}
                        </span>
                      ) : (
                        <span
                          className={`text-[9px] px-2 py-0.5 rounded border ${CONTROL_STATUS_BADGE[group]}`}
                        >
                          {CONTROL_GROUP_LABEL[group]}
                        </span>
                      )}
                      <span className="text-[9px] text-slate-600">{items.length}</span>
                    </div>
                    <ul className="flex flex-col gap-1">
                      {items.map(({ threat, elementLabel }) => {
                        const sev = effectiveSeverity(threat);
                        const active = threat.id === selectedThreatId;
                        return (
                          <li key={threat.id}>
                            <button
                              onClick={() => setSelectedThreatId(threat.id)}
                              className={`w-full text-left px-2 py-1.5 rounded-lg border transition-colors flex items-start gap-2 ${
                                active
                                  ? 'bg-emerald-500/10 border-emerald-500/40'
                                  : 'border-transparent hover:bg-slate-800/60 hover:border-slate-800'
                              }`}
                              title={`${sev} ・ ${elementLabel}`}
                            >
                              <span
                                className={`mt-1 h-2 w-2 rounded-full shrink-0 ${SEVERITY_DOT[sev]}`}
                                aria-hidden
                              />
                              <span className="min-w-0 flex-1">
                                <span className="block text-[9px] text-slate-500 truncate">
                                  {elementLabel}
                                </span>
                                <span className="block text-[11px] text-slate-300 leading-snug line-clamp-2">
                                  {threat.mitigation}
                                </span>
                              </span>
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* ④ 右ペイン: 詳細 + DREAD */}
          <div className="flex-1 min-w-0 overflow-y-auto px-4 py-4">
            {selectedThreat ? (
              <ThreatDetail
                key={selectedThreat.threat.id}
                threat={selectedThreat.threat}
                elementalId={selectedThreat.elementalId}
                elementLabel={selectedThreat.elementLabel}
              />
            ) : (
              <div className="h-full flex items-center justify-center">
                <p className="text-xs text-slate-600">脅威を選択してください。</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

/** 左ペインの要素ノード（要素→カテゴリ→脅威の 3 階層、折りたたみ）。 */
function ElementTreeNode({
  row,
  label,
  total,
  categories,
  selectedThreatId,
  onSelect,
}: {
  row: ElementAnalyticsRow;
  label: string;
  total: number;
  categories: { category: string; threats: ThreatView[] }[];
  selectedThreatId: string | null;
  onSelect: (id: string) => void;
}) {
  const [open, setOpen] = useState(true);
  return (
    <li className="rounded-lg bg-slate-800/40 border border-slate-800">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-2 px-2 py-2 text-left"
      >
        {open ? (
          <ChevronDown size={12} className="text-slate-500 shrink-0" />
        ) : (
          <ChevronRight size={12} className="text-slate-500 shrink-0" />
        )}
        <span className="text-[11px] font-mono font-bold text-emerald-400 shrink-0">
          {row.elementalId}
        </span>
        <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-700/50 text-slate-400 border border-slate-700 shrink-0">
          {KIND_LABEL[row.kind]}
        </span>
        <span className="text-xs font-bold text-slate-100 flex-1 truncate">{label}</span>
        {row.maxSeverity && (
          <span
            className={`text-[9px] px-1.5 py-0.5 rounded border shrink-0 ${SEVERITY_BADGE[row.maxSeverity]}`}
            title="この要素の最大リスク"
          >
            {row.maxSeverity}
          </span>
        )}
        <span className="text-[9px] text-slate-500 shrink-0">{total}</span>
      </button>
      {open && (
        <ul className="pb-1.5 pl-3 flex flex-col gap-1">
          {categories.map((cat) => (
            <CategoryTreeNode
              key={cat.category}
              category={cat.category}
              threats={cat.threats}
              selectedThreatId={selectedThreatId}
              onSelect={onSelect}
            />
          ))}
        </ul>
      )}
    </li>
  );
}

/** 左ペインのカテゴリノード（折りたたみ + 脅威の葉）。 */
function CategoryTreeNode({
  category,
  threats,
  selectedThreatId,
  onSelect,
}: {
  category: string;
  threats: ThreatView[];
  selectedThreatId: string | null;
  onSelect: (id: string) => void;
}) {
  const [open, setOpen] = useState(true);
  return (
    <li className="pl-1">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-1.5 px-1 py-1 text-left"
      >
        {open ? (
          <ChevronDown size={11} className="text-slate-600 shrink-0" />
        ) : (
          <ChevronRight size={11} className="text-slate-600 shrink-0" />
        )}
        <span className="text-[10px] font-semibold text-slate-400 flex-1 truncate">
          {category}
        </span>
        <span className="text-[9px] text-slate-600 shrink-0">{threats.length}</span>
      </button>
      {open && (
        <ul className="pl-4 flex flex-col gap-0.5">
          {threats.map((t) => {
            const sev = effectiveSeverity(t);
            const active = t.id === selectedThreatId;
            return (
              <li key={t.id}>
                <button
                  onClick={() => onSelect(t.id)}
                  className={`w-full text-left px-2 py-1 rounded border transition-colors flex items-center gap-2 ${
                    active
                      ? 'bg-emerald-500/10 border-emerald-500/40'
                      : 'border-transparent hover:bg-slate-800/60'
                  }`}
                >
                  <span
                    className={`h-1.5 w-1.5 rounded-full shrink-0 ${SEVERITY_DOT[sev]}`}
                    aria-hidden
                  />
                  <span className="text-[10px] text-slate-300 flex-1 truncate">
                    {t.name ?? t.category}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </li>
  );
}

/** 左ペイン末尾の「要素に紐づかない脅威」ノード（カテゴリ階層を 1 段省略）。 */
function UnassignedTreeNode({
  threats,
  selectedThreatId,
  onSelect,
}: {
  threats: ThreatView[];
  selectedThreatId: string | null;
  onSelect: (id: string) => void;
}) {
  const [open, setOpen] = useState(true);
  return (
    <li className="rounded-lg bg-slate-800/40 border border-slate-800">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-2 px-2 py-2 text-left"
      >
        {open ? (
          <ChevronDown size={12} className="text-slate-500 shrink-0" />
        ) : (
          <ChevronRight size={12} className="text-slate-500 shrink-0" />
        )}
        <span className="text-[10px] font-semibold text-slate-400 flex-1 truncate">
          要素に紐づかない脅威
        </span>
        <span className="text-[9px] text-slate-600 shrink-0">{threats.length}</span>
      </button>
      {open && (
        <ul className="pb-1.5 pl-7 pr-2 flex flex-col gap-0.5">
          {threats.map((t) => {
            const sev = effectiveSeverity(t);
            const active = t.id === selectedThreatId;
            return (
              <li key={t.id}>
                <button
                  onClick={() => onSelect(t.id)}
                  className={`w-full text-left px-2 py-1 rounded border transition-colors flex items-center gap-2 ${
                    active
                      ? 'bg-emerald-500/10 border-emerald-500/40'
                      : 'border-transparent hover:bg-slate-800/60'
                  }`}
                >
                  <span
                    className={`h-1.5 w-1.5 rounded-full shrink-0 ${SEVERITY_DOT[sev]}`}
                    aria-hidden
                  />
                  <span className="text-[10px] text-slate-300 flex-1 truncate">
                    {t.name ?? t.category}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </li>
  );
}

/** 右ペインの脅威詳細（対象要素 + バッジ群 + 説明 + 緩和策 + DREAD 評価）。 */
function ThreatDetail({
  threat,
  elementalId,
  elementLabel,
}: {
  threat: ThreatView;
  /** 対象要素の ElementalID（要素に紐づかない脅威では null）。 */
  elementalId: string | null;
  elementLabel: string;
}) {
  const sev = effectiveSeverity(threat);
  return (
    <div className="flex flex-col gap-3">
      {/* 対象要素（DREAD は要素インスタンス単位で保存されるため、ここで対象を明示する）。 */}
      <div className="flex items-center gap-2 min-w-0">
        {elementalId && (
          <span className="text-[11px] font-mono font-bold text-emerald-400 shrink-0">
            {elementalId}
          </span>
        )}
        <span className="text-[10px] text-slate-400 truncate" title={elementLabel}>
          {elementLabel}
        </span>
      </div>
      <div>
        <h3 className="text-sm font-bold text-slate-100">{threat.name ?? threat.category}</h3>
        <p className="text-[10px] text-slate-500 mt-0.5">{threat.category}</p>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <span className={`text-[10px] px-2 py-0.5 rounded border ${SEVERITY_BADGE[sev]}`}>
          {sev}
        </span>
        {threat.dread && (
          <span
            className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/40"
            title={`DREAD 評価済み（元の severity: ${threat.severity}）`}
          >
            DREAD {dreadTotal(threat.dread)}
          </span>
        )}
        {threat.origin === 'manual' && (
          <span className="text-[10px] px-2 py-0.5 rounded bg-violet-500/15 text-violet-300 border border-violet-500/40">
            Manual
          </span>
        )}
        {threat.suppression && (
          <span
            className={`text-[10px] px-2 py-0.5 rounded border ${RISK_TREATMENT_BADGE[threat.suppression.status]}`}
          >
            {RISK_TREATMENT_LABEL[threat.suppression.status]}
          </span>
        )}
        {threat.controlStatus && (
          <span
            className={`text-[10px] px-2 py-0.5 rounded border ${CONTROL_STATUS_BADGE[threat.controlStatus.status]}`}
          >
            {CONTROL_STATUS_LABEL[threat.controlStatus.status]}
          </span>
        )}
      </div>

      {threat.description && (
        <p className="text-[11px] leading-relaxed text-slate-400">{threat.description}</p>
      )}

      {threat.mitigation && (
        <div className="text-[11px] leading-relaxed">
          <p className="text-slate-300 font-bold mb-1">緩和策</p>
          <p className="text-slate-400">{threat.mitigation}</p>
        </div>
      )}

      <div className="pt-2 border-t border-slate-800">
        <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">
          DREAD 評価
        </p>
        <DreadEditor threat={threat} />
      </div>

      {threat.origin !== 'manual' && (
        <div className="pt-2 border-t border-slate-800">
          <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">
            リスク対応方針
          </p>
          <RiskTreatmentEditor key={threat.id} threat={threat} />
        </div>
      )}

      <div className="pt-2 border-t border-slate-800">
        <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">
          対策実装状況
        </p>
        <ControlStatusEditor key={threat.id} threat={threat} />
      </div>
    </div>
  );
}

/**
 * DREAD 評価フォーム（[[plan]] §2.34）。ローカルドラフトを編集し「保存」で
 * store へ明示コミットする（項目選択ごとの自動保存はしない＝Undo 1 ステップ化）。
 * 右ペインに常時配置するため、脅威切替で draft を作り直すよう key を threat.id に紐づける。
 */
function DreadEditor({ threat }: { threat: ThreatView }) {
  const setDreadScore = useDiagramStore((s) => s.setDreadScore);
  const clearDreadScore = useDiagramStore((s) => s.clearDreadScore);
  const [draft, setDraft] = useState<Record<DreadKey, DreadValue>>(() =>
    threat.dread
      ? {
          damage: threat.dread.damage,
          reproducibility: threat.dread.reproducibility,
          exploitability: threat.dread.exploitability,
          affectedUsers: threat.dread.affectedUsers,
          discoverability: threat.dread.discoverability,
        }
      : {
          damage: 2,
          reproducibility: 2,
          exploitability: 2,
          affectedUsers: 2,
          discoverability: 2,
        },
  );

  const total = DREAD_KEYS.reduce((acc, k) => acc + draft[k], 0);
  const rank = dreadRank(total);

  return (
    <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-700 flex flex-col gap-2">
      {DREAD_KEYS.map((key) => {
        const c = DREAD_CRITERIA[key];
        return (
          <div key={key} className="flex items-center gap-2">
            <span className="text-[10px] text-slate-400 w-56 shrink-0">{c.label}</span>
            <div className="flex gap-1">
              {([1, 2, 3] as const).map((v) => (
                <button
                  key={v}
                  onClick={() => setDraft((d) => ({ ...d, [key]: v }))}
                  title={c.levels[v - 1]}
                  className={`text-[10px] px-2.5 py-1 rounded border transition-colors ${
                    draft[key] === v
                      ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-200'
                      : 'border-slate-700 text-slate-500 hover:text-slate-300 hover:border-slate-500'
                  }`}
                >
                  {v} {DREAD_LEVEL_LABEL[v - 1]}
                </button>
              ))}
            </div>
            <span className="text-[9px] text-slate-600 flex-1 truncate">
              {c.levels[draft[key] - 1]}
            </span>
          </div>
        );
      })}
      <div className="flex items-center gap-3 pt-1 border-t border-slate-800">
        <span className="text-[10px] text-slate-400">
          合計 <span className="font-bold text-slate-200">{total}</span> / 15 →
        </span>
        <span className={`text-[10px] px-2 py-0.5 rounded border ${SEVERITY_BADGE[rank]}`}>
          {rank}
        </span>
        <span className="text-[9px] text-slate-600">（ルール由来: {threat.severity}）</span>
        <div className="flex gap-2 ml-auto">
          {threat.dread && (
            <button
              onClick={() => clearDreadScore(threat.id)}
              className="text-[10px] px-2.5 py-1 rounded border border-slate-700 text-slate-500 hover:text-red-300 hover:border-red-500/50 transition-colors"
            >
              評価をクリア
            </button>
          )}
          <button
            onClick={() => setDreadScore(threat.id, draft)}
            className="text-[10px] px-2.5 py-1 rounded bg-emerald-500/20 border border-emerald-500/40 text-emerald-200 hover:bg-emerald-500/30 transition-colors"
          >
            保存
          </button>
        </div>
      </div>
    </div>
  );
}

function edgeLabel(edge: DiagramEdge, nodeById: Map<string, DiagramNode>): string {
  const name = (id: string) => {
    const n = nodeById.get(id);
    return n ? getNodeDisplayName(n) : id;
  };
  const base = `${name(edge.source)} → ${name(edge.target)}`;
  return edge.dataFlowName ? `${base}（${edge.dataFlowName}）` : base;
}

function boundaryLabel(b: DiagramBoundary): string {
  return b.vlanName || b.microTrust || b.macroTrust || `${b.trustLevel} 境界`;
}
