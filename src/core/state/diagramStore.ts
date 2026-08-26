import { create } from 'zustand';
import type {
  BoundaryTypeId,
  ComponentTypeId,
  ControlStatusState,
  ControlStatusValue,
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  DragState,
  DreadScore,
  ElementKind,
  FrameworkView,
  GroupDragState,
  LayerData,
  LayerKey,
  LayerSeqCounters,
  ManualThreat,
  MarqueeState,
  ProjectMeta,
  PanState,
  ResizeHandle,
  ResizeState,
  SeqCounters,
  SuppressionState,
  SuppressionStatus,
  Viewport,
} from '../model/types';
import { EMPTY_LAYER, EMPTY_PROJECT_META } from '../model/types';
import { getNodeDimensions } from '../canvas/nodeGeometry';
import { IDENTITY_VIEWPORT, ZOOM_STEP, computeFit, zoomAtPoint } from '../canvas/viewport';

/** 全レイヤー空の手動脅威 Record を新規生成する（初期化 / hydrate 用）。 */
const emptyManualThreats = (): Record<LayerKey, ManualThreat[]> => ({
  L0: [],
  L1: [],
  L2: [],
  L3: [],
});

const MIN_BOUNDARY_W = 80;
const MIN_BOUNDARY_H = 60;

/** Undo/Redo 履歴の上限段数。 */
const MAX_HISTORY = 50;

/**
 * Undo/Redo のスナップショット。ドキュメント編集対象のみを持つ。
 * 全 mutation が immutable なため、ここは古い state への参照保持で安全（[[plan]] §2.24-C）。
 */
interface HistorySnapshot {
  layers: Record<LayerKey, LayerData>;
  manualThreats: Record<LayerKey, ManualThreat[]>;
  suppressions: Record<string, SuppressionState>;
  dreadScores: Record<string, DreadScore>;
  controlStatuses: Record<string, ControlStatusState>;
}

const snapshotOf = (s: DiagramState): HistorySnapshot => ({
  layers: s.layers,
  manualThreats: s.manualThreats,
  suppressions: s.suppressions,
  dreadScores: s.dreadScores,
  controlStatuses: s.controlStatuses,
});

/**
 * L1 にだけ初期サンプルを置く（[[plan]] §2 ステップ 18 で確定）。
 * L0 = ビジネスサイドが空から記載、L1 = セキュリティ担当者のデフォルト出発点。
 */
const INITIAL_L1: LayerData = {
  nodes: [
    { id: 'n1', seq: 1, type: 'USER', x: 50, y: 250 },
    { id: 'n2', seq: 2, type: 'GATEWAY', x: 250, y: 250 },
    { id: 'n3', seq: 3, type: 'LLM', x: 450, y: 250 },
    { id: 'n4', seq: 4, type: 'DB', x: 650, y: 250 },
  ],
  edges: [
    {
      id: 'e1',
      seq: 1,
      source: 'n1',
      target: 'n2',
      auth: 'None',
      network: 'Internet',
      encryption: 'Plain',
      dataFlow: 'outbound',
    },
    {
      id: 'e2',
      seq: 2,
      source: 'n2',
      target: 'n3',
      auth: 'Password',
      network: 'VPC',
      encryption: 'TLS',
      dataFlow: 'outbound',
    },
    {
      id: 'e3',
      seq: 3,
      source: 'n3',
      target: 'n4',
      auth: 'Password',
      network: 'VPC',
      encryption: 'TLS',
      dataFlow: 'outbound',
    },
  ],
  boundaries: [
    {
      id: 'b1',
      seq: 1,
      type: 'ROUNDED_DASHED',
      x: 200,
      y: 150,
      width: 600,
      height: 250,
      trustLevel: 'Internal',
    },
  ],
};

export const INITIAL_LAYERS: Record<LayerKey, LayerData> = {
  L0: EMPTY_LAYER,
  L1: INITIAL_L1,
  L2: EMPTY_LAYER,
  L3: EMPTY_LAYER,
};

export const DEFAULT_ACTIVE_LAYER: LayerKey = 'L1';

/**
 * ElementalID 採番カウンタ（[[plan]] §2.26）。レイヤー × 種別ごとに**単調増加**で、
 * 削除しても巻き戻さない（番号を再利用しない＝レポート参照の永続安定性）。値は
 * 「直近に割り当てた seq」。次に割り当てる seq は `value + 1`。
 */
const emptyCounters = (): SeqCounters => ({ node: 0, edge: 0, boundary: 0 });

/** 全レイヤー 0 始まりの採番カウンタを生成する。 */
const emptyIdCounters = (): LayerSeqCounters => ({
  L0: emptyCounters(),
  L1: emptyCounters(),
  L2: emptyCounters(),
  L3: emptyCounters(),
});

/** INITIAL_L1 のサンプル要素に割り当て済みの seq に合わせた初期カウンタ。 */
const INITIAL_ID_COUNTERS: LayerSeqCounters = {
  ...emptyIdCounters(),
  L1: { node: 4, edge: 3, boundary: 1 },
};

/** カウンタの (layer, kind) を value に更新した新しい Record を返す。 */
function bumpCounter(
  counters: LayerSeqCounters,
  layer: LayerKey,
  kind: ElementKind,
  value: number,
): LayerSeqCounters {
  return { ...counters, [layer]: { ...counters[layer], [kind]: value } };
}

/**
 * 種別内の要素へ現 seq 順（未設定は末尾、同点は配列順）で 1..n を振り直す。
 * 配列の並び（境界の描画順等）は変えず、seq のみ更新する。
 */
function renumberKind<T extends { seq?: number }>(items: T[]): T[] {
  const order = items
    .map((item, idx) => ({ idx, seq: item.seq }))
    .sort((a, b) => (a.seq ?? Infinity) - (b.seq ?? Infinity) || a.idx - b.idx);
  const seqByIdx = new Map<number, number>();
  order.forEach((o, i) => seqByIdx.set(o.idx, i + 1));
  return items.map((item, idx) => ({ ...item, seq: seqByIdx.get(idx) as number }));
}

/**
 * 内部要素 ID（不変キー）の生成。`Date.now()` 単独は同一ミリ秒内で衝突し得たため、
 * セッション内単調増加カウンタを併用して衝突を排除する（[[plan]] §2.26）。
 * セッション間は `Date.now()` 部が異なるため過去 ID とも衝突しない。
 */
let idSeq = 0;
const nextId = (prefix: string): string =>
  `${prefix}${Date.now().toString(36)}${(idSeq++).toString(36)}`;

function applyResize(
  start: { x: number; y: number; width: number; height: number },
  handle: ResizeHandle,
  dx: number,
  dy: number,
): { x: number; y: number; width: number; height: number } {
  let { x, y, width, height } = start;
  if (handle.includes('e')) width = start.width + dx;
  if (handle.includes('w')) {
    width = start.width - dx;
    x = start.x + dx;
  }
  if (handle.includes('s')) height = start.height + dy;
  if (handle.includes('n')) {
    height = start.height - dy;
    y = start.y + dy;
  }
  // 最小サイズ未満になる場合は、対応する辺で打ち止め（x/y を巻き戻す）。
  if (width < MIN_BOUNDARY_W) {
    if (handle.includes('w')) x = start.x + start.width - MIN_BOUNDARY_W;
    width = MIN_BOUNDARY_W;
  }
  if (height < MIN_BOUNDARY_H) {
    if (handle.includes('n')) y = start.y + start.height - MIN_BOUNDARY_H;
    height = MIN_BOUNDARY_H;
  }
  return { x, y, width, height };
}

export type ReorderAction = 'front' | 'back' | 'forward' | 'backward';

/**
 * 現在の activeLayer のデータに transformer を適用し、layers Record の更新部分を返す。
 * 各 CRUD アクションの共通ヘルパー。
 */
function withActiveLayer(
  s: { layers: Record<LayerKey, LayerData>; activeLayer: LayerKey },
  fn: (l: LayerData) => Partial<LayerData>,
): { layers: Record<LayerKey, LayerData> } {
  const current = s.layers[s.activeLayer];
  const next = { ...current, ...fn(current) };
  return { layers: { ...s.layers, [s.activeLayer]: next } };
}

// ── selectors（consumer から `useDiagramStore(selectActiveNodes)` 等で利用） ──
export const selectActiveNodes = (s: DiagramState): DiagramNode[] =>
  s.layers[s.activeLayer].nodes;
export const selectActiveEdges = (s: DiagramState): DiagramEdge[] =>
  s.layers[s.activeLayer].edges;
export const selectActiveBoundaries = (s: DiagramState): DiagramBoundary[] =>
  s.layers[s.activeLayer].boundaries;
export const selectActiveManualThreats = (s: DiagramState): ManualThreat[] =>
  s.manualThreats[s.activeLayer];
export const selectCanUndo = (s: DiagramState): boolean => s.past.length > 0;
export const selectCanRedo = (s: DiagramState): boolean => s.future.length > 0;

/**
 * パネル表示用の主選択ノード。ノードちょうど 1 個 / 境界 0 個のときのみその ID。
 * （複数選択 / ノード境界の混在時は RightSidebar が ThreatListPanel に戻る）
 */
export const selectPrimaryNodeId = (s: DiagramState): string | null =>
  s.selectedNodeIds.length === 1 && s.selectedBoundaryIds.length === 0
    ? s.selectedNodeIds[0]
    : null;

/**
 * パネル表示用の主選択境界。境界ちょうど 1 個 / ノード 0 個のときのみその ID。
 */
export const selectPrimaryBoundaryId = (s: DiagramState): string | null =>
  s.selectedBoundaryIds.length === 1 && s.selectedNodeIds.length === 0
    ? s.selectedBoundaryIds[0]
    : null;

/**
 * マーキー矩形に**完全内包**されるトップレベルノード / 境界の ID 群を返す。
 * 子ノード（バッジ表示 = 親不在でない parentId を持つ）は親と一緒に動くため対象外。
 */
function elementsInMarquee(
  nodes: DiagramNode[],
  boundaries: DiagramBoundary[],
  m: MarqueeState,
): { nodeIds: string[]; boundaryIds: string[] } {
  const minX = Math.min(m.startX, m.curX);
  const maxX = Math.max(m.startX, m.curX);
  const minY = Math.min(m.startY, m.curY);
  const maxY = Math.max(m.startY, m.curY);
  // 完全内包判定：矩形が対象の全 4 辺を覆う。
  const encloses = (x: number, y: number, w: number, h: number): boolean =>
    minX <= x && maxX >= x + w && minY <= y && maxY >= y + h;

  const ids = new Set(nodes.map((n) => n.id));
  const nodeIds: string[] = [];
  for (const n of nodes) {
    if (n.parentId && ids.has(n.parentId)) continue; // 子ノードは除外
    const { w, h } = getNodeDimensions(n);
    if (encloses(n.x, n.y, w, h)) nodeIds.push(n.id);
  }

  const boundaryIds: string[] = [];
  for (const b of boundaries) {
    if (encloses(b.x, b.y, b.width, b.height)) boundaryIds.push(b.id);
  }

  return { nodeIds, boundaryIds };
}

/**
 * 現在の選択集合（ノード + 境界）から、開始 client 座標を基準にした
 * グループ移動 transient 状態を生成する。
 */
function buildGroupDrag(s: DiagramState, clientX: number, clientY: number): GroupDragState {
  const layer = s.layers[s.activeLayer];
  const selNodes = new Set(s.selectedNodeIds);
  const selBoundaries = new Set(s.selectedBoundaryIds);
  return {
    startClientX: clientX,
    startClientY: clientY,
    nodeOrigins: layer.nodes
      .filter((n) => selNodes.has(n.id))
      .map((n) => ({ id: n.id, x: n.x, y: n.y })),
    boundaryOrigins: layer.boundaries
      .filter((b) => selBoundaries.has(b.id))
      .map((b) => ({ id: b.id, x: b.x, y: b.y })),
  };
}

export interface HydratePayload {
  layers: Record<LayerKey, LayerData>;
  activeLayer: LayerKey;
  activeFramework: FrameworkView;
  disabledLibraryIds?: string[];
  projectMeta?: ProjectMeta;
  manualThreats?: Record<LayerKey, ManualThreat[]>;
  suppressions?: Record<string, SuppressionState>;
  /** DREAD 評価（threatId キー。[[plan]] §2.34）。省略時は評価なし。 */
  dreadScores?: Record<string, DreadScore>;
  /** 対策実装状況（threatId キー）。省略時は未設定。 */
  controlStatuses?: Record<string, ControlStatusState>;
  /** ElementalID 採番カウンタ（[[plan]] §2.26）。省略時は全レイヤー 0 始まり。 */
  idCounters?: LayerSeqCounters;
}

interface DiagramState {
  // ---- diagram data (深度レイヤー) ----
  /** L0/L1/L2/L3 の独立した 4 枚のキャンバス。レイヤー間に相関関係なし。 */
  layers: Record<LayerKey, LayerData>;
  /** 現在編集対象のレイヤー。 */
  activeLayer: LayerKey;
  /**
   * ElementalID 採番カウンタ（レイヤー × 種別、単調増加）。[[plan]] §2.26。
   * 採番のみに使い、Undo/Redo では巻き戻さない（番号再利用を避けるため履歴対象外）。
   */
  idCounters: LayerSeqCounters;

  // ---- mode ----
  activeFramework: FrameworkView;
  isFocusMode: boolean;

  // ---- persistence ----
  /** IndexedDB からの初期復元が完了したか。完了まで auto-save は走らない。 */
  isHydrated: boolean;

  // ---- component library ----
  /** 無効化中のコンポーネントライブラリ ID（builtin は無効化不可）。 */
  disabledLibraryIds: Set<string>;

  // ---- project metadata ----
  /** プロジェクト概要（Project Edit 画面で編集）。 */
  projectMeta: ProjectMeta;
  /** Project Edit モーダルの開閉状態（UI 表示用、永続化しない）。 */
  isProjectEditOpen: boolean;
  /** コンプライアンスマップ閲覧モーダルの開閉状態（UI 表示用、永続化しない）。 */
  isComplianceMapOpen: boolean;
  /** Analytics（ElementalID 単位リスト）モーダルの開閉状態（UI 表示用、永続化しない）。 */
  isAnalyticsOpen: boolean;
  /** 脅威ライブラリ・インスペクタ（読み取り専用）モーダルの開閉状態（UI 表示用、永続化しない）。 */
  isLibraryInspectorOpen: boolean;
  /** Template（Import / Export）モーダルの開閉状態（UI 表示用、永続化しない）。 */
  isTemplateModalOpen: boolean;
  /** プロジェクトのファイル保存/読込モーダルの開閉状態（UI 表示用、永続化しない）。 */
  isProjectFileModalOpen: boolean;
  /** 新規プロジェクト作成の確認モーダルの開閉状態（UI 表示用、永続化しない）。 */
  isNewProjectConfirmOpen: boolean;

  // ---- manual threats / suppressions ----
  /** 手動脅威シナリオ（レイヤー別、プロジェクト固有データ）。 */
  manualThreats: Record<LayerKey, ManualThreat[]>;
  /** 検出脅威の抑制注記（threatId キー、グローバル）。 */
  suppressions: Record<string, SuppressionState>;
  /** 脅威への DREAD 評価（threatId キー、グローバル。[[plan]] §2.34）。 */
  dreadScores: Record<string, DreadScore>;
  /** 検出/手動脅威への対策実装状況（threatId キー、グローバル）。suppression とは別レイヤー。 */
  controlStatuses: Record<string, ControlStatusState>;
  /** 手動脅威エディタモーダルの開閉状態（UI 表示用、永続化しない）。 */
  isManualThreatModalOpen: boolean;
  /** 編集中の手動脅威 id。null = 新規追加モード。 */
  editingManualThreatId: string | null;

  // ---- selection ----
  /** 選択中ノード（複数）。パネル表示は selectPrimaryNodeId 経由で 1 個時のみ。 */
  selectedNodeIds: string[];
  selectedEdgeId: string | null;
  /** 選択中境界（複数）。パネル表示は selectPrimaryBoundaryId 経由で 1 個時のみ。 */
  selectedBoundaryIds: string[];

  // ---- interaction (transient) ----
  draggingNode: DragState | null;
  draggingBoundary: DragState | null;
  resizingBoundary: ResizeState | null;
  /** 複数ノードのグループ移動中の状態（単一ドラッグは draggingNode を使う）。 */
  draggingGroup: GroupDragState | null;
  /** 範囲選択（マーキー）中の矩形。 */
  marquee: MarqueeState | null;
  linkingFromId: string | null;

  // ---- viewport（ズーム/パン。transient・非永続・履歴対象外） ----
  /** ビューポート変換（倍率・パン）。 */
  viewport: Viewport;
  /** キャンバス `main` の実寸（zoomIn/Out/Fit の中心計算用、Canvas が同期）。 */
  canvasSize: { width: number; height: number };
  /** パン（Space+ドラッグ）中の transient 状態。 */
  panning: PanState | null;

  // ---- undo/redo（履歴。永続化しない） ----
  /** 過去スナップショット（末尾が直前状態）。 */
  past: HistorySnapshot[];
  /** やり直し用スナップショット（先頭が次状態）。 */
  future: HistorySnapshot[];
  /** ドラッグ開始済みで、最初の transient 更新時に履歴を 1 回記録する予約フラグ。 */
  _dragArmed: boolean;
  /** 直前コミットの合体タグ（同タグの連続編集を 1 ステップに合体）。 */
  _commitTag: string | null;

  // ---- actions: persistence ----
  hydrate: (payload: HydratePayload) => void;
  markHydrated: () => void;

  // ---- actions: undo/redo ----
  /**
   * 現在のドキュメント状態を past へ記録し future をクリアする。
   * mutation の**直前**に呼ぶこと（記録されるのは変更前のスナップショット）。
   * tag を渡すと、直前コミットが同 tag のときは push をスキップ（合体）。
   */
  recordHistory: (tag?: string) => void;
  undo: () => void;
  redo: () => void;

  // ---- actions: CRUD ----
  addNode: (type: ComponentTypeId) => void;
  addBoundary: (type: BoundaryTypeId) => void;
  deleteNode: (id: string) => void;
  deleteEdge: (id: string) => void;
  deleteBoundary: (id: string) => void;
  updateNode: <K extends keyof DiagramNode>(id: string, field: K, value: DiagramNode[K]) => void;
  updateEdge: <K extends keyof DiagramEdge>(id: string, field: K, value: DiagramEdge[K]) => void;
  updateBoundary: <K extends keyof DiagramBoundary>(
    id: string,
    field: K,
    value: DiagramBoundary[K],
  ) => void;
  reorderBoundary: (id: string, action: ReorderAction) => void;

  // ---- actions: mode ----
  setActiveFramework: (f: FrameworkView) => void;
  toggleFocusMode: () => void;

  // ---- actions: layer ----
  setActiveLayer: (layer: LayerKey) => void;
  /**
   * テンプレート（1 レイヤー分の図）をアクティブレイヤーへ**置換適用**する。
   * 内部 ID を全て新規採番し edge の source/target / parentId を付け替え、
   * 現 `idCounters` の続きから `seq` を振る（§2.26 の番号非再利用を維持）。
   */
  importTemplateToActiveLayer: (layer: LayerData) => void;

  // ---- actions: elemental id ----
  /**
   * 全レイヤーの ElementalID（seq）を種別ごとに 1..n へ振り直し、欠番を解消する
   * （ユーザー明示操作のみ。§2.26 の番号非再利用の唯一の例外）。
   * 旧 seq を含む履歴スナップショットが復活するとカウンタと矛盾するため、
   * Undo/Redo 履歴はクリアする。
   */
  renumberElementalIds: () => void;

  // ---- actions: selection ----
  selectNode: (id: string | null) => void;
  /** 選択集合を ids で置換（マーキー確定等）。edge / boundary 選択はクリア。 */
  setSelectedNodes: (ids: string[]) => void;
  /** Shift+クリック：id の選択を反転（追加 / 解除）。 */
  toggleNodeSelection: (id: string) => void;
  selectEdge: (id: string) => void;
  clearSelection: () => void;

  // ---- actions: linking ----
  setLinkingFromId: (id: string | null) => void;

  // ---- actions: component library ----
  toggleLibrary: (libraryId: string) => void;

  // ---- actions: project metadata ----
  updateProjectMeta: <K extends keyof ProjectMeta>(field: K, value: ProjectMeta[K]) => void;
  setProjectMeta: (meta: ProjectMeta) => void;
  openProjectEdit: () => void;
  closeProjectEdit: () => void;
  openComplianceMap: () => void;
  closeComplianceMap: () => void;
  openAnalytics: () => void;
  closeAnalytics: () => void;
  openLibraryInspector: () => void;
  closeLibraryInspector: () => void;
  openTemplate: () => void;
  closeTemplate: () => void;
  openProjectFile: () => void;
  closeProjectFile: () => void;
  openNewProjectConfirm: () => void;
  closeNewProjectConfirm: () => void;
  /**
   * 全レイヤー空・メタ未設定の「まっさらな新規プロジェクト」へ置き換える。
   * 採番カウンタ・抑制注記・DREAD 評価・Undo/Redo 履歴もリセットする
   * （保存確認は呼び出し側のモーダルで済ませてから呼ぶこと）。
   */
  newProject: () => void;

  // ---- actions: manual threats ----
  addManualThreat: (input: Omit<ManualThreat, 'id'>) => void;
  updateManualThreat: (id: string, patch: Partial<Omit<ManualThreat, 'id'>>) => void;
  removeManualThreat: (id: string) => void;
  /** id 指定で編集モーダル、未指定で新規追加モーダルを開く。 */
  openManualThreatEditor: (id?: string) => void;
  closeManualThreatEditor: () => void;

  // ---- actions: suppressions ----
  setSuppression: (threatId: string, status: SuppressionStatus, note?: string) => void;
  clearSuppression: (threatId: string) => void;

  // ---- actions: DREAD 評価 ----
  setDreadScore: (threatId: string, score: Omit<DreadScore, 'at'>) => void;
  clearDreadScore: (threatId: string) => void;

  // ---- actions: 対策実装状況 ----
  setControlStatus: (threatId: string, status: ControlStatusValue, note?: string) => void;
  clearControlStatus: (threatId: string) => void;

  // ---- actions: interaction (called by useDragInteractions / canvas) ----
  beginNodeInteraction: (
    nodeId: string,
    clientX: number,
    clientY: number,
    additive?: boolean,
  ) => void;
  beginBoundaryInteraction: (
    boundaryId: string,
    clientX: number,
    clientY: number,
    additive?: boolean,
  ) => void;
  beginBoundaryResize: (
    boundaryId: string,
    handle: ResizeHandle,
    clientX: number,
    clientY: number,
  ) => void;
  setNodePosition: (id: string, x: number, y: number) => void;
  /** 複数ノードの座標を一括更新（グループ移動用）。 */
  setNodesPositions: (updates: { id: string; x: number; y: number }[]) => void;
  setNodeParent: (id: string, parentId: string | undefined) => void;
  setBoundaryPosition: (id: string, x: number, y: number) => void;
  /** 複数境界の座標を一括更新（グループ移動用）。 */
  setBoundariesPositions: (updates: { id: string; x: number; y: number }[]) => void;
  applyBoundaryResizeDelta: (dx: number, dy: number) => void;
  endInteraction: () => void;

  // ---- actions: marquee（範囲選択） ----
  beginMarquee: (offsetLeft: number, offsetTop: number, x: number, y: number) => void;
  updateMarquee: (x: number, y: number) => void;
  endMarquee: () => void;

  // ---- actions: viewport（ズーム/パン） ----
  /** Canvas が `main` の実寸を同期する（zoomIn/Out/Fit の中心計算に使う）。 */
  setCanvasSize: (width: number, height: number) => void;
  /** `main` ローカル座標 (localX,localY) を固定して倍率を ×factor する（ホイール用）。 */
  zoomAtLocal: (localX: number, localY: number, factor: number) => void;
  /** キャンバス中心を基準に拡大／縮小（ボタン用）。 */
  zoomIn: () => void;
  zoomOut: () => void;
  /** 等倍・パンなしへ戻す（100%）。 */
  resetZoom: () => void;
  /** アクティブレイヤーの全要素を画面に収める。 */
  fitToContent: () => void;
  /** パン開始（Space+背景ドラッグ）。 */
  beginPan: (clientX: number, clientY: number) => void;
  /** パン中の tx/ty 更新（画面 px 差分、scale 非除算）。 */
  panTo: (clientX: number, clientY: number) => void;
}

export const useDiagramStore = create<DiagramState>((set, get) => ({
  layers: INITIAL_LAYERS,
  activeLayer: DEFAULT_ACTIVE_LAYER,
  idCounters: INITIAL_ID_COUNTERS,

  activeFramework: 'ALL',
  isFocusMode: false,

  isHydrated: false,

  disabledLibraryIds: new Set(),

  projectMeta: EMPTY_PROJECT_META,
  isProjectEditOpen: false,
  isComplianceMapOpen: false,
  isAnalyticsOpen: false,
  isLibraryInspectorOpen: false,
  isTemplateModalOpen: false,
  isProjectFileModalOpen: false,
  isNewProjectConfirmOpen: false,

  manualThreats: emptyManualThreats(),
  suppressions: {},
  dreadScores: {},
  controlStatuses: {},
  isManualThreatModalOpen: false,
  editingManualThreatId: null,

  selectedNodeIds: [],
  selectedEdgeId: null,
  selectedBoundaryIds: [],

  draggingNode: null,
  draggingBoundary: null,
  resizingBoundary: null,
  draggingGroup: null,
  marquee: null,
  linkingFromId: null,

  viewport: IDENTITY_VIEWPORT,
  canvasSize: { width: 0, height: 0 },
  panning: null,

  past: [],
  future: [],
  _dragArmed: false,
  _commitTag: null,

  hydrate: (payload) =>
    set({
      layers: payload.layers,
      activeLayer: payload.activeLayer,
      idCounters: payload.idCounters ?? emptyIdCounters(),
      activeFramework: payload.activeFramework,
      disabledLibraryIds: new Set(payload.disabledLibraryIds ?? []),
      projectMeta: payload.projectMeta ?? EMPTY_PROJECT_META,
      manualThreats: payload.manualThreats ?? emptyManualThreats(),
      suppressions: payload.suppressions ?? {},
      dreadScores: payload.dreadScores ?? {},
      controlStatuses: payload.controlStatuses ?? {},
      isHydrated: true,
      selectedNodeIds: [],
      selectedEdgeId: null,
      selectedBoundaryIds: [],
      // ロードは履歴のリセット起点
      past: [],
      future: [],
      _commitTag: null,
      _dragArmed: false,
    }),

  markHydrated: () => set({ isHydrated: true }),

  recordHistory: (tag) =>
    set((s) => {
      // 同一合体グループの連続コミットは、最初のスナップショットで十分なのでスキップ。
      if (tag != null && tag === s._commitTag) return s;
      const past = s.past.length >= MAX_HISTORY ? s.past.slice(1) : s.past.slice();
      past.push(snapshotOf(s));
      return { past, future: [], _commitTag: tag ?? null, _dragArmed: false };
    }),

  undo: () =>
    set((s) => {
      if (s.past.length === 0) return s;
      const previous = s.past[s.past.length - 1];
      return {
        ...previous,
        past: s.past.slice(0, -1),
        future: [snapshotOf(s), ...s.future],
        // stale 参照回避のため選択をクリア
        selectedNodeIds: [],
        selectedEdgeId: null,
        selectedBoundaryIds: [],
        _commitTag: null,
        _dragArmed: false,
      };
    }),

  redo: () =>
    set((s) => {
      if (s.future.length === 0) return s;
      const next = s.future[0];
      return {
        ...next,
        past: [...s.past, snapshotOf(s)],
        future: s.future.slice(1),
        selectedNodeIds: [],
        selectedEdgeId: null,
        selectedBoundaryIds: [],
        _commitTag: null,
        _dragArmed: false,
      };
    }),

  addNode: (type) => {
    get().recordHistory();
    set((s) => {
      const layer = s.activeLayer;
      const seq = s.idCounters[layer].node + 1;
      return {
        ...withActiveLayer(s, (l) => ({
          nodes: [...l.nodes, { id: nextId('n'), seq, type, x: 300, y: 300 }],
        })),
        idCounters: bumpCounter(s.idCounters, layer, 'node', seq),
      };
    });
  },

  addBoundary: (type) => {
    get().recordHistory();
    set((s) => {
      const layer = s.activeLayer;
      const seq = s.idCounters[layer].boundary + 1;
      const base = {
        id: nextId('b'),
        seq,
        type,
        x: 200,
        y: 200,
        width: 400,
        height: 200,
      } as const;
      let boundary: DiagramBoundary;
      if (type === 'ROUNDED') {
        boundary = { ...base, trustLevel: 'Internal', macroTrust: 'Office Area' };
      } else if (type === 'ROUNDED_DASHED') {
        boundary = {
          ...base,
          trustLevel: 'Internal',
          microTrust: 'Production',
          microSegmentationStatus: '未適用',
          sensitiveData: '無し',
        };
      } else if (type === 'RECT_DASHED') {
        // DMZ は Internet 相当の固定トラスト。
        boundary = { ...base, trustLevel: 'Internet' };
      } else {
        boundary = { ...base, trustLevel: 'Internal' };
      }
      return {
        ...withActiveLayer(s, (l) => ({ boundaries: [...l.boundaries, boundary] })),
        idCounters: bumpCounter(s.idCounters, layer, 'boundary', seq),
      };
    });
  },

  deleteNode: (id) => {
    get().recordHistory();
    set((s) => ({
      ...withActiveLayer(s, (l) => ({
        // 削除対象を除外し、子の parentId は解除してトップレベルに戻す。
        // 削除対象を標的にしていた攻撃者ノードの attackObjectiveId も解除する。
        nodes: l.nodes
          .filter((n) => n.id !== id)
          .map((n) => {
            if (n.parentId !== id && n.attackObjectiveId !== id) return n;
            const rest = { ...n };
            if (rest.parentId === id) delete rest.parentId;
            if (rest.attackObjectiveId === id) delete rest.attackObjectiveId;
            return rest;
          }),
      })),
      selectedNodeIds: s.selectedNodeIds.filter((nid) => nid !== id),
    }));
  },

  deleteEdge: (id) => {
    get().recordHistory();
    set((s) => ({
      ...withActiveLayer(s, (l) => ({ edges: l.edges.filter((e) => e.id !== id) })),
      selectedEdgeId: s.selectedEdgeId === id ? null : s.selectedEdgeId,
    }));
  },

  deleteBoundary: (id) => {
    get().recordHistory();
    set((s) => ({
      ...withActiveLayer(s, (l) => ({
        boundaries: l.boundaries.filter((b) => b.id !== id),
      })),
      selectedBoundaryIds: s.selectedBoundaryIds.filter((bid) => bid !== id),
    }));
  },

  updateNode: (id, field, value) => {
    get().recordHistory(`u:n:${id}:${String(field)}`);
    set((s) =>
      withActiveLayer(s, (l) => ({
        nodes: l.nodes.map((n) => (n.id === id ? { ...n, [field]: value } : n)),
      })),
    );
  },

  updateEdge: (id, field, value) => {
    get().recordHistory(`u:e:${id}:${String(field)}`);
    set((s) =>
      withActiveLayer(s, (l) => ({
        edges: l.edges.map((e) => (e.id === id ? { ...e, [field]: value } : e)),
      })),
    );
  },

  updateBoundary: (id, field, value) => {
    get().recordHistory(`u:b:${id}:${String(field)}`);
    set((s) =>
      withActiveLayer(s, (l) => ({
        boundaries: l.boundaries.map((b) => (b.id === id ? { ...b, [field]: value } : b)),
      })),
    );
  },

  /**
   * 境界の重なり順を並べ替える。配列の先頭 = 最背面、末尾 = 最前面（描画順）。
   */
  reorderBoundary: (id, action) => {
    get().recordHistory();
    set((s) => {
      const current = s.layers[s.activeLayer].boundaries;
      const idx = current.findIndex((b) => b.id === id);
      if (idx === -1) return s;
      const next = current.slice();
      const [item] = next.splice(idx, 1);
      let targetIdx: number;
      if (action === 'front') targetIdx = next.length;
      else if (action === 'back') targetIdx = 0;
      else if (action === 'forward') targetIdx = Math.min(idx + 1, next.length);
      else targetIdx = Math.max(idx - 1, 0);
      next.splice(targetIdx, 0, item);
      return withActiveLayer(s, () => ({ boundaries: next }));
    });
  },

  setActiveFramework: (f) => set({ activeFramework: f }),
  toggleFocusMode: () => set((s) => ({ isFocusMode: !s.isFocusMode })),

  setActiveLayer: (layer) =>
    set({
      activeLayer: layer,
      // レイヤー切替時は選択 / リンク中状態をクリア（別レイヤーの ID は無効）
      selectedNodeIds: [],
      selectedEdgeId: null,
      selectedBoundaryIds: [],
      linkingFromId: null,
      _commitTag: null,
    }),

  importTemplateToActiveLayer: (layer) => {
    get().recordHistory();
    set((s) => {
      const lk = s.activeLayer;
      const counters = s.idCounters[lk];

      // 旧 ID → 新 ID のマップを先に作る（edge の参照・parentId 付け替えに使う）。
      const idMap = new Map<string, string>();
      for (const n of layer.nodes) idMap.set(n.id, nextId('n'));

      let nodeSeq = counters.node;
      const nodes = layer.nodes.map((n) => {
        nodeSeq += 1;
        const next: DiagramNode = { ...n, id: idMap.get(n.id) as string, seq: nodeSeq };
        if (next.parentId) {
          const mapped = idMap.get(next.parentId);
          // 親がテンプレート内に居れば付け替え、居なければ親解除（トップレベル化）。
          if (mapped) next.parentId = mapped;
          else delete next.parentId;
        }
        if (next.attackObjectiveId) {
          const mapped = idMap.get(next.attackObjectiveId);
          // 標的がテンプレート内に居れば付け替え、居なければ解除。
          if (mapped) next.attackObjectiveId = mapped;
          else delete next.attackObjectiveId;
        }
        return next;
      });

      let edgeSeq = counters.edge;
      const edges = layer.edges
        // 端点が両方ともテンプレート内に存在するエッジのみ取り込む。
        .filter((e) => idMap.has(e.source) && idMap.has(e.target))
        .map((e) => {
          edgeSeq += 1;
          return {
            ...e,
            id: nextId('e'),
            seq: edgeSeq,
            source: idMap.get(e.source) as string,
            target: idMap.get(e.target) as string,
          };
        });

      let boundarySeq = counters.boundary;
      const boundaries = layer.boundaries.map((b) => {
        boundarySeq += 1;
        return { ...b, id: nextId('b'), seq: boundarySeq };
      });

      return {
        layers: { ...s.layers, [lk]: { nodes, edges, boundaries } },
        idCounters: {
          ...s.idCounters,
          [lk]: { node: nodeSeq, edge: edgeSeq, boundary: boundarySeq },
        },
        selectedNodeIds: [],
        selectedEdgeId: null,
        selectedBoundaryIds: [],
        _commitTag: null,
      };
    });
  },

  renumberElementalIds: () =>
    set((s) => {
      const layers = { ...s.layers };
      const idCounters = { ...s.idCounters };
      for (const key of Object.keys(s.layers) as LayerKey[]) {
        const l = s.layers[key];
        const nodes = renumberKind(l.nodes);
        const edges = renumberKind(l.edges);
        const boundaries = renumberKind(l.boundaries);
        layers[key] = { nodes, edges, boundaries };
        idCounters[key] = {
          node: nodes.length,
          edge: edges.length,
          boundary: boundaries.length,
        };
      }
      return {
        layers,
        idCounters,
        // 旧 seq のスナップショットが復元されるとカウンタと不整合になるため履歴をクリア
        past: [],
        future: [],
        _commitTag: null,
        _dragArmed: false,
      };
    }),

  selectNode: (id) =>
    set({
      selectedNodeIds: id ? [id] : [],
      selectedEdgeId: null,
      selectedBoundaryIds: [],
      _commitTag: null,
    }),

  setSelectedNodes: (ids) =>
    set({ selectedNodeIds: ids, selectedEdgeId: null, selectedBoundaryIds: [], _commitTag: null }),

  toggleNodeSelection: (id) =>
    set((s) => ({
      selectedNodeIds: s.selectedNodeIds.includes(id)
        ? s.selectedNodeIds.filter((nid) => nid !== id)
        : [...s.selectedNodeIds, id],
      selectedEdgeId: null,
      _commitTag: null,
    })),

  selectEdge: (id) =>
    set({ selectedEdgeId: id, selectedNodeIds: [], selectedBoundaryIds: [], _commitTag: null }),

  clearSelection: () =>
    set({ selectedNodeIds: [], selectedEdgeId: null, selectedBoundaryIds: [], _commitTag: null }),

  setLinkingFromId: (id) => set({ linkingFromId: id }),

  toggleLibrary: (libraryId) =>
    set((s) => {
      const next = new Set(s.disabledLibraryIds);
      if (next.has(libraryId)) next.delete(libraryId);
      else next.add(libraryId);
      return { disabledLibraryIds: next };
    }),

  updateProjectMeta: (field, value) =>
    set((s) => ({ projectMeta: { ...s.projectMeta, [field]: value } })),

  setProjectMeta: (meta) => set({ projectMeta: meta }),

  openProjectEdit: () => set({ isProjectEditOpen: true }),
  closeProjectEdit: () => set({ isProjectEditOpen: false }),

  openComplianceMap: () => set({ isComplianceMapOpen: true }),
  closeComplianceMap: () => set({ isComplianceMapOpen: false }),

  openAnalytics: () => set({ isAnalyticsOpen: true }),
  closeAnalytics: () => set({ isAnalyticsOpen: false }),

  openLibraryInspector: () => set({ isLibraryInspectorOpen: true }),
  closeLibraryInspector: () => set({ isLibraryInspectorOpen: false }),

  openTemplate: () => set({ isTemplateModalOpen: true }),
  closeTemplate: () => set({ isTemplateModalOpen: false }),
  openProjectFile: () => set({ isProjectFileModalOpen: true }),
  closeProjectFile: () => set({ isProjectFileModalOpen: false }),
  openNewProjectConfirm: () => set({ isNewProjectConfirmOpen: true }),
  closeNewProjectConfirm: () => set({ isNewProjectConfirmOpen: false }),

  newProject: () =>
    set({
      layers: { L0: EMPTY_LAYER, L1: EMPTY_LAYER, L2: EMPTY_LAYER, L3: EMPTY_LAYER },
      activeLayer: DEFAULT_ACTIVE_LAYER,
      idCounters: emptyIdCounters(),
      activeFramework: 'ALL',
      disabledLibraryIds: new Set(),
      projectMeta: EMPTY_PROJECT_META,
      manualThreats: emptyManualThreats(),
      suppressions: {},
      dreadScores: {},
      controlStatuses: {},
      isNewProjectConfirmOpen: false,
      selectedNodeIds: [],
      selectedEdgeId: null,
      selectedBoundaryIds: [],
      linkingFromId: null,
      viewport: IDENTITY_VIEWPORT,
      // 旧プロジェクトの状態へ Undo で戻れると採番カウンタと矛盾するため履歴をクリア
      past: [],
      future: [],
      _commitTag: null,
      _dragArmed: false,
    }),

  addManualThreat: (input) => {
    get().recordHistory();
    set((s) => {
      const item: ManualThreat = { ...input, id: nextId('mt') };
      return {
        manualThreats: {
          ...s.manualThreats,
          [s.activeLayer]: [...s.manualThreats[s.activeLayer], item],
        },
      };
    });
  },

  updateManualThreat: (id, patch) => {
    get().recordHistory();
    set((s) => ({
      manualThreats: {
        ...s.manualThreats,
        [s.activeLayer]: s.manualThreats[s.activeLayer].map((m) =>
          m.id === id ? { ...m, ...patch } : m,
        ),
      },
    }));
  },

  removeManualThreat: (id) => {
    get().recordHistory();
    set((s) => ({
      manualThreats: {
        ...s.manualThreats,
        [s.activeLayer]: s.manualThreats[s.activeLayer].filter((m) => m.id !== id),
      },
    }));
  },

  openManualThreatEditor: (id) =>
    set({ isManualThreatModalOpen: true, editingManualThreatId: id ?? null }),
  closeManualThreatEditor: () =>
    set({ isManualThreatModalOpen: false, editingManualThreatId: null }),

  setSuppression: (threatId, status, note) => {
    get().recordHistory();
    set((s) => ({
      suppressions: {
        ...s.suppressions,
        [threatId]: { status, ...(note ? { note } : {}), at: Date.now() },
      },
    }));
  },

  clearSuppression: (threatId) => {
    if (!(threatId in get().suppressions)) return;
    get().recordHistory();
    set((s) => {
      const next = { ...s.suppressions };
      delete next[threatId];
      return { suppressions: next };
    });
  },

  setDreadScore: (threatId, score) => {
    get().recordHistory();
    set((s) => ({
      dreadScores: { ...s.dreadScores, [threatId]: { ...score, at: Date.now() } },
    }));
  },

  clearDreadScore: (threatId) => {
    if (!(threatId in get().dreadScores)) return;
    get().recordHistory();
    set((s) => {
      const next = { ...s.dreadScores };
      delete next[threatId];
      return { dreadScores: next };
    });
  },

  setControlStatus: (threatId, status, note) => {
    get().recordHistory();
    set((s) => ({
      controlStatuses: {
        ...s.controlStatuses,
        [threatId]: { status, ...(note ? { note } : {}), at: Date.now() },
      },
    }));
  },

  clearControlStatus: (threatId) => {
    if (!(threatId in get().controlStatuses)) return;
    get().recordHistory();
    set((s) => {
      const next = { ...s.controlStatuses };
      delete next[threatId];
      return { controlStatuses: next };
    });
  },

  beginNodeInteraction: (nodeId, clientX, clientY, additive = false) => {
    const s = get();
    if (s.linkingFromId) {
      if (s.linkingFromId !== nodeId) {
        // リンクによるエッジ作成はドキュメント変更 → 履歴に記録
        get().recordHistory();
        set((curr) => {
          const layer = curr.activeLayer;
          const seq = curr.idCounters[layer].edge + 1;
          return {
            ...withActiveLayer(curr, (l) => ({
              edges: [
                ...l.edges,
                {
                  id: nextId('e'),
                  seq,
                  source: s.linkingFromId as string,
                  target: nodeId,
                  auth: 'None',
                  network: 'VPC',
                  encryption: 'TLS',
                  dataFlow: 'outbound',
                },
              ],
            })),
            idCounters: bumpCounter(curr.idCounters, layer, 'edge', seq),
          };
        });
      }
      set({ linkingFromId: null });
      return;
    }
    const nodes = s.layers[s.activeLayer].nodes;
    const node = nodes.find((n) => n.id === nodeId);
    if (!node) return;

    // Shift+クリック：選択をトグルするのみ（ドラッグは開始しない）。
    if (additive) {
      s.toggleNodeSelection(nodeId);
      return;
    }

    // 既に複数選択（ノード + 境界の合計が 2 以上）の一員なら、選択を維持したまま
    // ノード・境界をまとめてグループ移動。
    const selectionSize = s.selectedNodeIds.length + s.selectedBoundaryIds.length;
    if (selectionSize > 1 && s.selectedNodeIds.includes(nodeId)) {
      // _dragArmed: 最初の移動時に履歴を 1 回だけ記録する予約。
      set({ draggingGroup: buildGroupDrag(s, clientX, clientY), _dragArmed: true });
      return;
    }

    // それ以外は単一選択 + 単一ドラッグ（従来挙動、reparent あり）。
    set({
      selectedNodeIds: [nodeId],
      selectedEdgeId: null,
      selectedBoundaryIds: [],
      draggingNode: {
        id: nodeId,
        startClientX: clientX,
        startClientY: clientY,
        origX: node.x,
        origY: node.y,
      },
      _dragArmed: true,
      _commitTag: null,
    });
  },

  beginBoundaryInteraction: (boundaryId, clientX, clientY, additive = false) => {
    const s = get();
    const boundary = s.layers[s.activeLayer].boundaries.find((b) => b.id === boundaryId);
    if (!boundary) return;

    // Shift+クリック：境界選択をトグルするのみ（ドラッグは開始しない）。
    if (additive) {
      set({
        selectedBoundaryIds: s.selectedBoundaryIds.includes(boundaryId)
          ? s.selectedBoundaryIds.filter((bid) => bid !== boundaryId)
          : [...s.selectedBoundaryIds, boundaryId],
        selectedEdgeId: null,
      });
      return;
    }

    // 既に複数選択（ノード + 境界）の一員なら、選択維持でグループ移動。
    const selectionSize = s.selectedNodeIds.length + s.selectedBoundaryIds.length;
    if (selectionSize > 1 && s.selectedBoundaryIds.includes(boundaryId)) {
      set({ draggingGroup: buildGroupDrag(s, clientX, clientY), _dragArmed: true });
      return;
    }

    set({
      selectedBoundaryIds: [boundaryId],
      selectedNodeIds: [],
      selectedEdgeId: null,
      draggingBoundary: {
        id: boundaryId,
        startClientX: clientX,
        startClientY: clientY,
        origX: boundary.x,
        origY: boundary.y,
      },
      _dragArmed: true,
      _commitTag: null,
    });
  },

  beginBoundaryResize: (boundaryId, handle, clientX, clientY) => {
    const s = get();
    const boundary = s.layers[s.activeLayer].boundaries.find((b) => b.id === boundaryId);
    if (!boundary) return;
    set({
      selectedBoundaryIds: [boundaryId],
      selectedNodeIds: [],
      selectedEdgeId: null,
      _dragArmed: true,
      _commitTag: null,
      resizingBoundary: {
        id: boundaryId,
        handle,
        startX: clientX,
        startY: clientY,
        startBox: {
          x: boundary.x,
          y: boundary.y,
          width: boundary.width,
          height: boundary.height,
        },
      },
    });
  },

  setNodePosition: (id, x, y) => {
    if (get()._dragArmed) get().recordHistory();
    set((s) =>
      withActiveLayer(s, (l) => ({
        nodes: l.nodes.map((n) => (n.id === id ? { ...n, x, y } : n)),
      })),
    );
  },

  setNodesPositions: (updates) => {
    if (get()._dragArmed) get().recordHistory();
    set((s) => {
      const byId = new Map(updates.map((u) => [u.id, u]));
      return withActiveLayer(s, (l) => ({
        nodes: l.nodes.map((n) => {
          const u = byId.get(n.id);
          return u ? { ...n, x: u.x, y: u.y } : n;
        }),
      }));
    });
  },

  setNodeParent: (id, parentId) =>
    set((s) =>
      withActiveLayer(s, (l) => ({
        nodes: l.nodes.map((n) => {
          if (n.id !== id) return n;
          if (parentId === undefined) {
            // 親解除：parentId プロパティ自体を消す
            const { parentId: _omit, ...rest } = n;
            return rest as DiagramNode;
          }
          return { ...n, parentId };
        }),
      })),
    ),

  setBoundaryPosition: (id, x, y) => {
    if (get()._dragArmed) get().recordHistory();
    set((s) =>
      withActiveLayer(s, (l) => ({
        boundaries: l.boundaries.map((b) => (b.id === id ? { ...b, x, y } : b)),
      })),
    );
  },

  setBoundariesPositions: (updates) => {
    if (get()._dragArmed) get().recordHistory();
    set((s) => {
      const byId = new Map(updates.map((u) => [u.id, u]));
      return withActiveLayer(s, (l) => ({
        boundaries: l.boundaries.map((b) => {
          const u = byId.get(b.id);
          return u ? { ...b, x: u.x, y: u.y } : b;
        }),
      }));
    });
  },

  applyBoundaryResizeDelta: (dx, dy) => {
    const r = get().resizingBoundary;
    if (!r) return;
    if (get()._dragArmed) get().recordHistory();
    const box = applyResize(r.startBox, r.handle, dx, dy);
    set((s) =>
      withActiveLayer(s, (l) => ({
        boundaries: l.boundaries.map((b) => (b.id === r.id ? { ...b, ...box } : b)),
      })),
    );
  },

  endInteraction: () =>
    set({
      draggingNode: null,
      draggingBoundary: null,
      resizingBoundary: null,
      draggingGroup: null,
      panning: null,
      // 移動なしのクリックで終わった場合の予約解除
      _dragArmed: false,
    }),

  beginMarquee: (offsetLeft, offsetTop, x, y) =>
    set({
      // マーキー開始時に既存選択をクリア（背景の空クリックでも解除される挙動）。
      selectedNodeIds: [],
      selectedEdgeId: null,
      selectedBoundaryIds: [],
      marquee: { offsetLeft, offsetTop, startX: x, startY: y, curX: x, curY: y },
    }),

  updateMarquee: (x, y) =>
    set((s) => (s.marquee ? { marquee: { ...s.marquee, curX: x, curY: y } } : s)),

  endMarquee: () =>
    set((s) => {
      if (!s.marquee) return { marquee: null };
      const layer = s.layers[s.activeLayer];
      // marquee 矩形は main ローカル座標で描画している。内包判定はワールド座標で
      // 行うため、ビューポート変換を解いた矩形に変換する（world = (local - t)/scale）。
      const { scale, tx, ty } = s.viewport;
      const worldMarquee: MarqueeState = {
        ...s.marquee,
        startX: (s.marquee.startX - tx) / scale,
        startY: (s.marquee.startY - ty) / scale,
        curX: (s.marquee.curX - tx) / scale,
        curY: (s.marquee.curY - ty) / scale,
      };
      const { nodeIds, boundaryIds } = elementsInMarquee(
        layer.nodes,
        layer.boundaries,
        worldMarquee,
      );
      return { selectedNodeIds: nodeIds, selectedBoundaryIds: boundaryIds, marquee: null };
    }),

  setCanvasSize: (width, height) =>
    set((s) =>
      s.canvasSize.width === width && s.canvasSize.height === height
        ? s
        : { canvasSize: { width, height } },
    ),

  zoomAtLocal: (localX, localY, factor) =>
    set((s) => ({ viewport: zoomAtPoint(s.viewport, localX, localY, s.viewport.scale * factor) })),

  zoomIn: () =>
    set((s) => ({
      viewport: zoomAtPoint(
        s.viewport,
        s.canvasSize.width / 2,
        s.canvasSize.height / 2,
        s.viewport.scale * ZOOM_STEP,
      ),
    })),

  zoomOut: () =>
    set((s) => ({
      viewport: zoomAtPoint(
        s.viewport,
        s.canvasSize.width / 2,
        s.canvasSize.height / 2,
        s.viewport.scale / ZOOM_STEP,
      ),
    })),

  resetZoom: () => set({ viewport: IDENTITY_VIEWPORT }),

  fitToContent: () =>
    set((s) => {
      const layer = s.layers[s.activeLayer];
      return {
        viewport: computeFit(
          layer.nodes,
          layer.boundaries,
          s.canvasSize.width,
          s.canvasSize.height,
        ),
      };
    }),

  beginPan: (clientX, clientY) =>
    set((s) => ({
      panning: {
        startClientX: clientX,
        startClientY: clientY,
        startTx: s.viewport.tx,
        startTy: s.viewport.ty,
      },
    })),

  panTo: (clientX, clientY) =>
    set((s) => {
      if (!s.panning) return s;
      return {
        viewport: {
          ...s.viewport,
          tx: s.panning.startTx + (clientX - s.panning.startClientX),
          ty: s.panning.startTy + (clientY - s.panning.startClientY),
        },
      };
    }),
}));
