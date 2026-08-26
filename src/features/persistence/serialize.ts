import type {
  ControlStatusState,
  DreadScore,
  FrameworkView,
  LayerData,
  LayerKey,
  LayerSeqCounters,
  ManualThreat,
  ProjectMeta,
  SuppressionState,
} from '../../core/model/types';
import { EMPTY_LAYER, LAYER_KEYS } from '../../core/model/types';

/** 全レイヤー空の手動脅威 Record を新規生成する（hydrate / 初期化用）。 */
export function emptyManualThreats(): Record<LayerKey, ManualThreat[]> {
  return { L0: [], L1: [], L2: [], L3: [] };
}
import {
  PERSISTED_PROJECT_SCHEMA_VERSION,
  PersistedProjectSchema,
  type PersistedProject,
} from './schema';

export interface SerializableState {
  layers: Record<LayerKey, LayerData>;
  activeLayer: LayerKey;
  activeFramework: FrameworkView;
  disabledLibraryIds?: ReadonlySet<string> | readonly string[];
  projectMeta?: ProjectMeta;
  manualThreats?: Record<LayerKey, ManualThreat[]>;
  suppressions?: Record<string, SuppressionState>;
  /** 脅威への DREAD 評価（threatId キー。§2.34）。省略時は保存しない。 */
  dreadScores?: Record<string, DreadScore>;
  /** 対策実装状況（threatId キー）。省略時は保存しない。 */
  controlStatuses?: Record<string, ControlStatusState>;
  /** ElementalID 採番カウンタ（§2.26）。省略時は保存しない（旧テスト互換）。 */
  idCounters?: LayerSeqCounters;
}

/**
 * ストアの永続化対象 state を IndexedDB 保存形式に変換する純粋関数。
 *
 * 深度レイヤー化以降は `layers` を保存し、旧形式の `nodes/edges/boundaries`
 * トップレベルフィールドには触れない（schemaVersion は据え置きで、旧データの
 * 読み込みは deserialize 側のマイグレーションで吸収する）。
 */
export function serializeProject(state: SerializableState): PersistedProject {
  const disabled = state.disabledLibraryIds;
  const disabledArr =
    disabled instanceof Set
      ? [...disabled]
      : Array.isArray(disabled)
        ? [...disabled]
        : undefined;
  const meta = state.projectMeta;
  const hasMetaContent =
    !!meta &&
    (meta.name !== '' ||
      meta.systemName !== '' ||
      meta.purpose !== '' ||
      meta.businessImpact !== '' ||
      meta.securityObjectives !== '');
  const manual = state.manualThreats;
  const hasManual = !!manual && LAYER_KEYS.some((k) => (manual[k]?.length ?? 0) > 0);
  const suppressions = state.suppressions;
  const hasSuppressions = !!suppressions && Object.keys(suppressions).length > 0;
  const dreadScores = state.dreadScores;
  const hasDreadScores = !!dreadScores && Object.keys(dreadScores).length > 0;
  const controlStatuses = state.controlStatuses;
  const hasControlStatuses = !!controlStatuses && Object.keys(controlStatuses).length > 0;
  return {
    schemaVersion: PERSISTED_PROJECT_SCHEMA_VERSION,
    layers: state.layers,
    activeLayer: state.activeLayer,
    ...(state.idCounters ? { idCounters: state.idCounters } : {}),
    activeFramework: state.activeFramework,
    ...(disabledArr && disabledArr.length > 0 ? { disabledLibraryIds: disabledArr } : {}),
    ...(hasMetaContent ? { projectMeta: meta } : {}),
    ...(hasManual ? { manualThreats: manual } : {}),
    ...(hasSuppressions ? { suppressions } : {}),
    ...(hasDreadScores ? { dreadScores } : {}),
    ...(hasControlStatuses ? { controlStatuses } : {}),
    updatedAt: Date.now(),
  };
}

/**
 * 旧 framework 値を新 enum へ変換する（[[plan]] §2.29）：
 * `'STRIDE+AI'`→`'STRIDE'`（古典 STRIDE への改名）、`'MAESTRO'`→`'AgenticAI'`
 * （MAESTRO は概念であってフレームワークではないため概念カテゴリ名へ改称）。
 * 3 分類化以前に保存されたレコードは `activeFramework` と `manualThreats[].framework`
 * に旧値を持つ。schema を新 enum に揃えたため、parse 前にここで正規化しないと旧
 * プロジェクトが丸ごと破棄される。raw は信頼境界外なので形が想定外でもそのまま
 * 通し、検証は後段の Zod に委ねる。
 */
const LEGACY_FRAMEWORK_MAP: Record<string, string> = {
  'STRIDE+AI': 'STRIDE',
  MAESTRO: 'AgenticAI',
};

function migrateLegacyFramework(raw: unknown): unknown {
  if (typeof raw !== 'object' || raw === null) return raw;
  const r = raw as Record<string, unknown>;
  const next: Record<string, unknown> = { ...r };
  if (typeof r.activeFramework === 'string' && r.activeFramework in LEGACY_FRAMEWORK_MAP) {
    next.activeFramework = LEGACY_FRAMEWORK_MAP[r.activeFramework];
  }
  if (r.manualThreats && typeof r.manualThreats === 'object') {
    const layers = r.manualThreats as Record<string, unknown>;
    const migrated: Record<string, unknown> = {};
    for (const [key, arr] of Object.entries(layers)) {
      migrated[key] = Array.isArray(arr)
        ? arr.map((t) => {
            const fw = t && typeof t === 'object' ? (t as Record<string, unknown>).framework : undefined;
            return typeof fw === 'string' && fw in LEGACY_FRAMEWORK_MAP
              ? { ...(t as Record<string, unknown>), framework: LEGACY_FRAMEWORK_MAP[fw] }
              : t;
          })
        : arr;
    }
    next.manualThreats = migrated;
  }
  return next;
}

/**
 * IndexedDB から取り出した unknown を `PersistedProject` に変換する。
 * 失敗時は `null` を返し、呼び出し側で初期状態へフォールバックさせる。
 *
 * 未来の schemaVersion は Zod の `z.literal(1)` で reject されるため
 * 自動的に `null` 経由で安全側に倒れる。
 */
export function deserializeProject(raw: unknown): PersistedProject | null {
  const result = PersistedProjectSchema.safeParse(migrateLegacyFramework(raw));
  if (!result.success) return null;
  return result.data;
}

/**
 * 永続化レコードを「ハイドレート可能な layers + activeLayer」へ正規化する。
 *
 * - `layers` が含まれていればそのまま使用。
 * - 旧形式（深度レイヤー導入前）はトップレベルの `nodes/edges/boundaries` を
 *   **L1 へ自動マイグレート** し、L0/L2/L3 は空レイヤーで埋める（既存ユーザーの
 *   データロスを避ける。詳細は [[plan]] §2 ステップ 18）。
 * - どちらも欠ければ全レイヤー空で起動。
 */
export function resolveLayers(loaded: PersistedProject): {
  layers: Record<LayerKey, LayerData>;
  activeLayer: LayerKey;
} {
  if (loaded.layers) {
    const layers = LAYER_KEYS.reduce<Record<LayerKey, LayerData>>(
      (acc, key) => {
        const data = loaded.layers![key];
        acc[key] = {
          nodes: data.nodes,
          edges: data.edges as LayerData['edges'],
          boundaries: data.boundaries,
        };
        return acc;
      },
      { L0: EMPTY_LAYER, L1: EMPTY_LAYER, L2: EMPTY_LAYER, L3: EMPTY_LAYER },
    );
    return { layers, activeLayer: loaded.activeLayer ?? 'L1' };
  }

  // 旧形式：トップレベル nodes/edges/boundaries を L1 へマイグレート
  const migratedL1: LayerData = {
    nodes: loaded.nodes ?? [],
    edges: (loaded.edges ?? []) as LayerData['edges'],
    boundaries: loaded.boundaries ?? [],
  };
  return {
    layers: { L0: EMPTY_LAYER, L1: migratedL1, L2: EMPTY_LAYER, L3: EMPTY_LAYER },
    activeLayer: 'L1',
  };
}

/**
 * 1 種別の要素配列に対し、`seq` 未設定の要素へ採番を補完しつつ最終カウンタを求める。
 * 既存 `seq` は保持（安定性）、未設定のみ `start` の続きから連番を振る。
 * 何も変更しなければ入力配列の参照をそのまま返す（不要な再生成を避ける）。
 */
function fillSeq<T extends { seq?: number }>(
  items: T[],
  start: number,
): { items: T[]; counter: number } {
  let counter = start;
  let changed = false;
  const out = items.map((it) => {
    if (it.seq != null) {
      if (it.seq > counter) counter = it.seq;
      return it;
    }
    counter += 1;
    changed = true;
    return { ...it, seq: counter };
  });
  return { items: changed ? out : items, counter };
}

/**
 * ロード済みレイヤーから ElementalID の採番状態を確定する（[[plan]] §2.26 Step 3）。
 *
 * - `persisted`（保存済みカウンタ）があればそれを起点に使う（番号の永続的非再利用を保証）。
 * - `seq` 未設定の要素（旧データ / Step 2 以前の保存）には要素順で連番を補完する。
 * - 既存 `seq` は保持し、カウンタはレイヤー×種別ごとの最大値以上に保つ。
 */
export function resolveIdCounters(
  layers: Record<LayerKey, LayerData>,
  persisted?: LayerSeqCounters,
): { layers: Record<LayerKey, LayerData>; idCounters: LayerSeqCounters } {
  const nextLayers = {} as Record<LayerKey, LayerData>;
  const idCounters = {} as LayerSeqCounters;
  for (const key of LAYER_KEYS) {
    const layer = layers[key];
    const base = persisted?.[key] ?? { node: 0, edge: 0, boundary: 0 };
    const n = fillSeq(layer.nodes, base.node);
    const e = fillSeq(layer.edges, base.edge);
    const b = fillSeq(layer.boundaries, base.boundary);
    nextLayers[key] =
      n.items === layer.nodes && e.items === layer.edges && b.items === layer.boundaries
        ? layer
        : { nodes: n.items, edges: e.items, boundaries: b.items };
    idCounters[key] = { node: n.counter, edge: e.counter, boundary: b.counter };
  }
  return { layers: nextLayers, idCounters };
}
