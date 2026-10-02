import {
  deserializeProject,
  emptyManualThreats,
  resolveIdCounters,
  resolveLayers,
  resolveRiskScores,
} from '../features/persistence/serialize';
import { detectThreats } from '../core/threat-engine/detectThreats';
import { buildThreatViews } from '../core/threat-engine/buildThreatViews';
import { getThreatLibrary } from '../threat-library/loader/bundledLibrary';
import { effectiveSeverity } from '../core/model/risk';
import {
  EMPTY_PROJECT_META,
  LAYER_KEYS,
  isSuppressed,
  type ControlStatusState,
  type FrameworkView,
  type LayerData,
  type LayerKey,
  type ManualThreat,
  type ProjectMeta,
  type RiskScore,
  type Severity,
  type SuppressionState,
  type ThreatView,
} from '../core/model/types';
import type { BuildThreatReportInput } from '../features/export/threatReport';
import type { Locale } from '../i18n';

/**
 * ヘッドレス CLI の解析オプション（[[plan]] §2.49）。
 * 既定：レイヤーはノードが 1 件以上あるものすべて／framework は 'ALL'／locale は 'ja'。
 */
export interface AnalyzeOptions {
  layer?: LayerKey;
  framework?: FrameworkView;
  locale?: Locale;
}

/** レイヤー 1 件分の解析結果。`input` はレポート生成（JSON/MD）にそのまま渡す。 */
export interface LayerAnalysisResult {
  layer: LayerKey;
  threats: ThreatView[];
  input: BuildThreatReportInput;
}

/**
 * `deserializeProject` 以降の解析に必要な状態一式（[[plan]] §2.50 で `diff` と共有するため分離）。
 * レイヤーは常に全 4 層を含む（ノード数で絞り込むのは `analyzeResolvedProject` 側の責務）。
 */
export interface ResolvedProject {
  layers: Record<LayerKey, LayerData>;
  manualThreatsByLayer: Record<LayerKey, ManualThreat[]>;
  suppressions: Record<string, SuppressionState>;
  riskScores: Record<string, RiskScore> | undefined;
  controlStatuses: Record<string, ControlStatusState> | undefined;
  projectMeta: ProjectMeta;
}

/**
 * 保存済みプロジェクト JSON（`unknown`）を解析可能な状態へ変換する純粋関数。
 *
 * アプリ本体（`App.tsx`）と同じ経路（`deserializeProject` → `resolveLayers` →
 * `resolveIdCounters`）を通すことで、ブラウザと同じ結果になることを保証する。
 */
export function resolveProject(raw: unknown): ResolvedProject {
  const loaded = deserializeProject(raw);
  if (!loaded) {
    throw new Error(
      'プロジェクト JSON の形式が不正です（スキーマ検証に失敗しました）。CyberRiskScape で保存したファイルか確認してください。',
    );
  }

  const { layers: resolvedLayers } = resolveLayers(loaded);
  const { layers } = resolveIdCounters(resolvedLayers, loaded.idCounters);

  return {
    layers,
    manualThreatsByLayer: loaded.manualThreats ?? emptyManualThreats(),
    suppressions: loaded.suppressions ?? {},
    riskScores: resolveRiskScores(loaded),
    controlStatuses: loaded.controlStatuses,
    projectMeta: loaded.projectMeta ?? EMPTY_PROJECT_META,
  };
}

/**
 * 解析済み状態（`resolveProject` の出力）からレイヤーごとの脅威ビューを組み立てる純粋関数。
 * カスタムルール（IndexedDB 別保存）は含まれないため、同梱ルール
 * （`getThreatLibrary(locale).rules`）のみで評価する。
 */
export function analyzeResolvedProject(
  resolved: ResolvedProject,
  opts: AnalyzeOptions = {},
): LayerAnalysisResult[] {
  const { layers, manualThreatsByLayer, suppressions, riskScores, controlStatuses, projectMeta } =
    resolved;
  const locale = opts.locale ?? 'ja';
  const framework = opts.framework ?? 'ALL';

  const targetLayers: LayerKey[] = opts.layer
    ? [opts.layer]
    : LAYER_KEYS.filter((key) => layers[key].nodes.length > 0);

  const rules = getThreatLibrary(locale).rules;

  return targetLayers.map((layer) => {
    const layerData = layers[layer];
    const detected = detectThreats({
      nodes: layerData.nodes,
      edges: layerData.edges,
      framework,
      rules,
      boundaries: layerData.boundaries,
    });
    const threats = buildThreatViews({
      detected,
      manualThreats: manualThreatsByLayer[layer] ?? [],
      nodes: layerData.nodes,
      framework,
      suppressions,
      riskScores,
      controlStatuses,
    });
    const input: BuildThreatReportInput = {
      threats,
      nodes: layerData.nodes,
      edges: layerData.edges,
      boundaries: layerData.boundaries,
      projectMeta,
      framework,
      layer,
    };
    return { layer, threats, input };
  });
}

/**
 * 保存済みプロジェクト JSON（`unknown`）を解析し、レイヤーごとの脅威ビューを返す純粋関数。
 * `resolveProject` → `analyzeResolvedProject` の合成（従来の単発 API）。
 */
export function analyzeProject(
  raw: unknown,
  opts: AnalyzeOptions = {},
): LayerAnalysisResult[] {
  return analyzeResolvedProject(resolveProject(raw), opts);
}

/** `Severity` の強さ順位（ゲート判定のしきい値比較に使う。`diff.ts` でも再利用する）。 */
export const SEVERITY_RANK: Record<Severity, number> = { Low: 0, Medium: 1, High: 2, Critical: 3 };

/**
 * ゲート判定：抑制（受容・誤検知）されていない脅威のうち、実効 severity が
 * `failOn` 以上のものを返す（CLI の `--fail-on` が exit 1 にする対象）。
 */
export function evaluateGate(threats: ThreatView[], failOn: Severity): ThreatView[] {
  const threshold = SEVERITY_RANK[failOn];
  return threats.filter(
    (t) => !isSuppressed(t) && SEVERITY_RANK[effectiveSeverity(t)] >= threshold,
  );
}
