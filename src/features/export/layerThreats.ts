import { detectThreats } from '../../core/threat-engine/detectThreats';
import { buildThreatViews } from '../../core/threat-engine/buildThreatViews';
import type {
  FrameworkView,
  LayerData,
  LayerKey,
  ManualThreat,
  ProjectMeta,
  ThreatView,
} from '../../core/model/types';
import type { MergedRules } from '../custom-rules/mergeRules';
import type { BuildThreatReportInput } from './threatReport';

type ViewArgs = Parameters<typeof buildThreatViews>[0];

/** レイヤー別脅威の算出に必要なストア状態（DiagramState の部分集合）。 */
export interface LayerThreatsState {
  layers: Record<LayerKey, LayerData>;
  manualThreats: Record<LayerKey, ManualThreat[]>;
  suppressions: ViewArgs['suppressions'];
  riskScores: ViewArgs['riskScores'];
  controlStatuses: ViewArgs['controlStatuses'];
  activeFramework: FrameworkView;
  projectMeta: ProjectMeta;
}

export interface LayerThreats {
  layer: LayerKey;
  threats: ThreatView[];
  /** `buildThreatReport` へそのまま渡せる入力。 */
  input: BuildThreatReportInput;
}

/**
 * 指定レイヤーごとに脅威を算出する。App.tsx（アクティブレイヤー）と同じ経路
 * （detectThreats → buildThreatViews、カスタムルール込み・現在の framework）を
 * 非アクティブレイヤーにも適用する。
 */
export function computeLayerThreats(
  state: LayerThreatsState,
  merged: MergedRules,
  layerKeys: readonly LayerKey[],
): LayerThreats[] {
  return layerKeys.map((layer) => {
    const { nodes, edges, boundaries } = state.layers[layer];
    const threats = buildThreatViews({
      detected: detectThreats({
        nodes,
        edges,
        framework: state.activeFramework,
        rules: merged.rules,
        boundaries,
      }),
      manualThreats: state.manualThreats[layer],
      nodes,
      framework: state.activeFramework,
      suppressions: state.suppressions,
      riskScores: state.riskScores,
      controlStatuses: state.controlStatuses,
      customRuleIds: merged.customRuleIds,
    });
    return {
      layer,
      threats,
      input: {
        threats,
        nodes,
        edges,
        boundaries,
        projectMeta: state.projectMeta,
        framework: state.activeFramework,
        layer,
      },
    };
  });
}
