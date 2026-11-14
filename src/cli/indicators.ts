import { analyzeResolvedProject, resolveProject } from './analyze';
import {
  computeIndicators,
  type IndicatorWeights,
  type ModelIndicators,
} from '../features/indicators/computeIndicators';
import { LAYER_KEYS, type BusinessCriticality, type ProjectLifecycle } from '../core/model/types';

/**
 * `indicators`：脅威モデル単位の指標（設定率・検討率・実装済みの割合と、3 つをまとめた値）を出す。
 * 全レイヤー・全フレームワークの脅威を対象に、同梱ルールのみで評価する（カスタムルールの脅威は入らない）。
 * プロジェクトの ID と組織上の属性を添えるので、複数の脅威モデルの結果を並べて集計できる。
 */
export interface ProjectIndicatorsReport {
  schemaVersion: 1;
  projectId?: string;
  projectName?: string;
  organizationName?: string;
  organizationCode?: string;
  criticality?: BusinessCriticality;
  lifecycle?: ProjectLifecycle;
  /** 3 つの指標と、計算に使った重み（`weights`）。 */
  indicators: ModelIndicators;
}

export function projectIndicators(raw: unknown, weights?: IndicatorWeights): ProjectIndicatorsReport {
  const resolved = resolveProject(raw);
  const threats = LAYER_KEYS.flatMap((layer) =>
    analyzeResolvedProject(resolved, { layer, framework: 'ALL' }).flatMap((r) => r.threats),
  );
  const meta = resolved.projectMeta;
  return {
    schemaVersion: 1,
    ...(resolved.projectId ? { projectId: resolved.projectId } : {}),
    ...(meta.name ? { projectName: meta.name } : {}),
    ...(meta.organizationName ? { organizationName: meta.organizationName } : {}),
    ...(meta.organizationCode ? { organizationCode: meta.organizationCode } : {}),
    ...(meta.criticality ? { criticality: meta.criticality } : {}),
    ...(meta.lifecycle ? { lifecycle: meta.lifecycle } : {}),
    indicators: computeIndicators(threats, weights),
  };
}
