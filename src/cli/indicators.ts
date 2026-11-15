import { analyzeResolvedProject, resolveProject } from './analyze';
import {
  computeIndicators,
  type IndicatorWeights,
  type ModelIndicators,
} from '../features/indicators/computeIndicators';
import {
  computeAttackPathExposure,
  type AttackPathExposure,
} from '../features/indicators/computeAttackPathExposure';
import { LAYER_KEYS, type BusinessCriticality, type ProjectLifecycle } from '../core/model/types';
import { getThreatLibrary } from '../threat-library/loader/bundledLibrary';
import { version as APP_VERSION } from '../../package.json';

/**
 * `indicators`：脅威モデル単位の指標（設定率・検討率・実装済みの割合と、3 つをまとめた値）を出す。
 * 全レイヤー・全フレームワークの脅威を対象に、同梱ルールのみで評価する（カスタムルールの脅威は入らない）。
 * プロジェクトの ID と組織上の属性を添えるので、複数の脅威モデルの結果を並べて集計できる。
 */
export interface ProjectIndicatorsReport {
  schemaVersion: 1;
  /** 計算したアプリの版。 */
  appVersion: string;
  /** 判定に使った同梱ルールの件数（ルールが増えたことによる値の変化を、取り組みの変化と見分けるため）。 */
  ruleCount: number;
  projectId?: string;
  projectName?: string;
  organizationName?: string;
  organizationCode?: string;
  criticality?: BusinessCriticality;
  lifecycle?: ProjectLifecycle;
  /** 3 つの指標と、計算に使った重み（`weights`）。 */
  indicators: ModelIndicators;
  /**
   * 重要資産に届く攻撃経路上の未対策の脅威（「総合」には入れない別枠の指標）。
   * 図に攻撃者（AI エージェント攻撃者）が無ければ null（評価できない）。
   */
  attackPathExposure: AttackPathExposure | null;
}

export function projectIndicators(raw: unknown, weights?: IndicatorWeights): ProjectIndicatorsReport {
  const resolved = resolveProject(raw);
  const results = LAYER_KEYS.flatMap((layer) => analyzeResolvedProject(resolved, { layer, framework: 'ALL' }));
  const threats = results.flatMap((r) => r.threats);
  const meta = resolved.projectMeta;
  return {
    schemaVersion: 1,
    appVersion: APP_VERSION,
    ruleCount: getThreatLibrary('ja').rules.length,
    ...(resolved.projectId ? { projectId: resolved.projectId } : {}),
    ...(meta.name ? { projectName: meta.name } : {}),
    ...(meta.organizationName ? { organizationName: meta.organizationName } : {}),
    ...(meta.organizationCode ? { organizationCode: meta.organizationCode } : {}),
    ...(meta.criticality ? { criticality: meta.criticality } : {}),
    ...(meta.lifecycle ? { lifecycle: meta.lifecycle } : {}),
    indicators: computeIndicators(threats, weights),
    attackPathExposure: computeAttackPathExposure(
      results.map((r) => ({ ...r.input, layer: r.layer, threats: r.threats })),
      weights,
    ),
  };
}
