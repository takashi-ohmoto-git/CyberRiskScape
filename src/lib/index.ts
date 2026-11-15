/**
 * 外部のプログラムから使うための入口。
 *
 * 画面を通さずに、保存済みプロジェクトの読み書き・脅威の判定・指標の計算・差分を呼ぶ。
 * ここから出す名前と引数・戻り値は、外から使われる前提で保つ（変えるときは利用側への影響を確かめる）。
 * 実装の置き場所（`core/`・`features/`・`cli/`）が変わっても、この入口の名前は変えない。
 *
 * 同梱の知識（YAML）は Vite の `import.meta.glob` で読み込むため、利用側も Vite でビルドする。
 * どの関数も DOM・Node・IndexedDB に依存しない。
 */

// 保存形式：検証・旧形式の読み替え・書き出し
export {
  PERSISTED_PROJECT_SCHEMA_VERSION,
  PersistedProjectSchema,
  type PersistedProject,
} from '../features/persistence/schema';
export {
  deserializeProject,
  serializeProject,
  type SerializableState,
} from '../features/persistence/serialize';
export { normalizeProject } from '../features/persistence/normalizeProject';

// 脅威の判定
export {
  analyzeProject,
  analyzeResolvedProject,
  findOrphanedJudgementsInProject,
  resolveProject,
  type AnalyzeOptions,
  type LayerAnalysisResult,
  type ResolvedProject,
} from '../cli/analyze';
export {
  findOrphanedJudgements,
  type OrphanedJudgement,
  type OrphanReason,
} from '../core/threat-engine/orphanedJudgements';

// リスク評価後の重大度（評価済みなら評価の結果、未評価ならルールの重大度）
export { effectiveSeverity } from '../core/model/risk';

// 指標
export {
  BUNDLED_INDICATOR_WEIGHTS,
  computeIndicators,
  loadIndicatorWeights,
  type IndicatorWeights,
  type ModelIndicators,
} from '../features/indicators/computeIndicators';
export {
  computeAttackPathExposure,
  type AttackPathExposure,
} from '../features/indicators/computeAttackPathExposure';
export { projectIndicators, type ProjectIndicatorsReport } from '../cli/indicators';

// モデルの差分
export { diffProjects, type DiffOptions, type ProjectDiff } from '../cli/diff';

// 指摘・資産・部品
export {
  IDENTIFIER_SCHEMES,
  identityKey,
  normalizeIdentifiers,
} from '../core/model/identifierSchemes';
export {
  matchServiceScope,
  scopeContains,
  type ScopeTarget,
  type ServiceScopeEntry,
} from '../core/model/serviceScope';
export { buildAssetViews } from '../features/asset-view/buildAssetViews';
export { listBomComponents } from '../features/bom-import/listBomComponents';
export { applyVulnIntel } from '../features/vuln-intel/vulnIntel';

// モデルの型
export { LAYER_KEYS } from '../core/model/types';
export type {
  Asset,
  BomComponent,
  ControlStatusState,
  Finding,
  FindingIdentifier,
  FrameworkView,
  LayerData,
  LayerKey,
  ManualThreat,
  ProjectMeta,
  RiskScore,
  Severity,
  SuppressionState,
  ThreatView,
  VulnIntel,
} from '../core/model/types';
