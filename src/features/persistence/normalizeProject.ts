import {
  deserializeProject,
  resolveIdCounters,
  resolveLayers,
  resolveRiskScores,
} from './serialize';
import type { PersistedProject } from './schema';

/**
 * 保存済みプロジェクト JSON（`unknown`）を、現行の保存形式に直して返す純粋関数。
 * 検証に失敗したら `null`。
 *
 * 直すのは旧形式だけ：
 * - トップレベルの `nodes`・`edges`・`boundaries` → `layers`（L1）
 * - `dreadScores` → `riskScores`
 * - `seq` の無い要素への採番と `idCounters`
 * - 旧 framework 値（`deserializeProject` が行う）
 *
 * それ以外の項目は組み替えずにそのまま通す（保存形式に項目を足しても、ここを直さずに通る）。
 * `updatedAt` は変えないので、同じ入力からは同じ結果になり、2 回かけても変わらない。
 */
export function normalizeProject(raw: unknown): PersistedProject | null {
  const loaded = deserializeProject(raw);
  if (!loaded) return null;
  const { nodes: _nodes, edges: _edges, boundaries: _boundaries, dreadScores: _dreadScores, ...rest } = loaded;
  const resolved = resolveLayers(loaded);
  const { layers, idCounters } = resolveIdCounters(resolved.layers, loaded.idCounters);
  const riskScores = resolveRiskScores(loaded);
  return {
    ...rest,
    layers,
    activeLayer: resolved.activeLayer,
    idCounters,
    ...(riskScores ? { riskScores } : {}),
  };
}
