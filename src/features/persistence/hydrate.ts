import { useDiagramStore } from '../../core/state/diagramStore';
import { emptyManualThreats, resolveIdCounters, resolveLayers } from './serialize';
import type { PersistedProject } from './schema';

/**
 * 検証済み `PersistedProject` を Zustand ストアへハイドレートする。
 *
 * 起動時の IndexedDB 復元（[[usePersistence]]）と、フォルダからのファイル読込
 * （[[fileSystem]]）の両方で同一経路を使うために抽出した共通関数。
 * レイヤー正規化 → ElementalID 採番カウンタ復元 → `store.hydrate` の順。
 */
export function hydrateFromPersisted(loaded: PersistedProject): void {
  const resolved = resolveLayers(loaded);
  const { layers, idCounters } = resolveIdCounters(resolved.layers, loaded.idCounters);
  useDiagramStore.getState().hydrate({
    layers,
    activeLayer: resolved.activeLayer,
    idCounters,
    activeFramework: loaded.activeFramework,
    disabledLibraryIds: loaded.disabledLibraryIds,
    projectMeta: loaded.projectMeta,
    manualThreats: loaded.manualThreats ?? emptyManualThreats(),
    suppressions: loaded.suppressions,
    dreadScores: loaded.dreadScores,
    controlStatuses: loaded.controlStatuses,
  });
}
