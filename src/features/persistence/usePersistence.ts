import { useEffect } from 'react';
import { useDiagramStore } from '../../core/state/diagramStore';
import { loadProject, saveProject } from './repository';
import { hydrateFromPersisted } from './hydrate';
import { type SerializableState } from './serialize';

const DEBOUNCE_MS = 500;

/**
 * 起動時に IndexedDB からプロジェクトを復元し、その後の編集を
 * デバウンス auto-save するフック。`App.tsx` のルートで 1 回だけ呼ぶ。
 *
 * - ハイドレート完了までは `isHydrated = false`。`App.tsx` 側で描画ゲート。
 * - 保存対象は `nodes` / `edges` / `boundaries` / `activeFramework` のみ。
 *   選択状態・transient な相互作用 state は意図的に保存しない。
 * - アンマウント時は pending タイマーを fire-and-forget でフラッシュ。
 */
export function usePersistence(): void {
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let pendingSnapshot: SerializableState | null = null;

    const flush = () => {
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
      if (pendingSnapshot === null) return;
      const snapshot = pendingSnapshot;
      pendingSnapshot = null;
      void saveProject(snapshot).catch((e) => {
        console.error('[persistence] save failed', e);
      });
    };

    void (async () => {
      try {
        const loaded = await loadProject();
        if (cancelled) return;
        if (loaded) {
          hydrateFromPersisted(loaded);
        } else {
          useDiagramStore.getState().markHydrated();
        }
      } catch (e) {
        console.error('[persistence] load failed; starting with defaults', e);
        if (!cancelled) useDiagramStore.getState().markHydrated();
      }
    })();

    const unsubscribe = useDiagramStore.subscribe((state, prev) => {
      if (!state.isHydrated) return;
      const changed =
        state.layers !== prev.layers ||
        state.activeLayer !== prev.activeLayer ||
        state.idCounters !== prev.idCounters ||
        state.activeFramework !== prev.activeFramework ||
        state.disabledLibraryIds !== prev.disabledLibraryIds ||
        state.projectMeta !== prev.projectMeta ||
        state.manualThreats !== prev.manualThreats ||
        state.suppressions !== prev.suppressions ||
        state.dreadScores !== prev.dreadScores ||
        state.controlStatuses !== prev.controlStatuses;
      if (!changed) return;
      pendingSnapshot = {
        layers: state.layers,
        activeLayer: state.activeLayer,
        idCounters: state.idCounters,
        activeFramework: state.activeFramework,
        disabledLibraryIds: state.disabledLibraryIds,
        projectMeta: state.projectMeta,
        manualThreats: state.manualThreats,
        suppressions: state.suppressions,
        dreadScores: state.dreadScores,
        controlStatuses: state.controlStatuses,
      };
      if (timer !== null) clearTimeout(timer);
      timer = setTimeout(flush, DEBOUNCE_MS);
    });

    return () => {
      cancelled = true;
      unsubscribe();
      flush();
    };
  }, []);
}
