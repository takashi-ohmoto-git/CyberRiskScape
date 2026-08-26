import { create } from 'zustand';
import type { CustomRuleLibrary } from './schema';
import {
  deleteCustomRuleLibrary,
  listCustomRuleLibraries,
  saveCustomRuleLibrary,
} from './repository';

/**
 * カスタムルールライブラリ専用ストア。diagram（プロジェクト）とは独立した
 * 全プロジェクト共通の状態なので `diagramStore` には混ぜない。
 *
 * mutator はメモリ状態を更新したうえで IndexedDB へ fire-and-forget で永続化する
 * （ライブラリの追加/更新/削除は離散的な操作なのでデバウンス不要）。
 */
interface CustomRulesState {
  libraries: CustomRuleLibrary[];
  isLoaded: boolean;
  /** カスタムルール管理モーダルの開閉（UI 表示用、永続化しない）。 */
  isManagerOpen: boolean;

  /** 起動時に IndexedDB から全ライブラリをロードする（多重ロードはガード）。 */
  load: () => Promise<void>;
  openManager: () => void;
  closeManager: () => void;
  /** ライブラリを追加/置換（同 id があれば置換）。 */
  upsertLibrary: (lib: CustomRuleLibrary) => void;
  deleteLibrary: (id: string) => void;
  /** 有効/無効を切り替える。 */
  toggleLibrary: (id: string) => void;
}

function persist(lib: CustomRuleLibrary): void {
  void saveCustomRuleLibrary(lib).catch((e) =>
    console.error('[custom-rules] save failed', e),
  );
}

export const useCustomRulesStore = create<CustomRulesState>((set, get) => ({
  libraries: [],
  isLoaded: false,
  isManagerOpen: false,

  openManager: () => set({ isManagerOpen: true }),
  closeManager: () => set({ isManagerOpen: false }),

  load: async () => {
    if (get().isLoaded) return;
    try {
      const libraries = await listCustomRuleLibraries();
      set({ libraries, isLoaded: true });
    } catch (e) {
      console.error('[custom-rules] load failed; starting empty', e);
      set({ isLoaded: true });
    }
  },

  upsertLibrary: (lib) => {
    const next = { ...lib, updatedAt: Date.now() };
    set((s) => {
      const exists = s.libraries.some((l) => l.id === next.id);
      const libraries = exists
        ? s.libraries.map((l) => (l.id === next.id ? next : l))
        : [...s.libraries, next];
      return { libraries };
    });
    persist(next);
  },

  deleteLibrary: (id) => {
    set((s) => ({ libraries: s.libraries.filter((l) => l.id !== id) }));
    void deleteCustomRuleLibrary(id).catch((e) =>
      console.error('[custom-rules] delete failed', e),
    );
  },

  toggleLibrary: (id) => {
    const target = get().libraries.find((l) => l.id === id);
    if (!target) return;
    const next = { ...target, enabled: !target.enabled, updatedAt: Date.now() };
    set((s) => ({ libraries: s.libraries.map((l) => (l.id === id ? next : l)) }));
    persist(next);
  },
}));

/** 全プロジェクト共通のカスタムライブラリ一覧。 */
export const selectCustomLibraries = (s: CustomRulesState): CustomRuleLibrary[] => s.libraries;
