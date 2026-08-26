import { useEffect } from 'react';
import { useCustomRulesStore } from './store';

/**
 * 起動時に IndexedDB からカスタムルールライブラリをロードするフック。
 * `App.tsx` のルートで 1 回だけ呼ぶ。
 */
export function useCustomRules(): void {
  const isLoaded = useCustomRulesStore((s) => s.isLoaded);
  const load = useCustomRulesStore((s) => s.load);
  useEffect(() => {
    if (!isLoaded) void load();
  }, [isLoaded, load]);
}
