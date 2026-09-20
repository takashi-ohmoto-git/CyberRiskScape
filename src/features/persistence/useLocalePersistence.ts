import { useEffect } from 'react';
import { getLocale, setLocale, subscribeLocale } from '../../i18n';
import { getSavedLocale, setSavedLocale } from './locale';

/**
 * 起動時に保存済みロケールを復元し、その後の切替を IndexedDB へ保存するフック。
 * `App.tsx` のルートで 1 回だけ呼ぶ。
 *
 * 永続化の知識を features 側に閉じ込め、`i18n`（core 相当）からは
 * 永続化層を参照しない（依存方向を core ← features に保つため）。
 */
export function useLocalePersistence(): void {
  useEffect(() => {
    let cancelled = false;

    void (async () => {
      try {
        const saved = await getSavedLocale();
        if (cancelled || saved === null) return;
        setLocale(saved);
      } catch (e) {
        // 復元に失敗しても既定ロケールで動作は続行する。
        console.error('[locale] restore failed', e);
      }
    })();

    const unsubscribe = subscribeLocale(() => {
      void setSavedLocale(getLocale()).catch((e) => {
        console.error('[locale] save failed', e);
      });
    });

    return () => {
      cancelled = true;
      unsubscribe();
    };
  }, []);
}
