import { useEffect } from 'react';
import { useDiagramStore } from './diagramStore';

/** テキスト編集中（native undo に委ねる要素）かどうか。 */
function isTextEditing(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || target.isContentEditable;
}

/**
 * グローバル keydown を購読し、Undo / Redo を実行するフック。
 * App ルートで 1 度だけ呼ぶこと。
 *
 * - Ctrl/Cmd+Z … Undo
 * - Ctrl/Cmd+Shift+Z / Ctrl+Y … Redo
 * - input / textarea / contentEditable にフォーカス中はブラウザの
 *   テキスト native undo に委ね、横取りしない。
 */
export function useUndoRedo(): void {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey)) return;
      const key = e.key.toLowerCase();
      const isUndo = key === 'z' && !e.shiftKey;
      const isRedo = (key === 'z' && e.shiftKey) || key === 'y';
      if (!isUndo && !isRedo) return;
      if (isTextEditing(e.target)) return;

      e.preventDefault();
      const store = useDiagramStore.getState();
      if (isRedo) store.redo();
      else store.undo();
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);
}
