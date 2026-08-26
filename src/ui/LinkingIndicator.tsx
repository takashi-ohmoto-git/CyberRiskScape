import { Zap } from 'lucide-react';
import { useDiagramStore } from '../core/state/diagramStore';

export function LinkingIndicator() {
  const setLinkingFromId = useDiagramStore((s) => s.setLinkingFromId);

  return (
    <div className="absolute top-24 left-6 z-10 bg-rose-600 text-white px-4 py-2 rounded-xl text-xs font-black animate-pulse flex items-center gap-2 shadow-xl border border-rose-400">
      <Zap size={14} /> リンク作成中... 別のコンポーネントをクリックしてください
      <button
        onClick={() => setLinkingFromId(null)}
        className="ml-2 bg-white/20 hover:bg-white/30 px-2 py-0.5 rounded"
      >
        キャンセル
      </button>
    </div>
  );
}
