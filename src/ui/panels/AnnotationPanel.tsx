import { MessageSquare, Trash2, Type } from 'lucide-react';
import type { DiagramAnnotation } from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import { selectActiveNodes, useDiagramStore } from '../../core/state/diagramStore';
import { useT } from '../../i18n';

interface AnnotationPanelProps {
  annotation: DiagramAnnotation;
}

/** テキストラベル／吹き出しの編集パネル（[[plan]] §2.48）。BoundaryPanel と同じ見た目に揃える。 */
export function AnnotationPanel({ annotation }: AnnotationPanelProps) {
  const t = useT();
  const onUpdate = useDiagramStore((s) => s.updateAnnotation);
  const deleteAnnotation = useDiagramStore((s) => s.deleteAnnotation);
  const onClose = useDiagramStore((s) => s.clearSelection);
  const allNodes = useDiagramStore(selectActiveNodes);
  const isCallout = annotation.kind === 'callout';
  const Icon = isCallout ? MessageSquare : Type;

  // リンク先候補が削除済み等で候補に無い場合は「未リンク」表示にフォールバック。
  const targetValue = allNodes.some((n) => n.id === annotation.targetNodeId)
    ? (annotation.targetNodeId as string)
    : '';

  const onDelete = () => {
    deleteAnnotation(annotation.id);
    onClose();
  };

  return (
    <div className="flex flex-col h-full">
      <div className="p-6 border-b border-slate-800 bg-amber-600/5">
        <div className="flex items-center gap-2 mb-2">
          <Icon size={20} className="text-amber-500" />
          <h2 className="text-lg font-black tracking-tight">Annotation Properties</h2>
        </div>
        <p className="text-xs text-slate-500 font-bold uppercase">
          {isCallout ? 'Callout' : 'Text Label'}
        </p>
      </div>
      <div className="p-6 space-y-8 flex-1 overflow-y-auto">
        <section>
          <label
            htmlFor={`annotation-text-${annotation.id}`}
            className="text-xs font-black text-slate-500 uppercase block mb-2"
          >
            {t('panels.annotation.textLabel')}
          </label>
          <textarea
            id={`annotation-text-${annotation.id}`}
            value={annotation.text}
            onChange={(e) => onUpdate(annotation.id, 'text', e.target.value)}
            placeholder={t('panels.annotation.textPlaceholder')}
            rows={4}
            className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-amber-500 resize-none"
          />
        </section>

        {isCallout && (
          <section>
            <label
              htmlFor={`annotation-target-${annotation.id}`}
              className="text-xs font-black text-slate-500 uppercase block mb-2"
            >
              {t('panels.annotation.linkedNodeLabel')}
            </label>
            <select
              id={`annotation-target-${annotation.id}`}
              value={targetValue}
              onChange={(e) =>
                onUpdate(annotation.id, 'targetNodeId', e.target.value === '' ? undefined : e.target.value)
              }
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-amber-500"
            >
              <option value="">{t('panels.annotation.linkedNodeUnset')}</option>
              {allNodes.map((n) => {
                const prefix = n.seq != null ? `${formatElementalId('node', n.seq)}: ` : '';
                return (
                  <option key={n.id} value={n.id}>
                    {prefix}
                    {getNodeDisplayName(n)}
                  </option>
                );
              })}
            </select>
          </section>
        )}

        <button
          onClick={onDelete}
          className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-rose-600/10 text-rose-500 border border-rose-600/30 text-xs font-black hover:bg-rose-600/20"
        >
          <Trash2 size={14} />
          {t('panels.annotation.deleteButton')}
        </button>
      </div>
      <div className="p-6 border-t border-slate-800">
        <button onClick={onClose} className="w-full bg-slate-800 py-3 rounded-xl font-bold text-xs">
          {t('panels.common.close')}
        </button>
      </div>
    </div>
  );
}
