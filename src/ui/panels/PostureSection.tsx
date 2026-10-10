import { ClipboardCheck } from 'lucide-react';
import type { DiagramNode, NodePosture, PostureEnumKey } from '../../core/model/types';
import { POSTURE_ENUM_KEYS, POSTURE_FIELD_VALUES } from '../../core/model/types';
import { getComponentRegistry } from '../../component-library/defaultRegistry';
import { useDiagramStore } from '../../core/state/diagramStore';
import { useLocale, useT, type TranslationKey } from '../../i18n';

const LABEL_CLASS = 'text-xs font-black text-slate-500 uppercase block mb-1.5';
const FIELD_CLASS =
  'w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500';

/** 空の項目を落とした posture を返す。全項目が空なら undefined（属性ごと削除）。 */
function compact(value: NodePosture): NodePosture | undefined {
  const entries = Object.entries(value).filter(([, v]) => v !== undefined && v !== '');
  return entries.length === 0 ? undefined : (Object.fromEntries(entries) as NodePosture);
}

/**
 * 運用状況（Posture）の入力欄。型が宣言したグループ（コンポーネントライブラリの `posture:`）の
 * 項目だけを出す。最終点検日・点検メモは全型で入力できる。
 * 未入力の項目は、脅威エンジンが対策なしとして評価する。
 */
export function PostureSection({ node }: { node: DiagramNode }) {
  const t = useT();
  const [locale] = useLocale();
  const registry = getComponentRegistry(locale);
  const onUpdate = useDiagramStore((s) => s.updateNode);

  const fields = POSTURE_ENUM_KEYS.filter((k) => registry.acceptsPostureField(node.type, k));
  const posture = node.posture ?? {};

  const set = (patch: Partial<NodePosture>) => {
    onUpdate(node.id, 'posture', compact({ ...posture, ...patch }));
  };

  const setEnum = (key: PostureEnumKey, raw: string) =>
    set({ [key]: raw === '' ? undefined : raw } as Partial<NodePosture>);

  return (
    <div className="bg-slate-800/50 p-4 rounded-2xl border border-slate-700">
      <h3 className="text-xs font-bold text-slate-300 mb-2 flex items-center gap-2">
        <ClipboardCheck size={14} className="text-blue-500" /> {t('panels.posture.title')}
        {node.posture && (
          <span className="text-xs font-black px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300">
            {t('panels.posture.configured')}
          </span>
        )}
      </h3>
      <p className="text-xs text-slate-500 mb-4 leading-relaxed">{t('panels.posture.note')}</p>
      <div className="space-y-3">
        {fields.map((key) => (
          <div key={key}>
            <label htmlFor={`node-posture-${key}-${node.id}`} className={LABEL_CLASS}>
              {t(`panels.posture.field.${key}` as TranslationKey)}
            </label>
            <select
              id={`node-posture-${key}-${node.id}`}
              value={posture[key] ?? ''}
              onChange={(e) => setEnum(key, e.target.value)}
              className={FIELD_CLASS}
            >
              <option value="">{t('panels.node.unset')}</option>
              {POSTURE_FIELD_VALUES[key].map((val) => (
                <option key={val} value={val}>
                  {t(`panels.posture.value.${key}.${val}` as TranslationKey)}
                </option>
              ))}
            </select>
          </div>
        ))}
        <div>
          <label htmlFor={`node-posture-reviewed-${node.id}`} className={LABEL_CLASS}>
            {t('panels.posture.lastReviewedAt')}
          </label>
          <input
            id={`node-posture-reviewed-${node.id}`}
            type="date"
            value={posture.lastReviewedAt ?? ''}
            onChange={(e) => set({ lastReviewedAt: e.target.value || undefined })}
            className={FIELD_CLASS}
          />
        </div>
        <div>
          <label htmlFor={`node-posture-note-${node.id}`} className={LABEL_CLASS}>
            {t('panels.posture.reviewNote')}
          </label>
          <textarea
            id={`node-posture-note-${node.id}`}
            value={posture.reviewNote ?? ''}
            maxLength={2000}
            rows={2}
            onChange={(e) => set({ reviewNote: e.target.value || undefined })}
            className={`${FIELD_CLASS} resize-y`}
          />
        </div>
      </div>
    </div>
  );
}
