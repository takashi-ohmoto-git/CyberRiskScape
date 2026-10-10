import {
  SegmentEnvironmentSchema,
  SegmentSensitiveDataSchema,
  SegmentStatusSchema,
} from '../../../threat-library/schema/threatRule';
import type { SegmentDraft } from '../../../features/custom-rules/editor/draft';
import { useT, type TranslationKey } from '../../../i18n';
import { ChipGroup, toggleInArray } from './ChipGroup';

/**
 * 所属区画（3 軸）の選択エディタ。各軸は OR、空選択 = その軸を条件にしない。
 * ノードの `segment`、エッジの `sourceSegment` / `targetSegment` で共用する
 * （`AgentAttributesEditor` と同じ位置づけ）。`label` を渡すと各行の頭に付ける（エッジの発信元／宛先の区別用）。
 */
const SEGMENT_AXES = [
  { key: 'status', labelKey: 'ruleEditor.segment.status', options: SegmentStatusSchema.options },
  { key: 'environment', labelKey: 'ruleEditor.segment.environment', options: SegmentEnvironmentSchema.options },
  { key: 'sensitiveData', labelKey: 'ruleEditor.segment.sensitiveData', options: SegmentSensitiveDataSchema.options },
] as const satisfies readonly { key: keyof SegmentDraft; labelKey: TranslationKey; options: readonly string[] }[];

export function SegmentEditor({
  value,
  onChange,
  label,
  compact = false,
}: {
  value: SegmentDraft;
  onChange: (next: SegmentDraft) => void;
  label?: string;
  /** true = ラベル列 120px（`EdgeWhenLeafEditor` に合わせる）。既定はノード側の 160px。 */
  compact?: boolean;
}) {
  const t = useT();
  return (
    <>
      {SEGMENT_AXES.map((axis) => (
        <div
          key={axis.key}
          className={`grid ${compact ? 'grid-cols-[120px_1fr]' : 'grid-cols-[160px_1fr]'} gap-2 items-start`}
        >
          <span className="text-xs text-slate-500 pt-0.5">
            {label ? `${label} ` : ''}
            {t(axis.labelKey)}
          </span>
          <ChipGroup
            options={axis.options}
            selected={value[axis.key]}
            onToggle={(v) => onChange({ ...value, [axis.key]: toggleInArray(value[axis.key], v) })}
          />
        </div>
      ))}
    </>
  );
}
