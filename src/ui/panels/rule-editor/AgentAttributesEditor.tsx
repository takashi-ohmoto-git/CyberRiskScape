import {
  AgencyLevelSchema,
  BlastRadiusSchema,
  IdentityTierSchema,
} from '../../../threat-library/schema/threatRule';
import type { AgentAttributesDraft } from '../../../features/custom-rules/editor/draft';
import { useT, type TranslationKey } from '../../../i18n';
import { ChipGroup, toggleInArray } from './ChipGroup';

/**
 * エージェント特有属性（3 軸）の選択エディタ。各軸は OR、空選択 = その軸を条件にしない。
 * `appliesTo.agentAttributes` と `conditions[].when.agentAttributes` の双方で共用する
 * （`AttackSurfaceEditor` と同じ位置づけ）。
 */
const AGENT_AXES = [
  { key: 'agency', labelKey: 'ruleEditor.nodeTarget.agentAxis.agency', options: AgencyLevelSchema.options },
  { key: 'blastRadius', labelKey: 'ruleEditor.nodeTarget.agentAxis.blastRadius', options: BlastRadiusSchema.options },
  { key: 'identityTier', labelKey: 'ruleEditor.nodeTarget.agentAxis.identityTier', options: IdentityTierSchema.options },
] as const satisfies readonly { key: keyof AgentAttributesDraft; labelKey: TranslationKey; options: readonly string[] }[];

export function AgentAttributesEditor({
  value,
  onChange,
}: {
  value: AgentAttributesDraft;
  onChange: (next: AgentAttributesDraft) => void;
}) {
  const t = useT();
  return (
    <>
      {AGENT_AXES.map((axis) => (
        <div key={axis.key} className="grid grid-cols-[160px_1fr] gap-2 items-start">
          <span className="text-xs text-slate-500 pt-0.5">{t(axis.labelKey)}</span>
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
