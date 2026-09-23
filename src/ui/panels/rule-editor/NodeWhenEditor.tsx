import {
  AuthProviderRoleSchema,
  IdentityProviderKindSchema,
} from '../../../threat-library/schema/threatRule';
import { getComponentRegistry } from '../../../component-library/defaultRegistry';
import type { NodeWhenDraft } from '../../../features/custom-rules/editor/draft';
import { useLocale, useT } from '../../../i18n';
import { ChipGroup, toggleInArray } from './ChipGroup';
import { AttackSurfaceEditor } from './AttackSurfaceEditor';
import { AgentAttributesEditor } from './AgentAttributesEditor';

/**
 * ノード条件（`conditions[].when`）の編集。Edge 側の `EdgeWhenLeafEditor` に対応する
 * ノード版で、③ severity 分岐から使う。
 *
 * `appliesTo` のノード側絞り込み軸のミラーだが、**接続要件は持たない**
 * （接続は「発火するか」の問いで、段階分けの軸ではない——`NodeWhenSchema` 参照）。
 * `nodeType` は `appliesTo.anyOf` で複数型を対象にしたルールの絞り込みに効く。
 */
function AxisRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[160px_1fr] gap-2 items-start">
      <span className="text-xs text-slate-500 pt-0.5">{label}</span>
      {children}
    </div>
  );
}

export function NodeWhenEditor({
  when,
  onChange,
}: {
  when: NodeWhenDraft;
  onChange: (next: NodeWhenDraft) => void;
}) {
  const t = useT();
  const [locale] = useLocale();
  const registry = getComponentRegistry(locale);
  const componentIds = registry.getAll().map((c) => c.id);
  const labelOf = (id: string) => registry.get(id)?.label ?? id;

  return (
    <div className="flex flex-col gap-2 bg-slate-900/60 border border-slate-700/70 rounded-lg p-3">
      <AxisRow label={t('ruleEditor.nodeWhen.nodeTypeLabel')}>
        <ChipGroup
          options={componentIds}
          selected={when.nodeType}
          optionLabel={labelOf}
          onToggle={(v) => onChange({ ...when, nodeType: toggleInArray(when.nodeType, v) })}
        />
      </AxisRow>

      <AxisRow label={t('ruleEditor.nodeTarget.identityProviderKindLabel')}>
        <ChipGroup
          options={IdentityProviderKindSchema.options}
          selected={when.identityProviderKind}
          onToggle={(v) =>
            onChange({ ...when, identityProviderKind: toggleInArray(when.identityProviderKind, v) })
          }
        />
      </AxisRow>

      <AxisRow label={t('ruleEditor.nodeTarget.authProviderRoleLabel')}>
        <ChipGroup
          options={AuthProviderRoleSchema.options}
          selected={when.authProviderRole}
          onToggle={(v) =>
            onChange({ ...when, authProviderRole: toggleInArray(when.authProviderRole, v) })
          }
        />
      </AxisRow>

      <AgentAttributesEditor
        value={when.agentAttributes}
        onChange={(agentAttributes) => onChange({ ...when, agentAttributes })}
      />

      <AxisRow label={t('ruleEditor.nodeWhen.attackSurfaceLabel')}>
        <AttackSurfaceEditor
          value={when.attackSurface}
          onChange={(attackSurface) => onChange({ ...when, attackSurface })}
        />
      </AxisRow>
    </div>
  );
}
