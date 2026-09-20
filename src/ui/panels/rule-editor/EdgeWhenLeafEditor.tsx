import {
  AuthTypeSchema,
  EdgeSemanticSchema,
  EncryptionTypeSchema,
  ManagedStateSchema,
  NetworkTypeSchema,
  TrustLevelSchema,
  UserTrustAttributeSchema,
} from '../../../threat-library/schema/threatRule';
import { getComponentRegistry } from '../../../component-library/defaultRegistry';
import type { EdgeLeafDraft } from '../../../features/custom-rules/editor/draft';
import { useLocale, useT, type TranslationKey } from '../../../i18n';
import { ChipGroup, toggleInArray } from './ChipGroup';

/**
 * Edge リーフ（5+ 軸）の編集（§2.25 Phase D / ②マッチ条件・③分岐で共用）。
 *
 * - enum 選択肢はスキーマの `.options` から導出（手書きとのドリフトを防ぐ）。
 * - source/target 型候補は `componentRegistry` から取得（カスタム型も列挙）。
 * - 各軸は OR、軸間は AND。全軸未選択のリーフは保存時にスキーマが弾く。
 */

/** 文字列 enum 軸の設定（型軸は別扱い）。 */
const ENUM_AXES = [
  { key: 'auth', labelKey: 'ruleEditor.edgeLeaf.axis.auth', options: AuthTypeSchema.options },
  { key: 'network', labelKey: 'ruleEditor.edgeLeaf.axis.network', options: NetworkTypeSchema.options },
  { key: 'encryption', labelKey: 'ruleEditor.edgeLeaf.axis.encryption', options: EncryptionTypeSchema.options },
  { key: 'sourceTrust', labelKey: 'ruleEditor.edgeLeaf.axis.sourceTrust', options: TrustLevelSchema.options },
  { key: 'targetTrust', labelKey: 'ruleEditor.edgeLeaf.axis.targetTrust', options: TrustLevelSchema.options },
  { key: 'sourceManagedState', labelKey: 'ruleEditor.edgeLeaf.axis.sourceManagedState', options: ManagedStateSchema.options },
  { key: 'targetManagedState', labelKey: 'ruleEditor.edgeLeaf.axis.targetManagedState', options: ManagedStateSchema.options },
  { key: 'sourceUserTrust', labelKey: 'ruleEditor.edgeLeaf.axis.sourceUserTrust', options: UserTrustAttributeSchema.options },
  { key: 'targetUserTrust', labelKey: 'ruleEditor.edgeLeaf.axis.targetUserTrust', options: UserTrustAttributeSchema.options },
  { key: 'semantic', labelKey: 'ruleEditor.edgeLeaf.axis.semantic', options: EdgeSemanticSchema.options },
] as const satisfies readonly { key: string; labelKey: TranslationKey; options: readonly string[] }[];

const TYPE_AXES = [
  { key: 'sourceType', labelKey: 'ruleEditor.edgeLeaf.axis.sourceType' },
  { key: 'targetType', labelKey: 'ruleEditor.edgeLeaf.axis.targetType' },
] as const satisfies readonly { key: string; labelKey: TranslationKey }[];

function AxisRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[120px_1fr] gap-2 items-start">
      <span className="text-xs text-slate-500 pt-1">{label}</span>
      {children}
    </div>
  );
}

export function EdgeWhenLeafEditor({
  leaf,
  onChange,
}: {
  leaf: EdgeLeafDraft;
  onChange: (next: EdgeLeafDraft) => void;
}) {
  const t = useT();
  const [locale] = useLocale();
  const registry = getComponentRegistry(locale);
  const componentIds = registry.getAll().map((c) => c.id);
  const labelOf = (id: string) => registry.get(id)?.label ?? id;

  return (
    <div className="flex flex-col gap-2 bg-slate-900/60 border border-slate-700/70 rounded-lg p-3">
      {ENUM_AXES.map((axis) => (
        <AxisRow key={axis.key} label={t(axis.labelKey)}>
          <ChipGroup
            options={axis.options}
            selected={leaf[axis.key]}
            onToggle={(v) => onChange({ ...leaf, [axis.key]: toggleInArray(leaf[axis.key], v) })}
          />
        </AxisRow>
      ))}
      {TYPE_AXES.map((axis) => (
        <AxisRow key={axis.key} label={t(axis.labelKey)}>
          <ChipGroup
            options={componentIds}
            selected={leaf[axis.key]}
            optionLabel={labelOf}
            onToggle={(v) => onChange({ ...leaf, [axis.key]: toggleInArray(leaf[axis.key], v) })}
          />
        </AxisRow>
      ))}
    </div>
  );
}
