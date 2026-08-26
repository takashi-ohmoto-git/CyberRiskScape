import {
  AuthTypeSchema,
  EdgeSemanticSchema,
  EncryptionTypeSchema,
  ManagedStateSchema,
  NetworkTypeSchema,
  TrustLevelSchema,
  UserTrustAttributeSchema,
} from '../../../threat-library/schema/threatRule';
import { componentRegistry } from '../../../component-library/defaultRegistry';
import type { EdgeLeafDraft } from '../../../features/custom-rules/editor/draft';
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
  { key: 'auth', label: '認証', options: AuthTypeSchema.options },
  { key: 'network', label: 'ネットワーク', options: NetworkTypeSchema.options },
  { key: 'encryption', label: '暗号化', options: EncryptionTypeSchema.options },
  { key: 'sourceTrust', label: 'source 信頼境界', options: TrustLevelSchema.options },
  { key: 'targetTrust', label: 'target 信頼境界', options: TrustLevelSchema.options },
  { key: 'sourceManagedState', label: 'source 端末管理', options: ManagedStateSchema.options },
  { key: 'targetManagedState', label: 'target 端末管理', options: ManagedStateSchema.options },
  { key: 'sourceUserTrust', label: 'source ユーザー信頼', options: UserTrustAttributeSchema.options },
  { key: 'targetUserTrust', label: 'target ユーザー信頼', options: UserTrustAttributeSchema.options },
  { key: 'semantic', label: 'エッジ意味論', options: EdgeSemanticSchema.options },
] as const;

const TYPE_AXES = [
  { key: 'sourceType', label: 'source 型' },
  { key: 'targetType', label: 'target 型' },
] as const;

function AxisRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[120px_1fr] gap-2 items-start">
      <span className="text-[11px] text-slate-500 pt-1">{label}</span>
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
  const componentIds = componentRegistry.getAll().map((c) => c.id);
  const labelOf = (id: string) => componentRegistry.get(id)?.label ?? id;

  return (
    <div className="flex flex-col gap-2 bg-slate-900/60 border border-slate-700/70 rounded-lg p-3">
      {ENUM_AXES.map((axis) => (
        <AxisRow key={axis.key} label={axis.label}>
          <ChipGroup
            options={axis.options}
            selected={leaf[axis.key]}
            onToggle={(v) => onChange({ ...leaf, [axis.key]: toggleInArray(leaf[axis.key], v) })}
          />
        </AxisRow>
      ))}
      {TYPE_AXES.map((axis) => (
        <AxisRow key={axis.key} label={axis.label}>
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
