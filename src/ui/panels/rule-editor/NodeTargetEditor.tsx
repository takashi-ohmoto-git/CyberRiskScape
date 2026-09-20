import {
  AgencyLevelSchema,
  BlastRadiusSchema,
  ConnectionDirectionSchema,
  IdentityTierSchema,
} from '../../../threat-library/schema/threatRule';
import { getComponentRegistry } from '../../../component-library/defaultRegistry';
import type {
  AgentAttributesDraft,
  ConnectionDraft,
  NodeDraft,
} from '../../../features/custom-rules/editor/draft';
import { useLocale, useT, type TranslationKey } from '../../../i18n';
import { ChipGroup, toggleInArray } from './ChipGroup';
import { AttackSurfaceEditor } from './AttackSurfaceEditor';

/**
 * ②マッチ条件（Node ルール）（§2.25 Phase D / D3）。
 *
 * nodeType（単一 / anyOf）＋ connection（接続要件・ピア攻撃面）＋ attackSurface ＋
 * agentAttributes を編集する。各条件は AND（連結）で評価される。
 */
const inputCls =
  'bg-slate-800 border border-slate-700 rounded-md px-2 py-1 text-[12px] text-slate-100 focus:outline-none focus:border-blue-500';

const AGENT_AXES = [
  { key: 'agency', labelKey: 'ruleEditor.nodeTarget.agentAxis.agency', options: AgencyLevelSchema.options },
  { key: 'blastRadius', labelKey: 'ruleEditor.nodeTarget.agentAxis.blastRadius', options: BlastRadiusSchema.options },
  { key: 'identityTier', labelKey: 'ruleEditor.nodeTarget.agentAxis.identityTier', options: IdentityTierSchema.options },
] as const satisfies readonly { key: keyof AgentAttributesDraft; labelKey: TranslationKey; options: readonly string[] }[];

function SubLabel({ children }: { children: React.ReactNode }) {
  return <span className="text-xs text-slate-500">{children}</span>;
}

export function NodeTargetEditor({
  node,
  onChange,
}: {
  node: NodeDraft;
  onChange: (next: NodeDraft) => void;
}) {
  const t = useT();
  const [locale] = useLocale();
  const registry = getComponentRegistry(locale);
  const componentIds = registry.getAll().map((c) => c.id);
  const labelOf = (id: string) => registry.get(id)?.label ?? id;
  const setConn = (next: ConnectionDraft) => onChange({ ...node, connection: next });

  return (
    <div className="flex flex-col gap-4">
      {/* 対象型 */}
      <div className="flex flex-col gap-2">
        <div className="flex gap-1.5">
          <button
            type="button"
            onClick={() => onChange({ ...node, mode: 'single' })}
            className={modeCls(node.mode === 'single')}
          >
            {t('ruleEditor.nodeTarget.mode.single')}
          </button>
          <button
            type="button"
            onClick={() => onChange({ ...node, mode: 'anyOf' })}
            className={modeCls(node.mode === 'anyOf')}
          >
            {t('ruleEditor.nodeTarget.mode.anyOf')}
          </button>
        </div>
        {node.mode === 'single' ? (
          <select
            value={node.nodeTypes[0] ?? ''}
            onChange={(e) => onChange({ ...node, nodeTypes: e.target.value ? [e.target.value] : [] })}
            className={inputCls}
          >
            <option value="">{t('ruleEditor.nodeTarget.selectType')}</option>
            {componentIds.map((id) => (
              <option key={id} value={id}>
                {labelOf(id)}（{id}）
              </option>
            ))}
          </select>
        ) : (
          <div className="flex flex-col gap-1">
            <SubLabel>{t('ruleEditor.nodeTarget.selectTwoOrMore')}</SubLabel>
            <ChipGroup
              options={componentIds}
              selected={node.nodeTypes}
              optionLabel={labelOf}
              onToggle={(v) => onChange({ ...node, nodeTypes: toggleInArray(node.nodeTypes, v) })}
            />
          </div>
        )}
      </div>

      {/* 接続要件 */}
      <div className="flex flex-col gap-2 border-t border-slate-700/60 pt-3">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={node.connection.enabled}
            onChange={(e) => setConn({ ...node.connection, enabled: e.target.checked })}
            className="accent-blue-600"
          />
          <span className="text-[12px] font-bold text-slate-200">{t('ruleEditor.nodeTarget.connectionEnabled')}</span>
          <span className="text-[10px] text-slate-500">{t('ruleEditor.nodeTarget.connectionDefault')}</span>
        </label>

        {node.connection.enabled && (
          <div className="flex flex-col gap-2 pl-6">
            <div className="flex gap-1.5">
              <button
                type="button"
                onClick={() => setConn({ ...node.connection, required: true })}
                className={modeCls(node.connection.required)}
              >
                {t('ruleEditor.nodeTarget.connectionRequired')}
              </button>
              <button
                type="button"
                onClick={() => setConn({ ...node.connection, required: false })}
                className={modeCls(!node.connection.required)}
                title={t('ruleEditor.nodeTarget.connectionIntrinsicTitle')}
              >
                {t('ruleEditor.nodeTarget.connectionIntrinsic')}
              </button>
            </div>

            {node.connection.required && (
              <>
                <div className="grid grid-cols-[120px_1fr] gap-2 items-center">
                  <SubLabel>{t('ruleEditor.nodeTarget.direction')}</SubLabel>
                  <select
                    value={node.connection.direction}
                    onChange={(e) =>
                      setConn({
                        ...node.connection,
                        direction: e.target.value as ConnectionDraft['direction'],
                      })
                    }
                    className={inputCls}
                  >
                    {ConnectionDirectionSchema.options.map((d) => (
                      <option key={d} value={d}>
                        {d}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="flex flex-col gap-1">
                  <SubLabel>{t('ruleEditor.nodeTarget.peerTypeLabel')}</SubLabel>
                  <ChipGroup
                    options={componentIds}
                    selected={node.connection.peerType}
                    optionLabel={labelOf}
                    onToggle={(v) =>
                      setConn({ ...node.connection, peerType: toggleInArray(node.connection.peerType, v) })
                    }
                  />
                </div>
                <div className="flex flex-col gap-1">
                  <SubLabel>{t('ruleEditor.nodeTarget.peerAttackSurfaceLabel')}</SubLabel>
                  <AttackSurfaceEditor
                    value={node.connection.peerAttackSurface}
                    onChange={(peerAttackSurface) => setConn({ ...node.connection, peerAttackSurface })}
                  />
                </div>
              </>
            )}
          </div>
        )}
      </div>

      {/* attackSurface */}
      <div className="flex flex-col gap-2 border-t border-slate-700/60 pt-3">
        <SubLabel>{t('ruleEditor.nodeTarget.attackSurfaceLabel')}</SubLabel>
        <AttackSurfaceEditor
          value={node.attackSurface}
          onChange={(attackSurface) => onChange({ ...node, attackSurface })}
        />
      </div>

      {/* agentAttributes */}
      <div className="flex flex-col gap-2 border-t border-slate-700/60 pt-3">
        <SubLabel>{t('ruleEditor.nodeTarget.agentAttributesLabel')}</SubLabel>
        {AGENT_AXES.map((axis) => (
          <div key={axis.key} className="grid grid-cols-[160px_1fr] gap-2 items-start">
            <span className="text-xs text-slate-500 pt-0.5">{t(axis.labelKey)}</span>
            <ChipGroup
              options={axis.options}
              selected={node.agentAttributes[axis.key]}
              onToggle={(v) =>
                onChange({
                  ...node,
                  agentAttributes: {
                    ...node.agentAttributes,
                    [axis.key]: toggleInArray(node.agentAttributes[axis.key], v),
                  },
                })
              }
            />
          </div>
        ))}
      </div>
    </div>
  );
}

function modeCls(active: boolean): string {
  return `px-2.5 py-1 rounded-md text-xs font-bold border transition-colors ${
    active
      ? 'bg-blue-600 border-blue-500 text-white'
      : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
  }`;
}
