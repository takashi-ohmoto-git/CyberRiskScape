import {
  AgencyLevelSchema,
  BlastRadiusSchema,
  ConnectionDirectionSchema,
  IdentityTierSchema,
} from '../../../threat-library/schema/threatRule';
import { componentRegistry } from '../../../component-library/defaultRegistry';
import type {
  AgentAttributesDraft,
  ConnectionDraft,
  NodeDraft,
} from '../../../features/custom-rules/editor/draft';
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
  { key: 'agency', label: 'agency（自律度）', options: AgencyLevelSchema.options },
  { key: 'blastRadius', label: 'blastRadius（影響範囲）', options: BlastRadiusSchema.options },
  { key: 'identityTier', label: 'identityTier（同一性）', options: IdentityTierSchema.options },
] as const satisfies readonly { key: keyof AgentAttributesDraft; label: string; options: readonly string[] }[];

function SubLabel({ children }: { children: React.ReactNode }) {
  return <span className="text-[11px] text-slate-500">{children}</span>;
}

export function NodeTargetEditor({
  node,
  onChange,
}: {
  node: NodeDraft;
  onChange: (next: NodeDraft) => void;
}) {
  const componentIds = componentRegistry.getAll().map((c) => c.id);
  const labelOf = (id: string) => componentRegistry.get(id)?.label ?? id;
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
            単一型
          </button>
          <button
            type="button"
            onClick={() => onChange({ ...node, mode: 'anyOf' })}
            className={modeCls(node.mode === 'anyOf')}
          >
            いずれかの型 (anyOf)
          </button>
        </div>
        {node.mode === 'single' ? (
          <select
            value={node.nodeTypes[0] ?? ''}
            onChange={(e) => onChange({ ...node, nodeTypes: e.target.value ? [e.target.value] : [] })}
            className={inputCls}
          >
            <option value="">（型を選択）</option>
            {componentIds.map((id) => (
              <option key={id} value={id}>
                {labelOf(id)}（{id}）
              </option>
            ))}
          </select>
        ) : (
          <div className="flex flex-col gap-1">
            <SubLabel>2 つ以上の型を選択</SubLabel>
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
          <span className="text-[12px] font-bold text-slate-200">接続要件を指定する</span>
          <span className="text-[10px] text-slate-500">未指定 = 既定（任意方向のエッジ1本以上）</span>
        </label>

        {node.connection.enabled && (
          <div className="flex flex-col gap-2 pl-6">
            <div className="flex gap-1.5">
              <button
                type="button"
                onClick={() => setConn({ ...node.connection, required: true })}
                className={modeCls(node.connection.required)}
              >
                接続が必要
              </button>
              <button
                type="button"
                onClick={() => setConn({ ...node.connection, required: false })}
                className={modeCls(!node.connection.required)}
                title="接続有無に関係なく発火（内在的脅威）"
              >
                内在的（接続不問）
              </button>
            </div>

            {node.connection.required && (
              <>
                <div className="grid grid-cols-[120px_1fr] gap-2 items-center">
                  <SubLabel>方向</SubLabel>
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
                  <SubLabel>接続先（ピア）の型（任意・OR）</SubLabel>
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
                  <SubLabel>接続先（ピア）の攻撃面（任意）</SubLabel>
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
        <SubLabel>このノードの攻撃面（任意・FRONT_END_SERVER / GATEWAY 等で意味を持つ）</SubLabel>
        <AttackSurfaceEditor
          value={node.attackSurface}
          onChange={(attackSurface) => onChange({ ...node, attackSurface })}
        />
      </div>

      {/* agentAttributes */}
      <div className="flex flex-col gap-2 border-t border-slate-700/60 pt-3">
        <SubLabel>エージェント属性（任意・未指定属性は「最悪を仮定」評価）</SubLabel>
        {AGENT_AXES.map((axis) => (
          <div key={axis.key} className="grid grid-cols-[160px_1fr] gap-2 items-start">
            <span className="text-[11px] text-slate-500 pt-0.5">{axis.label}</span>
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
  return `px-2.5 py-1 rounded-md text-[11px] font-bold border transition-colors ${
    active
      ? 'bg-blue-600 border-blue-500 text-white'
      : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
  }`;
}
