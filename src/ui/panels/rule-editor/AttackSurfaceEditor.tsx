import type { AttackSurfaceDraft } from '../../../features/custom-rules/editor/draft';
import { useT, type TranslationKey } from '../../../i18n';

/**
 * Attack Surface 条件（7 属性）の三状態エディタ（§2.25 Phase D / D3）。
 * 各属性は 不問(null) / 有(true) / 無(false)。null = その属性を条件にしない。
 * node.attackSurface と connection.peerAttackSurface の双方で共用。
 */
const SURFACE_ROWS: { key: keyof AttackSurfaceDraft; labelKey: TranslationKey }[] = [
  { key: 'hasGlobalIp', labelKey: 'ruleEditor.attackSurface.field.hasGlobalIp' },
  { key: 'hasSourceIpRestriction', labelKey: 'ruleEditor.attackSurface.field.hasSourceIpRestriction' },
  { key: 'hasRemoteAccessRestriction', labelKey: 'ruleEditor.attackSurface.field.hasRemoteAccessRestriction' },
  { key: 'hasUserAuthentication', labelKey: 'ruleEditor.attackSurface.field.hasUserAuthentication' },
  { key: 'hasAccessLog', labelKey: 'ruleEditor.attackSurface.field.hasAccessLog' },
  { key: 'hasWafProtection', labelKey: 'ruleEditor.attackSurface.field.hasWafProtection' },
  { key: 'hasDdosProtection', labelKey: 'ruleEditor.attackSurface.field.hasDdosProtection' },
];

const TRISTATE: { value: boolean | null; labelKey: TranslationKey }[] = [
  { value: null, labelKey: 'ruleEditor.attackSurface.tristate.unspecified' },
  { value: true, labelKey: 'ruleEditor.attackSurface.tristate.yes' },
  { value: false, labelKey: 'ruleEditor.attackSurface.tristate.no' },
];

export function AttackSurfaceEditor({
  value,
  onChange,
}: {
  value: AttackSurfaceDraft;
  onChange: (next: AttackSurfaceDraft) => void;
}) {
  const t = useT();
  return (
    <div className="flex flex-col gap-1.5">
      {SURFACE_ROWS.map((row) => (
        <div key={row.key} className="grid grid-cols-[150px_1fr] gap-2 items-center">
          <span className="text-xs text-slate-500">{t(row.labelKey)}</span>
          <div className="flex gap-1">
            {TRISTATE.map((ts) => {
              const on = value[row.key] === ts.value;
              return (
                <button
                  key={ts.labelKey}
                  type="button"
                  onClick={() => onChange({ ...value, [row.key]: ts.value })}
                  className={`px-2 py-0.5 rounded-md text-xs font-medium border transition-colors ${
                    on
                      ? 'bg-blue-600 border-blue-500 text-white'
                      : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                  }`}
                >
                  {t(ts.labelKey)}
                </button>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
