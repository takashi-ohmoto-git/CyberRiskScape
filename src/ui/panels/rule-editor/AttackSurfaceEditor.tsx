import type { AttackSurfaceDraft } from '../../../features/custom-rules/editor/draft';

/**
 * Attack Surface 条件（7 属性）の三状態エディタ（§2.25 Phase D / D3）。
 * 各属性は 不問(null) / 有(true) / 無(false)。null = その属性を条件にしない。
 * node.attackSurface と connection.peerAttackSurface の双方で共用。
 */
const SURFACE_ROWS: { key: keyof AttackSurfaceDraft; label: string }[] = [
  { key: 'hasGlobalIp', label: 'グローバル IP' },
  { key: 'hasSourceIpRestriction', label: '送信元 IP 制限' },
  { key: 'hasRemoteAccessRestriction', label: 'リモートアクセス制限' },
  { key: 'hasUserAuthentication', label: 'ユーザー認証' },
  { key: 'hasAccessLog', label: 'アクセスログ' },
  { key: 'hasWafProtection', label: 'WAF' },
  { key: 'hasDdosProtection', label: 'DDoS 防御' },
];

const TRISTATE: { value: boolean | null; label: string }[] = [
  { value: null, label: '不問' },
  { value: true, label: '有' },
  { value: false, label: '無' },
];

export function AttackSurfaceEditor({
  value,
  onChange,
}: {
  value: AttackSurfaceDraft;
  onChange: (next: AttackSurfaceDraft) => void;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      {SURFACE_ROWS.map((row) => (
        <div key={row.key} className="grid grid-cols-[150px_1fr] gap-2 items-center">
          <span className="text-[11px] text-slate-500">{row.label}</span>
          <div className="flex gap-1">
            {TRISTATE.map((t) => {
              const on = value[row.key] === t.value;
              return (
                <button
                  key={t.label}
                  type="button"
                  onClick={() => onChange({ ...value, [row.key]: t.value })}
                  className={`px-2 py-0.5 rounded-md text-[11px] font-medium border transition-colors ${
                    on
                      ? 'bg-blue-600 border-blue-500 text-white'
                      : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                  }`}
                >
                  {t.label}
                </button>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
