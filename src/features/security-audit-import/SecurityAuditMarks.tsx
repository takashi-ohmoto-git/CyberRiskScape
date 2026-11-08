import { FileSearch } from 'lucide-react';
import { useT } from '../../i18n';

/**
 * 脅威カードの「ソース監査で実証（ローカル）／要確認」の印（ペンテストの印とは別。docs/architecture.md §8.9）。
 * 要確認は重大度を持たないので、色は中立（スレート）にする。
 */
export function SecurityAuditMarks({ confirmed, unverified }: { confirmed: boolean; unverified: boolean }) {
  const t = useT();
  return (
    <>
      {confirmed && (
        <span
          title={t('threats.threatCard.securityAuditVerifiedHint')}
          className="text-xs font-bold px-2 py-0.5 rounded bg-slate-700/60 text-slate-200 border border-slate-400 inline-flex items-center gap-1"
        >
          <FileSearch size={12} />
          {t('threats.threatCard.securityAuditVerified')}
        </span>
      )}
      {unverified && (
        <span
          title={t('threats.threatCard.securityAuditUnverifiedHint')}
          className="text-xs font-bold px-2 py-0.5 rounded bg-slate-800/60 text-slate-300 border border-dotted border-slate-500 inline-flex items-center gap-1"
        >
          <FileSearch size={12} />
          {t('threats.threatCard.securityAuditUnverified')}
        </span>
      )}
    </>
  );
}
