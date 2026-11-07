import { useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, FileSearch } from 'lucide-react';
import { MAX_FINDINGS, type DiagramNode, type Finding } from '../../core/model/types';
import { useDiagramStore } from '../../core/state/diagramStore';
import { useT } from '../../i18n';
import { replaceFindings } from '../findings-import/replaceFindings';
import { BUNDLED_SECURITY_AUDIT_MAP } from '../findings-report/findingMap';
import { buildAuditRows } from './auditRows';
import {
  SECURITY_AUDIT_MAX_BYTES,
  parseCoverageLedger,
  parseSecurityAudit,
  type LedgerUnit,
} from './parseSecurityAudit';
import { SECURITY_AUDIT_PRODUCT, securityAuditToFindings, type SecurityAuditReport } from './securityAuditToFindings';
import { SecurityAuditList } from './SecurityAuditList';

/**
 * ノード詳細パネルの「ソース監査の指摘」欄（docs/architecture.md §8.9）。
 * findings.json（＋任意で coverage-ledger.json）をブラウザの中で読み、このノードの指摘として取り込む。
 * 取り込み直しは製品 × scope（ノード ID）の単位の置き換えで、Undo の対象外のため、既存があるときは確認を挟む。
 */

interface Pending {
  converted: Finding[];
  report: SecurityAuditReport;
  invalid: number;
}

type Result = { report: SecurityAuditReport; invalid: number };

export function SecurityAuditSection({ node }: { node: DiagramNode }) {
  const t = useT();
  const findings = useDiagramStore((s) => s.findings);
  const layerKey = useDiagramStore((s) => s.activeLayer);
  const layer = useDiagramStore((s) => s.layers[s.activeLayer]);
  const setFindings = useDiagramStore((s) => s.setFindings);
  const [open, setOpen] = useState(false);
  const [findingsFile, setFindingsFile] = useState<File | null>(null);
  const [ledgerFile, setLedgerFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  const [result, setResult] = useState<Result | null>(null);

  const rows = useMemo(() => buildAuditRows(findings, node.id, layer), [findings, node.id, layer]);
  const existing = findings.filter(
    (f) => f.source.product === SECURITY_AUDIT_PRODUCT && f.source.scope === node.id,
  ).length;

  const readJson = async (file: File): Promise<unknown> => {
    if (file.size > SECURITY_AUDIT_MAX_BYTES) {
      throw new Error(t('findings.securityAudit.error.tooLarge', { max: SECURITY_AUDIT_MAX_BYTES / 1024 / 1024 }));
    }
    try {
      return JSON.parse(await file.text()) as unknown;
    } catch {
      throw new Error(`${file.name}: ${t('findings.securityAudit.error.invalidJson')}`);
    }
  };

  const apply = (p: Pending) => {
    // 確認待ちの間に指摘が変わっても、最新の指摘に対して置き換える
    const current = useDiagramStore.getState().findings;
    const r = replaceFindings(current, p.converted, SECURITY_AUDIT_PRODUCT, node.id);
    if (r.findings.length > MAX_FINDINGS) {
      setError(t('findings.securityAudit.error.overLimit', { max: MAX_FINDINGS }));
      setPending(null);
      return;
    }
    setFindings(r.findings);
    setPending(null);
    setResult({ report: p.report, invalid: p.invalid });
  };

  const onImport = async () => {
    setError(null);
    setResult(null);
    setPending(null);
    if (!findingsFile) return;
    try {
      const parsed = parseSecurityAudit(await readJson(findingsFile));
      if (!parsed.ok) throw new Error(parsed.error);
      let ledger: LedgerUnit[] | undefined;
      if (ledgerFile) {
        const pl = parseCoverageLedger(await readJson(ledgerFile));
        if (!pl.ok) throw new Error(pl.error);
        ledger = pl.units;
      }
      const conv = securityAuditToFindings({
        items: parsed.items,
        ...(ledger ? { ledger } : {}),
        map: BUNDLED_SECURITY_AUDIT_MAP,
        scope: node.id,
        subject: { layer: layerKey, nodeId: node.id },
        importedAt: new Date().toISOString(),
      });
      if (conv.findings.length > MAX_FINDINGS) {
        throw new Error(t('findings.securityAudit.error.overLimit', { max: MAX_FINDINGS }));
      }
      const p: Pending = { converted: conv.findings, report: conv.report, invalid: parsed.invalid };
      if (existing > 0) setPending(p);
      else apply(p);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const pick = (set: (f: File | null) => void) => (e: React.ChangeEvent<HTMLInputElement>) => {
    set(e.target.files?.[0] ?? null);
    setResult(null);
    setError(null);
    setPending(null);
  };

  return (
    <div className="bg-slate-800/50 rounded-2xl border border-slate-700">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full px-4 py-3 flex items-center justify-between text-xs font-bold text-slate-300 hover:text-slate-100 transition-colors"
        aria-expanded={open}
      >
        <span className="flex items-center gap-2">
          <FileSearch size={14} className="text-blue-500 shrink-0" /> {t('findings.securityAudit.title')}
          <span className="text-xs font-normal text-slate-400">
            {t('findings.securityAudit.count', { count: rows.length })}
          </span>
        </span>
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-3">
          <p className="text-xs text-slate-500 leading-relaxed">{t('findings.securityAudit.hint')}</p>
          <div className="space-y-2">
            <label className="block text-xs text-slate-300">
              <span className="font-bold">{t('findings.securityAudit.pickFindings')}</span>
              <input
                type="file"
                accept="application/json,.json"
                data-testid="security-audit-findings-file"
                onChange={pick(setFindingsFile)}
                className="block w-full mt-1 text-xs text-slate-300"
              />
            </label>
            <label className="block text-xs text-slate-300">
              <span className="font-bold">{t('findings.securityAudit.pickLedger')}</span>
              <input
                type="file"
                accept="application/json,.json"
                data-testid="security-audit-ledger-file"
                onChange={pick(setLedgerFile)}
                className="block w-full mt-1 text-xs text-slate-300"
              />
            </label>
            <button
              type="button"
              disabled={!findingsFile}
              onClick={() => void onImport()}
              className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed text-xs font-bold text-white transition-colors"
            >
              {t('findings.securityAudit.import')}
            </button>
          </div>
          {pending && (
            <div role="alertdialog" className="rounded-lg border border-amber-500/50 bg-amber-500/10 p-3 space-y-2">
              <p className="text-xs text-amber-200 leading-relaxed">
                {t('findings.securityAudit.confirmReplace', { count: existing })}
              </p>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => apply(pending)}
                  className="px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-xs font-bold text-white"
                >
                  {t('findings.securityAudit.replace')}
                </button>
                <button
                  type="button"
                  onClick={() => setPending(null)}
                  className="px-3 py-1.5 rounded-lg bg-slate-700 hover:bg-slate-600 text-xs font-bold text-slate-100"
                >
                  {t('findings.securityAudit.cancel')}
                </button>
              </div>
            </div>
          )}
          {error && (
            <p role="alert" className="text-xs text-rose-300 leading-relaxed">
              {error}
            </p>
          )}
          {result && (
            <p role="status" className="text-xs text-slate-300 leading-relaxed">
              {t('findings.securityAudit.result', { ...result.report, invalid: result.invalid })}
            </p>
          )}
          <SecurityAuditList rows={rows} />
        </div>
      )}
    </div>
  );
}
