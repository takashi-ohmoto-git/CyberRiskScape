/**
 * エージェント ダッシュボード（画面のモーダルと CLI の単体 HTML）で共有する CSS。
 * Tailwind を持たない単体 HTML でも使えるよう、クラスはすべて `rd-` 接頭辞の素の CSS。外部フォント・URL は使わない。
 */
export const REPO_DASHBOARD_CSS = `
.rd-root{background:#0f172a;color:#f1f5f9;font-family:system-ui,-apple-system,"Segoe UI","Hiragino Sans","Yu Gothic",sans-serif;font-size:14px;line-height:1.5;padding:20px;box-sizing:border-box}
.rd-root *{box-sizing:border-box}
.rd-header{display:flex;flex-wrap:wrap;align-items:baseline;gap:8px 16px;margin-bottom:16px}
.rd-title{font-size:20px;font-weight:700;margin:0}
.rd-meta{font-size:12px;color:#94a3b8}
.rd-section{margin:20px 0 8px;font-size:14px;font-weight:700;color:#cbd5e1}
.rd-alerts{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:6px}
.rd-alert{padding:8px 12px;border-radius:8px;border:1px solid;font-size:13px;word-break:break-word}
.rd-alert-high{background:rgba(239,68,68,.12);border-color:#ef4444;color:#fecaca}
.rd-alert-medium{background:rgba(245,158,11,.12);border-color:#f59e0b;color:#fde68a}
.rd-noalerts{color:#86efac;font-size:13px;margin:0}
.rd-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:16px}
@media (max-width:900px){.rd-kpis{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:480px){.rd-kpis{grid-template-columns:minmax(0,1fr)}}
.rd-kpi{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:12px 14px}
.rd-kpi-label{font-size:12px;color:#94a3b8}
.rd-kpi-value{font-size:26px;font-weight:700;color:#60a5fa}
.rd-kpi-value-warn{color:#fbbf24}
.rd-kpi-sub{font-size:12px;color:#94a3b8;word-break:break-word}
.rd-details{margin:8px 0;background:#1e293b;border:1px solid #334155;border-radius:12px;padding:8px 12px}
.rd-details>summary{cursor:pointer;font-weight:600;font-size:13px;color:#e2e8f0}
.rd-chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.rd-chip{background:#0f172a;border:1px solid #475569;color:#bfdbfe;border-radius:999px;padding:2px 10px;font-size:12px;word-break:break-all}
.rd-table-wrap{overflow-x:auto;margin-top:8px}
.rd-table{border-collapse:collapse;width:100%;font-size:12px}
.rd-table th,.rd-table td{border-bottom:1px solid #334155;padding:4px 8px;text-align:left;white-space:nowrap}
.rd-table th{color:#94a3b8;font-weight:600}
.rd-table td.rd-wrap{white-space:normal;min-width:200px}
.rd-warn{color:#fbbf24;font-weight:700}
.rd-bad{color:#f87171;font-weight:700}
.rd-note{font-size:12px;color:#94a3b8;margin:6px 0}
.rd-list{list-style:none;margin:8px 0 0;padding:0;display:flex;flex-direction:column;gap:4px;font-size:13px}
.rd-muted{color:#94a3b8}
`;
