import { renderToStaticMarkup } from 'react-dom/server';
import { BRANDING } from '../../core/branding';
import { translate, type Locale } from '../../i18n';
import type { RepoDashboardData } from './buildRepoDashboard';
import { RepoDashboard } from './RepoDashboard';
import { REPO_DASHBOARD_CSS } from './repoDashboardCss';

const escapeHtml = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/**
 * エージェント ダッシュボードの単体 HTML（`import-repo --dashboard`）。スクリプト・外部 URL なし。
 * CSP で他のすべての読み込みを禁じる。
 */
export function renderRepoDashboardHtml(data: RepoDashboardData, locale: Locale): string {
  const body = renderToStaticMarkup(<RepoDashboard data={data} t={(k, p) => translate(k, locale, p)} />);
  const title = `${translate('repoDashboard.title', locale)}${data.repoName ? `: ${data.repoName}` : ''} - ${BRANDING.name}`;
  return `<!doctype html>
<html lang="${locale}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>${escapeHtml(title)}</title>
<style>body{margin:0;background:#0f172a}${REPO_DASHBOARD_CSS}</style>
</head>
<body>
${body}
</body>
</html>
`;
}
