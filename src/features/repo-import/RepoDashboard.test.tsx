import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { translate } from '../../i18n';
import { buildRepoDashboard } from './buildRepoDashboard';
import { RepoDashboard } from './RepoDashboard';
import { repoToLayer, type RepoFile } from './repoToLayer';

const FILES: RepoFile[] = [
  { path: 'package.json', text: JSON.stringify({ dependencies: { a: '1.0.0' } }) },
  {
    path: 'package-lock.json',
    text: JSON.stringify({
      packages: { '': {}, 'node_modules/a': { version: '1.0.0', resolved: 'http://registry.example.com/a.tgz', hasInstallScript: true } },
    }),
  },
  { path: '.env', text: 'TOKEN=super-secret-value\n' },
  { path: '.claude/settings.json', text: JSON.stringify({ permissions: { allow: ['Bash(npx *)'], deny: [] } }) },
  { path: '.claude/skills/review/SKILL.md', text: '' },
  { path: '.claude/skills/<img src=x onerror=alert(1)>/SKILL.md', text: '' },
  { path: '.claude/commands/deploy.md', text: '' },
];

function html(locale: 'ja' | 'en' = 'ja'): string {
  const r = repoToLayer(FILES, { collectedAt: '2026-11-01T00:00:00.000Z', repoName: 'sample', gitIgnored: { '.env': false } });
  if (!r.ok) throw new Error(r.error);
  const data = buildRepoDashboard(r.layer, 'repo-agent')!;
  return renderToStaticMarkup(<RepoDashboard data={data} t={(k, p) => translate(k, locale, p)} />);
}

describe('RepoDashboard', () => {
  it('スキル名・コマンド名・警告・.env の変数名を表示する', () => {
    const h = html();
    expect(h).toContain('review');
    expect(h).toContain('/deploy');
    expect(h).toContain('rd-alert-high');
    expect(h).toContain('TOKEN');
  });

  it('.env の値は出さない', () => {
    expect(html()).not.toContain('super-secret-value');
  });

  it('スキル名に含まれる HTML はエスケープされる', () => {
    const h = html();
    expect(h).not.toContain('<img');
    expect(h).toContain('&lt;img');
  });

  it('英語でも描画できる', () => {
    expect(html('en')).toContain('Agent dashboard');
  });
});
