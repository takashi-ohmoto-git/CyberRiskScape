import { describe, expect, it } from 'vitest';
import { buildRepoDashboard } from './buildRepoDashboard';
import { renderRepoDashboardHtml } from './renderRepoDashboardHtml';
import { repoToLayer, type RepoFile } from './repoToLayer';

const FILES: RepoFile[] = [
  { path: 'package.json', text: JSON.stringify({ dependencies: { a: '1.0.0' } }) },
  { path: '.mcp.json', text: JSON.stringify({ mcpServers: { remote: { url: 'https://mcp.example.com/x' } } }) },
  { path: '.claude/settings.json', text: JSON.stringify({ permissions: { allow: ['Read'], deny: [] } }) },
  { path: '.claude/skills/review/SKILL.md', text: '' },
];

function out(locale: 'ja' | 'en' = 'ja'): string {
  const r = repoToLayer(FILES, { collectedAt: '2026-11-01T00:00:00.000Z', repoName: 'sample' });
  if (!r.ok) throw new Error(r.error);
  return renderRepoDashboardHtml(buildRepoDashboard(r.layer, 'repo-agent')!, locale);
}

describe('renderRepoDashboardHtml', () => {
  it('doctype・CSP・タイトルを持つ', () => {
    const h = out();
    expect(h.startsWith('<!doctype html>')).toBe(true);
    expect(h).toContain(`default-src 'none'; style-src 'unsafe-inline'`);
    expect(h).toContain('<title>');
    expect(h).toContain('<html lang="ja">');
    expect(out('en')).toContain('<html lang="en">');
  });

  it('スクリプトと外部 URL を含まない', () => {
    const h = out();
    expect(h).not.toContain('<script');
    expect(h).not.toMatch(/(src|href)="https?:/);
    expect(h).toContain('review');
  });
});
