import { describe, expect, it } from 'vitest';
import { buildRepoDashboard } from './buildRepoDashboard';
import { repoToLayer, type RepoFile } from './repoToLayer';

const FILES: RepoFile[] = [
  {
    path: 'package.json',
    text: JSON.stringify({ dependencies: { a: '1.0.0' }, devDependencies: { b: '^2.0.0' } }),
  },
  {
    path: 'package-lock.json',
    text: JSON.stringify({
      packages: {
        '': {},
        'node_modules/a': { version: '1.0.0', resolved: 'http://registry.example.com/a.tgz', integrity: 'sha512-x', hasInstallScript: true },
        'node_modules/b': { version: '2.1.0', dev: true, resolved: 'http://registry.example.com/b.tgz' },
      },
    }),
  },
  { path: '.env', text: 'TOKEN=abc\n' },
  {
    path: '.mcp.json',
    text: JSON.stringify({ mcpServers: { local: { command: 'node' }, remote: { url: 'https://mcp.example.com/x' } } }),
  },
  { path: '.claude/settings.json', text: JSON.stringify({ permissions: { allow: ['Bash(npx *)', 'Read'], deny: ['Read(.env)'] } }) },
  { path: '.claude/skills/review/SKILL.md', text: '' },
  { path: '.claude/skills/apply/SKILL.md', text: '' },
  { path: '.claude/commands/deploy.md', text: '' },
];

function layer() {
  const r = repoToLayer(FILES, { collectedAt: '2026-11-01T00:00:00.000Z', repoName: 'sample', gitIgnored: { '.env': false } });
  if (!r.ok) throw new Error(r.error);
  return r.layer;
}

describe('buildRepoDashboard', () => {
  it('エージェントのインベントリが無いノードなら undefined', () => {
    expect(buildRepoDashboard(layer(), 'repo-pc')).toBeUndefined();
    expect(buildRepoDashboard(layer(), 'no-such-node')).toBeUndefined();
  });

  it('スキル・コマンド・設定の要約・リポジトリ名を集める', () => {
    const d = buildRepoDashboard(layer(), 'repo-agent')!;
    expect(d.repoName).toBe('sample');
    expect(d.skills).toEqual(['apply', 'review']);
    expect(d.commands).toEqual(['/deploy']);
    expect(d.agent).toMatchObject({ allowCount: 2, denyCount: 1, broadAllows: ['Bash(npx *)'], sandbox: false });
  });

  it('MCP・依存・.env・外部の接続先を集める', () => {
    const d = buildRepoDashboard(layer(), 'repo-agent')!;
    expect(d.mcpServers.map((m) => [m.label, m.internet])).toEqual([
      ['local', false],
      ['remote', true],
    ]);
    expect(d.manifests).toHaveLength(1);
    expect(d.manifests[0].packages.map((p) => p.name)).toEqual(['a', 'b']);
    expect(d.envFiles).toMatchObject([{ label: '.env', template: false, gitIgnored: false }]);
    expect(d.external.map((e) => e.type).sort()).toEqual(['MCP_SERVER', 'PACKAGE_REGISTRY']);
  });

  it('警告を出し、重大なものを先に並べる', () => {
    const d = buildRepoDashboard(layer(), 'repo-agent')!;
    const keys = d.alerts.map((a) => a.key);
    expect(keys).toEqual(
      expect.arrayContaining([
        'repoDashboard.alert.broadAllow',
        'repoDashboard.alert.sandboxUnset',
        'repoDashboard.alert.mcpNoAuth',
        'repoDashboard.alert.installScripts',
        'repoDashboard.alert.unlocked',
        'repoDashboard.alert.envTracked',
        'repoDashboard.alert.plainExternal',
      ]),
    );
    const firstMedium = d.alerts.findIndex((a) => a.level === 'medium');
    expect(d.alerts.slice(firstMedium).every((a) => a.level === 'medium')).toBe(true);
  });
});
