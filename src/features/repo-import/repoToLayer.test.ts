import { describe, expect, it } from 'vitest';
import { classifyEnvValue, parseEnv, repoToLayer, type RepoFile, type RepoImportSummary } from './repoToLayer';
import { PersistedLayerDataSchema } from '../persistence/schema';
import type { LayerData } from '../../core/model/types';
import { layerToProject } from '../kong-import/toProject';
import { analyzeProject } from '../../cli/analyze';

// 出力に漏れてはいけない目印の秘密文字列。
const ENV_SECRET = 'ENVSECRET9f8e7d6c5b4a39281706';
const MCP_ENV_SECRET = 'MCPENVSECRET-abc123';
const MCP_HDR_SECRET = 'Bearer MCPHDRSECRET-xyz789';
const NPMRC_SECRET = 'NPMTOKENSECRET-0000';
const URL_USER_SECRET = 'urluser:urlpassSECRET';
const QUERY_SECRET = 'querytokenSECRET';
const PEM_BODY = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7PEMBODYSECRET==';
const ALLOW_SECRET = 'ALLOWCMDSECRET-tok';

const COLLECTED_AT = '2026-10-29T00:00:00.000Z';

const LOCK = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    '': { name: 'app' },
    'node_modules/left-pad': {
      version: '1.3.0',
      resolved: `https://${URL_USER_SECRET}@registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz?token=${QUERY_SECRET}`,
      integrity: 'sha512-aaa',
    },
    'node_modules/esbuild': {
      version: '0.21.0',
      resolved: 'https://registry.npmjs.org/esbuild/-/esbuild-0.21.0.tgz',
      integrity: 'sha512-bbb',
      hasInstallScript: true,
      dev: true,
    },
    'node_modules/a/node_modules/left-pad': {
      version: '0.0.1',
      resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-0.0.1.tgz',
      integrity: 'sha512-ccc',
      optional: true,
    },
  },
});

const FILES: RepoFile[] = [
  {
    path: 'package.json',
    text: JSON.stringify({ dependencies: { 'left-pad': '^1.3.0' }, devDependencies: { esbuild: '0.21.0' } }),
  },
  { path: 'package-lock.json', text: LOCK },
  { path: '.npmrc', text: `registry=https://${URL_USER_SECRET}@npm.internal.example.com/?x=${QUERY_SECRET}\n//npm.internal.example.com/:_authToken=${NPMRC_SECRET}\n` },
  {
    path: 'server/requirements.txt',
    text: [
      '# comment',
      `--index-url https://${URL_USER_SECRET}@pypi.example.org/simple?k=${QUERY_SECRET}`,
      '-r base.txt',
      'requests==2.31.0 \\',
      '    --hash=sha256:aaaa',
      'flask>=2.0',
      `private-pkg @ https://${URL_USER_SECRET}@git.example.com/p.git`,
    ].join('\n'),
  },
  { path: '.env', text: `DB_PASSWORD=${ENV_SECRET}\nPORT=3000\nEMPTY=\nPEM="-----BEGIN PRIVATE KEY-----\n${PEM_BODY}\n-----END PRIVATE KEY-----"\nAFTER=1\n` },
  { path: '.env.example', text: 'DB_PASSWORD=\nAPI_URL=https://example.com\n' },
  {
    path: '.mcp.json',
    text: JSON.stringify({
      mcpServers: {
        local: { command: '/usr/bin/npx', args: ['-y', 'some-mcp', '--token', MCP_ENV_SECRET], env: { LOCAL_KEY: MCP_ENV_SECRET } },
        remote: { type: 'http', url: `https://${URL_USER_SECRET}@mcp.example.com/mcp?k=${QUERY_SECRET}`, headers: { Authorization: MCP_HDR_SECRET } },
      },
    }),
  },
  {
    path: '.claude/settings.json',
    text: JSON.stringify({
      permissions: {
        allow: ['Bash(npx *)', 'Bash(git status)', 'Read', `Bash(curl -H "x: ${ALLOW_SECRET}" https://x)`],
        deny: ['Read(.env)'],
      },
      sandbox: { enabled: true },
      hooks: { PreToolUse: [] },
    }),
  },
  { path: '.claude/skills/review/SKILL.md', text: '' },
  { path: '.claude/commands/deploy.md', text: '' },
];

const OPTS = { collectedAt: COLLECTED_AT, repoName: 'sample-repo', gitIgnored: { '.env': true, '.env.example': false } };

function ok(files: RepoFile[] = FILES): { layer: LayerData; summary: RepoImportSummary } {
  const r = repoToLayer(files, OPTS);
  if (!r.ok) throw new Error(r.error);
  return r;
}

const byType = (layer: LayerData, type: string) => layer.nodes.filter((n) => n.type === type);
const node = (layer: LayerData, label: string) => layer.nodes.find((n) => n.label === label)!;

describe('classifyEnvValue / parseEnv', () => {
  it('値の種類を判定する', () => {
    expect(classifyEnvValue('')).toBe('empty');
    expect(classifyEnvValue('https://example.com')).toBe('url');
    expect(classifyEnvValue('3000')).toBe('number');
    expect(classifyEnvValue('true')).toBe('boolean');
    expect(classifyEnvValue('/var/lib/x')).toBe('path');
    expect(classifyEnvValue('eyJhbGciOi.eyJzdWIi.sig-nature')).toBe('jwt');
    expect(classifyEnvValue('-----BEGIN RSA PRIVATE KEY-----')).toBe('private-key');
    expect(classifyEnvValue(ENV_SECRET)).toBe('secret-like');
    expect(classifyEnvValue('hello world')).toBe('text');
  });

  it('複数行の引用値の続きを変数として読まない', () => {
    const items = parseEnv(`PEM="-----BEGIN KEY-----\n${PEM_BODY}\n-----END KEY-----"\nAFTER=1\n# c\nexport X='a b'\n`);
    expect(items.map((i) => i.name)).toEqual(['PEM', 'AFTER', 'X']);
    expect(items[0].valueKind).toBe('private-key');
    expect(items[2]).toEqual({ name: 'X', valueKind: 'text', length: 3 });
  });
});

describe('repoToLayer', () => {
  it('PersistedLayerDataSchema に適合する', () => {
    const { layer } = ok();
    expect(PersistedLayerDataSchema.safeParse(layer).success).toBe(true);
  });

  it('出力に秘密文字列が含まれない', () => {
    const { layer } = ok();
    const text = JSON.stringify(layerToProject(layer));
    for (const secret of [ENV_SECRET, MCP_ENV_SECRET, MCP_HDR_SECRET, NPMRC_SECRET, URL_USER_SECRET, 'urlpassSECRET', QUERY_SECRET, PEM_BODY, ALLOW_SECRET]) {
      expect(text).not.toContain(secret);
    }
  });

  it('.env は変数名・種類・長さだけをインベントリに持つ', () => {
    const { layer } = ok();
    const env = node(layer, '.env');
    expect(env.type).toBe('CREDENTIAL');
    expect(env.parentId).toBe('repo-pc');
    expect(env.inventory).toMatchObject({ kind: 'env', source: '.env', template: false, gitIgnored: true });
    expect(env.inventory?.kind === 'env' && env.inventory.items).toEqual([
      { name: 'DB_PASSWORD', valueKind: 'secret-like', length: ENV_SECRET.length },
      { name: 'PORT', valueKind: 'number', length: 4 },
      { name: 'EMPTY', valueKind: 'empty', length: 0 },
      { name: 'PEM', valueKind: 'private-key', length: expect.any(Number) },
      { name: 'AFTER', valueKind: 'number', length: 1 },
    ]);
    expect(node(layer, '.env.example').inventory).toMatchObject({ template: true, gitIgnored: false });
  });

  it('npm：ロックから版・install script・ホストを読み、整合性付きなら Locked', () => {
    const { layer, summary } = ok();
    const dep = node(layer, 'package.json');
    expect(dep.type).toBe('PACKAGE_DEPENDENCIES');
    expect(dep.posture).toEqual({ dependencyLockfile: 'Locked', installScripts: 'Allowed' });
    const inv = dep.inventory!;
    expect(inv.kind).toBe('npm');
    const items = inv.kind === 'npm' ? inv.items : [];
    expect(items.map((i) => `${i.name}@${i.version}`)).toEqual(['esbuild@0.21.0', 'left-pad@0.0.1', 'left-pad@1.3.0']);
    expect(items.find((i) => i.name === 'esbuild')).toMatchObject({ dev: true, hasInstallScript: true, hasIntegrity: true, resolvedHost: 'registry.npmjs.org' });
    expect(summary.installScriptPackages).toBe(1);
  });

  it('npm：ロックが無ければ Unlocked、版の固定は完全一致のときだけ', () => {
    const { layer } = ok([FILES[0]]);
    const dep = node(layer, 'package.json');
    expect(dep.posture).toEqual({ dependencyLockfile: 'Unlocked' });
    const items = dep.inventory?.kind === 'npm' ? dep.inventory.items : [];
    expect(items.find((i) => i.name === 'left-pad')).toMatchObject({ version: '^1.3.0', pinned: false });
    expect(items.find((i) => i.name === 'esbuild')).toMatchObject({ pinned: true, dev: true });
  });

  it('.npmrc の ignore-scripts=true で installScripts が Disabled、registry のホストが取得元になる', () => {
    const files = FILES.map((f) =>
      f.path === '.npmrc' ? { path: '.npmrc', text: 'ignore-scripts=true\nregistry=https://npm.corp/\n' } : f,
    );
    const { layer } = ok(files);
    expect(node(layer, 'package.json').posture?.installScripts).toBe('Disabled');
    const reg = byType(layer, 'PACKAGE_REGISTRY').map((n) => n.label);
    expect(reg).toContain('パッケージレジストリ（npm.corp）');
    expect(reg).toContain('パッケージレジストリ（registry.npmjs.org）');
    // 組織内のレジストリへの線は VPC
    expect(layer.edges.find((e) => e.target === 'repo-registry-npm-corp')?.network).toBe('VPC');
  });

  it('pip：== で pinned、--hash で整合性、直接参照 URL は記録しない', () => {
    const { layer } = ok();
    const dep = node(layer, 'server/requirements.txt');
    expect(dep.inventory?.kind).toBe('pypi');
    const items = dep.inventory?.kind === 'pypi' ? dep.inventory.items : [];
    expect(items.map((i) => i.name)).toEqual(['flask', 'private-pkg', 'requests']);
    expect(items.find((i) => i.name === 'requests')).toMatchObject({ version: '2.31.0', pinned: true, hasIntegrity: true });
    expect(items.find((i) => i.name === 'flask')).toMatchObject({ pinned: false, hasIntegrity: false });
    expect(items.find((i) => i.name === 'private-pkg')?.version).toBeUndefined();
    expect(dep.posture).toEqual({ dependencyLockfile: 'Unlocked' });
    expect(byType(layer, 'PACKAGE_REGISTRY').some((n) => n.label?.includes('pypi.example.org'))).toBe(true);
  });

  it('エージェント：広い許可は Broad、サンドボックス有効は Enforced、設定の中身は列挙しない', () => {
    const { layer } = ok();
    const agent = byType(layer, 'AGENT')[0];
    expect(agent.posture).toEqual({ commandAllowScope: 'Broad', agentSandbox: 'Enforced' });
    expect(agent.description).toContain('Bash(npx *)');
    expect(agent.description).not.toContain('git status');
  });

  it('エージェント：広い許可もサンドボックスも無ければ posture は未入力', () => {
    const { layer } = ok([
      { path: '.claude/settings.json', text: JSON.stringify({ permissions: { allow: ['Bash(git status)'] } }) },
    ]);
    expect(byType(layer, 'AGENT')[0].posture).toBeUndefined();
  });

  it('.claude/ が無ければ AGENT を作らない', () => {
    const { layer } = ok([FILES[0]]);
    expect(byType(layer, 'AGENT')).toHaveLength(0);
    expect(byType(layer, 'AGENT_SKILL')).toHaveLength(0);
  });

  it('MCP：stdio は Global IP なしで実行ファイル名だけ、remote はホストだけ・Internet 側', () => {
    const { layer, summary } = ok();
    const local = node(layer, 'local');
    expect(local.type).toBe('MCP_SERVER');
    expect(local.attackSurface).toEqual({ hasGlobalIp: false });
    expect(local.description).toContain('npx');
    expect(local.description).toContain('LOCAL_KEY');
    const remote = node(layer, 'remote');
    expect(remote.attackSurface).toBeUndefined();
    expect(remote.description).toContain('mcp.example.com');
    expect(remote.description).toContain('Authorization');
    const e = layer.edges.find((x) => x.target === remote.id)!;
    expect(e).toMatchObject({ source: 'repo-agent', semantic: 'tool_invocation', network: 'Internet', encryption: 'TLS', auth: 'Token' });
    expect(summary.mcpServers).toBe(2);
    const internet = layer.boundaries.find((b) => b.trustLevel === 'Internet')!;
    expect(remote.x).toBeGreaterThan(internet.x);
  });

  it('スキルとコマンドを名前だけで AGENT_SKILL にし、エージェントから線を引く', () => {
    const { layer, summary } = ok();
    const skills = byType(layer, 'AGENT_SKILL').map((n) => n.label);
    expect(skills.sort()).toEqual(['/deploy', 'review']);
    expect(layer.edges.filter((e) => e.source === 'repo-agent' && skills.length > 0).length).toBeGreaterThan(2);
    expect(summary).toMatchObject({ skills: 1, commands: 1 });
  });

  it('ID はパスと名前から決まり、入力順に依存しない', () => {
    const a = ok(FILES).layer;
    const b = ok([...FILES].reverse()).layer;
    expect(a.nodes.map((n) => n.id).sort()).toEqual(b.nodes.map((n) => n.id).sort());
    expect(a.nodes.map((n) => n.id)).toContain('repo-env-env');
    expect(a.nodes.map((n) => n.id)).toContain('repo-deps-server-requirements-txt');
  });

  it('対象ファイルが無ければエラー', () => {
    expect(repoToLayer([{ path: 'README.md', text: '' }], OPTS).ok).toBe(false);
  });

  it('壊れた JSON は警告にして続行する', () => {
    const { summary } = ok([FILES[0], { path: '.mcp.json', text: '{' }]);
    expect(summary.warnings.some((w) => w.includes('.mcp.json'))).toBe(true);
  });

  it('analyzeProject で脅威が出る', () => {
    const project = layerToProject(ok().layer);
    const [result] = analyzeProject(project);
    expect(result.layer).toBe('L1');
    expect(result.threats.length).toBeGreaterThan(0);
    const nodeIds = new Set(result.threats.map((t) => t.nodeId));
    expect(nodeIds.size).toBeGreaterThan(0);
  });
});
