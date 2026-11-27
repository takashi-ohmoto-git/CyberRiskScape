/**
 * CLI（src/cli/main.ts）の全サブコマンドのスモークテスト。
 * 実際にビルドした CLI（vite build --ssr と同等）を子プロセスで起動し、終了コードと出力の要点を確かめる。
 * main.ts の構造を変えるリファクタで挙動が保たれていることを確認するための網。
 * 入力は既存のフィクスチャか、テスト内で一時ディレクトリに書く架空の小さなデータ。出力は一時ディレクトリだけに書く。
 */
import { spawn, spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { build } from 'vite';

const fx = (rel: string): string => fileURLToPath(new URL(rel, import.meta.url));

const SAMPLE = fx('./__fixtures__/sample-project.json');
const CHANGED = fx('./__fixtures__/sample-project-changed.json');
const F = (rel: string): string => fx(`../features/${rel}`);

let tmp = '';
let cliPath = '';
/** テスト内で用意する入力ファイルの置き場。 */
let inDir = '';
/** 出力ファイルの置き場。 */
let outDir = '';
/** git 履歴を持つ一時リポジトリ（export-event-log 用）。 */
let gitRepo = '';

interface Case {
  /** サブコマンド名（main.ts のコマンド表 COMMANDS の名前と一致させる）。 */
  command: string;
  /** 引数を返す（一時ディレクトリが決まった後に評価する）。サブコマンド名は含めない。 */
  args: () => string[];
  exit: number;
  /** --out で書かれるファイル（outDir からの相対）。あればその内容を、無ければ stdout を検査する。 */
  outFile?: string;
  /** 検査対象（outFile または stdout）に含まれる文字列。 */
  contains?: string[];
  /** stderr に含まれる文字列。 */
  stderrContains?: string[];
  /** 検査対象を JSON として読み、その値を検査する。 */
  json?: (value: unknown) => void;
}

const out = (name: string): string => join(outDir, name);
const inp = (name: string): string => join(inDir, name);

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function hasLayers(v: unknown): void {
  expect(isRecord(v) && isRecord(v.layers) && 'L1' in v.layers).toBe(true);
}

const CASES: Case[] = [
  {
    command: 'analyze',
    args: () => [SAMPLE, '--out', out('analyze.json')],
    exit: 0,
    outFile: 'analyze.json',
    json: (v) => {
      expect(Array.isArray(v)).toBe(true);
      expect((v as Record<string, unknown>[])[0].kind).toBe('cyberriskscape-threat-report');
    },
  },
  {
    command: 'diff',
    args: () => [SAMPLE, CHANGED, '--out', out('diff.md')],
    exit: 0,
    outFile: 'diff.md',
    contains: ['# モデル差分レポート', '## 実行トリガー'],
  },
  {
    command: 'triggers',
    args: () => ['--out', out('triggers.md')],
    exit: 0,
    outFile: 'triggers.md',
    contains: ['# 脅威モデリングの実行トリガー チェックリスト'],
  },
  {
    command: 'indicators',
    args: () => [SAMPLE, '--out', out('indicators.json')],
    exit: 0,
    outFile: 'indicators.json',
    json: (v) => {
      expect(isRecord(v) && isRecord(v.indicators)).toBe(true);
      expect(isRecord(v) && v.projectName).toBe('CLIスモークテスト用サンプル');
    },
  },
  {
    command: 'export-scope',
    args: () => [SAMPLE, '--format', 'json', '--out', out('scope.json')],
    exit: 0,
    outFile: 'scope.json',
    json: (v) => expect(isRecord(v)).toBe(true),
  },
  {
    // 入力の用意が無いため誤りの経路を確かめる（実在しないチェックリスト ID）
    command: 'checklist',
    args: () => [SAMPLE, '--id', 'no-such-checklist'],
    exit: 2,
    stderrContains: ['不明なチェックリスト ID です'],
  },
  {
    command: 'export-postman',
    args: () => [SAMPLE, '--out', out('postman.json')],
    exit: 0,
    outFile: 'postman.json',
    json: (v) => expect(isRecord(v) && isRecord(v.info) && Array.isArray(v.item)).toBe(true),
  },
  {
    command: 'export-sbom-ai',
    args: () => [SAMPLE, '--out', out('sbom-ai.json')],
    exit: 0,
    outFile: 'sbom-ai.json',
    json: (v) => {
      expect(isRecord(v) && v.bomFormat).toBe('CycloneDX');
      expect(isRecord(v) && v.specVersion).toBe('1.7');
    },
  },
  {
    command: 'export-test-plan',
    args: () => [SAMPLE, '--out', out('test-plan.md')],
    exit: 0,
    outFile: 'test-plan.md',
    contains: ['# ペネトレーションテスト計画書'],
  },
  {
    command: 'export-roe',
    args: () => [SAMPLE, '--out', out('roe.md')],
    exit: 0,
    outFile: 'roe.md',
    contains: ['# 交戦規定（RoE）／スコープ宣言'],
  },
  {
    command: 'export-attack-navigator',
    args: () => [SAMPLE, '--out', out('navigator.json')],
    exit: 0,
    outFile: 'navigator.json',
    json: (v) => expect(isRecord(v) && Array.isArray(v.techniques)).toBe(true),
  },
  {
    command: 'export-investigation-plan',
    args: () => [SAMPLE, '--out', out('inv-plan.md')],
    exit: 0,
    outFile: 'inv-plan.md',
    contains: ['# 侵害調査計画'],
  },
  {
    command: 'export-detection-requirements',
    args: () => [SAMPLE, '--out', out('detection.md')],
    exit: 0,
    outFile: 'detection.md',
    contains: ['# 攻撃経路ごとの検知要件'],
  },
  {
    command: 'export-contractor-paths',
    args: () => [SAMPLE, '--out', out('contractor.md')],
    exit: 0,
    outFile: 'contractor.md',
    contains: ['# 委託先の接続経路の一覧'],
  },
  {
    command: 'export-event-log',
    args: () => ['--repo', gitRepo, '--path', 'model.json', '--max-commits', '5', '--out', out('events.json')],
    exit: 0,
    outFile: 'events.json',
    stderrContains: ['イベントログを出力しました'],
    json: (v) => expect(isRecord(v)).toBe(true),
  },
  {
    command: 'export-requirements',
    args: () => [SAMPLE, '--out', out('requirements.md')],
    exit: 0,
    outFile: 'requirements.md',
    contains: ['# セキュリティ要件一覧'],
  },
  {
    // 入力の用意が無いため誤りの経路を確かめる（証拠の指定なし）
    command: 'investigation-report',
    args: () => [SAMPLE],
    exit: 2,
    stderrContains: ['--evidence を 1 つ以上指定してください'],
  },
  {
    command: 'export-triage-patterns',
    args: () => ['--out', out('triage.json')],
    exit: 0,
    outFile: 'triage.json',
    json: (v) => expect(isRecord(v) && v.format).toBe('cyberriskscape-triage-patterns'),
  },
  {
    command: 'findings-report',
    args: () => [
      SAMPLE,
      '--skill-scanner',
      F('findings-report/__fixtures__/skill-scanner-single.json'),
      '--out',
      out('findings-report.md'),
    ],
    exit: 0,
    stderrContains: ['突き合わせました'],
  },
  {
    command: 'pqc-sbom-report',
    args: () => [SAMPLE, '--sbom', F('sbom-crypto/__fixtures__/cbom-1.7.json'), '--node', 'C1', '--out', out('pqc.md')],
    exit: 0,
    stderrContains: ['SBOM の暗号の確認を出力しました'],
  },
  {
    command: 'import-repo',
    args: () => [inp('repo'), '--out', out('repo.json')],
    exit: 0,
    outFile: 'repo.json',
    stderrContains: ['リポジトリを取り込みました'],
    json: hasLayers,
  },
  {
    command: 'import-prowler',
    args: () => [
      F('prowler-import/__fixtures__/sample-project.json'),
      '--ocsf',
      F('prowler-import/__fixtures__/sample.ocsf.json'),
      '--out',
      out('prowler.json'),
    ],
    exit: 0,
    contains: ['# Prowler 取り込みレポート'],
  },
  {
    command: 'import-findings',
    args: () => [
      SAMPLE,
      '--format',
      'xccdf',
      '--in',
      F('scap-import/__fixtures__/xccdf-results.xml'),
      '--out',
      out('findings.json'),
    ],
    exit: 0,
    contains: ['# SCAP 取り込みレポート（XCCDF）'],
  },
  {
    command: 'import-pentest',
    args: () => [
      F('pentest-import/__fixtures__/sample-project.json'),
      '--in',
      F('pentest-import/__fixtures__/registry.yaml'),
      '--out',
      out('pentest.json'),
    ],
    exit: 0,
    contains: ['# ペンテスト取り込みレポート'],
  },
  {
    command: 'import-business-context',
    args: () => [SAMPLE, '--in', F('business-context/__fixtures__/table.csv'), '--out', out('business.json')],
    exit: 0,
    outFile: 'business.json',
    json: hasLayers,
  },
  {
    // 入力の用意が無いため誤りの経路を確かめる（API が要る。ネットワークには出ない）
    command: 'convert-celonis',
    args: () => [],
    exit: 2,
    stderrContains: ['--api <base-url> を指定してください'],
  },
  {
    command: 'import-kev',
    args: () => [SAMPLE, '--kev', inp('kev.json'), '--out', out('kev.json')],
    exit: 0,
    contains: ['# KEV 照合レポート', '2026.01.01'],
  },
  {
    command: 'fill-patch-status',
    args: () => [SAMPLE, '--out', out('patch.json')],
    exit: 0,
    contains: ['# パッチ状況の補完レポート'],
  },
  {
    // 入力の用意が無いため誤りの経路を確かめる（照会キーの指定なし）
    command: 'context',
    args: () => [SAMPLE],
    exit: 2,
    stderrContains: ['--ip / --host / --purl のうち 1 つだけを指定してください'],
  },
  {
    command: 'import-epss',
    args: () => [SAMPLE, '--epss', F('epss-import/__fixtures__/epss_scores.csv'), '--out', out('epss.json')],
    exit: 0,
    contains: ['# EPSS 照合レポート'],
  },
  {
    command: 'findings-priority',
    args: () => [SAMPLE, '--out', out('priority.md')],
    exit: 0,
    outFile: 'priority.md',
    contains: ['# 指摘の優先度（推奨）'],
  },
  {
    command: 'asm-reconcile',
    args: () => [SAMPLE, '--out', out('asm.md')],
    exit: 0,
    outFile: 'asm.md',
    contains: ['# ASM の観測と図の突き合わせ'],
  },
  {
    command: 'sbom-report',
    args: () => [SAMPLE, '--out', out('sbom-report.md')],
    exit: 0,
    outFile: 'sbom-report.md',
    contains: ['# SBOM の検収レポート'],
  },
  {
    command: 'import-sarif',
    args: () => [
      SAMPLE,
      '--sarif',
      F('sarif-import/__fixtures__/sample.sarif.json'),
      '--scope',
      'smoke',
      '--out',
      out('sarif.json'),
    ],
    exit: 0,
    contains: ['# SARIF 取り込みレポート'],
  },
  {
    command: 'import-nuclei',
    args: () => [
      SAMPLE,
      '--in',
      F('nuclei-import/__fixtures__/nuclei.jsonl'),
      '--scope',
      'smoke',
      '--out',
      out('nuclei.json'),
    ],
    exit: 0,
    contains: ['# Nuclei 取り込みレポート'],
  },
  {
    command: 'import-security-audit',
    args: () => [SAMPLE, '--in', F('security-audit-import/__fixtures__/findings.json'), '--out', out('audit.json')],
    exit: 0,
    contains: ['# ソース監査の取り込みレポート'],
  },
  {
    command: 'import-sbom',
    args: () => [SAMPLE, '--sbom', F('bom-import/__fixtures__/syft.cdx.json'), '--scope', 'smoke', '--out', out('sbom.json')],
    exit: 0,
    contains: ['# 部品の取り込みレポート'],
  },
  {
    command: 'export-spdx',
    args: () => [SAMPLE, '--out', out('spdx.json')],
    exit: 0,
    outFile: 'spdx.json',
    json: (v) => expect(isRecord(v) && v.spdxVersion).toBe('SPDX-2.3'),
  },
  {
    command: 'import-aipentest-assets',
    args: () => [
      SAMPLE,
      '--format',
      'ai-asm',
      '--endpoints',
      inp('aiasm.json'),
      '--scope',
      'smoke',
      '--out',
      out('aipentest.json'),
    ],
    exit: 0,
    contains: ['# 資産の取り込みレポート（AI-ASM）'],
  },
  {
    command: 'import-conjur',
    args: () => [inp('conjur.yml'), '--out', out('conjur.json')],
    exit: 0,
    outFile: 'conjur.json',
    stderrContains: ['Conjur ポリシーを取り込みました'],
    json: hasLayers,
  },
  {
    command: 'import-shodan',
    args: () => [inp('shodan.json'), '--out', out('shodan.json')],
    exit: 0,
    outFile: 'shodan.json',
    stderrContains: ['Shodan の書き出しを取り込みました'],
    json: hasLayers,
  },
  {
    command: 'import-openapi',
    args: () => [SAMPLE, '--in', inp('openapi.yaml'), '--scope', 'smoke', '--out', out('openapi.json')],
    exit: 0,
    contains: ['# OpenAPI の取り込みレポート', 'Partner Portal API'],
  },
  {
    command: 'import-ocsf',
    args: () => [
      SAMPLE,
      '--in',
      F('ocsf-import/__fixtures__/sample.ocsf.json'),
      '--scope',
      'smoke',
      '--out',
      out('ocsf.json'),
    ],
    exit: 0,
    contains: ['# OCSF の取り込みレポート'],
  },
  {
    command: 'import-entra-apps',
    args: () => [
      SAMPLE,
      '--in',
      inp('entra'),
      '--tenant-id',
      '33333333-3333-3333-3333-333333333333',
      '--out',
      out('entra.json'),
    ],
    exit: 0,
    contains: ['# Microsoft Graph（外部アプリ・同意）の取り込みレポート'],
  },
  {
    // 同梱の問い合わせの一覧を出して終わる（ネットワークには出ない）
    command: 'import-bloodhound',
    args: () => [SAMPLE, '--print-queries'],
    exit: 0,
    json: (v) => {
      expect(Array.isArray(v)).toBe(true);
      expect((v as Record<string, unknown>[])[0].id).toBe('kerberoastable-users');
    },
  },
  {
    command: 'convert-cyberstrikeai',
    args: () => [
      F('pentest-import/__fixtures__/cyberstrikeai-vulns.json'),
      '--scope',
      'smoke',
      '--out',
      out('cyberstrikeai.yaml'),
    ],
    exit: 0,
    outFile: 'cyberstrikeai.yaml',
    stderrContains: ['CyberStrikeAI の脆弱性を台帳に変換しました'],
    contains: ['import-pentest'],
  },
  {
    command: 'convert-strix',
    args: () => [F('pentest-import/__fixtures__/strix-findings.sarif'), '--scope', 'smoke', '--out', out('strix.yaml')],
    exit: 0,
    outFile: 'strix.yaml',
    stderrContains: ['Strix の指摘を台帳に変換しました'],
    contains: ['import-pentest'],
  },
  {
    command: 'convert-metasploit',
    args: () => [
      F('metasploit-import/__fixtures__/metasploit-export.xml'),
      '--scope',
      'smoke',
      '--out',
      out('metasploit.yaml'),
    ],
    exit: 0,
    outFile: 'metasploit.yaml',
    stderrContains: ['Metasploit の指摘を台帳に変換しました'],
    contains: ['import-pentest'],
  },
  {
    command: 'import-metasploit-assets',
    args: () => [
      SAMPLE,
      '--xml',
      F('metasploit-import/__fixtures__/metasploit-export.xml'),
      '--scope',
      'smoke',
      '--out',
      out('msf-assets.json'),
    ],
    exit: 0,
    contains: ['# 資産の取り込みレポート（Metasploit）'],
  },
  {
    command: 'import-scopesentry',
    args: () => [inp('scopesentry.json'), '--out', out('scopesentry.json')],
    exit: 0,
    outFile: 'scopesentry.json',
    stderrContains: ['ScopeSentry のデータを取り込みました'],
    json: hasLayers,
  },
  {
    command: 'import-kong',
    args: () => [inp('kong.yaml'), '--out', out('kong.json')],
    exit: 0,
    outFile: 'kong.json',
    stderrContains: ['Kong 設定を取り込みました'],
    json: hasLayers,
  },
  {
    command: 'import-tm7',
    args: () => [F('tm7-import/__fixtures__/example.tm7'), '--out', out('tm7.json')],
    exit: 0,
    outFile: 'tm7.json',
    stderrContains: ['.tm7 を取り込みました'],
    json: hasLayers,
  },
  {
    command: 'migration-report',
    args: () => [SAMPLE, '--out', out('migration.md')],
    exit: 0,
    outFile: 'migration.md',
    contains: ['# 移行レポート'],
  },
  {
    command: 'import-kongctl',
    args: () => [inp('kongctl.yaml'), '--out', out('kongctl.json')],
    exit: 0,
    outFile: 'kongctl.json',
    stderrContains: ['kongctl 設定を取り込みました'],
    json: hasLayers,
  },
];

/** main.ts のソースから、サブコマンド名（コマンド表 COMMANDS の `['名前', ...` の行）を集める。 */
function commandsInMainSource(): string[] {
  const source = readFileSync(fx('./main.ts'), 'utf-8');
  const names = [...source.matchAll(/^ {2}\['([a-z0-9-]+)', /gm)].map((m) => m[1]);
  return [...new Set(names)];
}

beforeAll(async () => {
  tmp = mkdtempSync(join(tmpdir(), 'crs-cli-smoke-'));
  const cliOut = join(tmp, 'cli');
  inDir = join(tmp, 'in');
  outDir = join(tmp, 'out');
  gitRepo = join(tmp, 'repo');
  for (const d of [inDir, outDir, join(inDir, 'repo'), join(inDir, 'entra'), gitRepo]) mkdirSync(d, { recursive: true });

  // npm run build:cli（vite build --ssr src/cli/main.ts）と同じ設定（vite.config.ts）でビルドする
  await build({
    build: { ssr: 'src/cli/main.ts', outDir: cliOut, emptyOutDir: true },
    logLevel: 'silent',
  });
  cliPath = join(cliOut, 'main.js');

  // 架空の入力
  const writeJson = (name: string, value: unknown) => writeFileSync(inp(name), JSON.stringify(value));
  writeJson('repo/package.json', { name: 'demo', version: '1.0.0', dependencies: { 'left-pad': '1.0.0' } });
  writeJson('kev.json', { catalogVersion: '2026.01.01', vulnerabilities: [{ cveID: 'CVE-2024-0001' }] });
  writeJson('aiasm.json', { endpoints: [{ method: 'GET', url: 'https://shop.example/api/items?q=1' }] });
  writeJson('shodan.json', {
    ip_str: '203.0.113.10',
    port: 443,
    transport: 'tcp',
    hostnames: [],
    domains: [],
    timestamp: '2026-09-20T00:00:00',
    hash: 1,
    data: 'x',
  });
  writeJson('entra/servicePrincipals.json', {
    value: [
      {
        id: 'sp1',
        appId: '11111111-1111-1111-1111-111111111111',
        displayName: 'Ext App',
        appOwnerOrganizationId: '22222222-2222-2222-2222-222222222222',
      },
    ],
  });
  writeJson('scopesentry.json', [
    { host: 'www.example.com', ip: '203.0.113.10', port: '443', service: 'https', type: 'http', url: 'https://www.example.com/' },
  ]);
  const writeLines = (name: string, lines: string[]) => writeFileSync(inp(name), `${lines.join('\n')}\n`);
  writeLines('conjur.yml', [
    '- !policy',
    '  id: orders',
    '  body:',
    '    - !host api',
    '    - !variable db/password',
    '    - !permit',
    '      role: !host api',
    '      privileges: [read, execute]',
    '      resource: !variable db/password',
  ]);
  writeLines('openapi.yaml', [
    'openapi: 3.0.3',
    'info: { title: Partner Portal API, version: 1.2.0 }',
    'servers:',
    '  - url: https://api.portal.example.com/v1',
    'paths:',
    '  /health:',
    '    get: {}',
  ]);
  writeLines('kong.yaml', [
    '_format_version: "3.0"',
    'services:',
    '  - name: orders',
    '    url: https://orders.internal:8443/v1',
    '    routes:',
    '      - name: orders-route',
    '        paths: ["/orders"]',
    '        protocols: ["https"]',
    '    plugins:',
    '      - name: key-auth',
  ]);
  writeLines('kongctl.yaml', [
    'ai_gateways:',
    '  - name: gw',
    '    deployment_type: hybrid',
    '    proxy_urls:',
    '      - { host: ai.example.com, port: 443, protocol: https }',
    '    model_providers:',
    '      - { name: p-ollama, type: ollama }',
  ]);

  // export-event-log 用：2 版を持つ一時 git リポジトリ（実リポジトリの履歴には依存しない）
  const git = (...args: string[]) => {
    const r = spawnSync(
      'git',
      ['-c', 'user.name=smoke', '-c', 'user.email=smoke@example.com', '-c', 'commit.gpgsign=false', ...args],
      { cwd: gitRepo, encoding: 'utf8' },
    );
    if (r.status !== 0) throw new Error(`git ${args.join(' ')} に失敗: ${r.stderr}`);
  };
  git('init', '-q');
  cpSync(SAMPLE, join(gitRepo, 'model.json'));
  git('add', 'model.json');
  git('commit', '-q', '-m', 'v1');
  cpSync(CHANGED, join(gitRepo, 'model.json'));
  git('commit', '-q', '-a', '-m', 'v2');
}, 180_000);

afterAll(() => {
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

function runCli(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [cliPath, ...args], { encoding: 'utf8', timeout: 60_000 });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

describe('CLI main（全サブコマンドのスモーク）', () => {
  it('main.ts の全サブコマンドがスモークの表に載っている → 追加したのに表に無ければ落ちる（mcp は別 it）', () => {
    const inSource = commandsInMainSource().filter((c) => c !== 'mcp');
    const inTable = CASES.map((c) => c.command);
    expect([...inTable].sort()).toEqual([...inSource].sort());
    expect(new Set(inTable).size).toBe(inTable.length);
    expect(commandsInMainSource()).toContain('mcp');
  });

  it('ビルドした CLI が存在する → main.js がある', () => {
    expect(existsSync(cliPath)).toBe(true);
  });

  it.each(CASES.map((c) => [c.command, c] as const))('%s: 期待の終了コードと出力の要点を返す', (_name, c) => {
    const r = runCli([c.command, ...c.args()]);
    expect(r.status, r.stderr).toBe(c.exit);
    for (const s of c.stderrContains ?? []) expect(r.stderr).toContain(s);
    if (c.exit !== 0) return;
    const hasBody = c.outFile !== undefined || c.contains !== undefined || c.json !== undefined;
    if (!hasBody) return;
    const body = c.outFile ? readFileSync(out(c.outFile), 'utf-8') : r.stdout;
    expect(body.length).toBeGreaterThan(0);
    for (const s of c.contains ?? []) expect(body).toContain(s);
    if (c.json) c.json(JSON.parse(body));
  }, 30_000);

  it('不明なコマンド → 終了コード 2 と使い方を出す', () => {
    const r = runCli(['no-such-command']);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('不明なコマンドです');
  });

  it('--help → 終了コード 0 で全サブコマンドの使い方を標準出力に出す', () => {
    const r = runCli(['--help']);
    expect(r.status).toBe(0);
    for (const c of commandsInMainSource()) expect(r.stdout).toContain(c);
  });

  it('mcp: initialize のあと tools/list → 10 個のツールを返す', async () => {
    const lines = await new Promise<string[]>((resolve, reject) => {
      const child = spawn(process.execPath, [cliPath, 'mcp', '--root', tmp], { stdio: ['pipe', 'pipe', 'pipe'] });
      let buf = '';
      const timer = setTimeout(() => {
        child.kill();
        reject(new Error('mcp の応答がタイムアウトしました'));
      }, 30_000);
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', (d: string) => {
        buf += d;
        const got = buf.split('\n').filter((l) => l.trim() !== '');
        if (got.length >= 2) {
          clearTimeout(timer);
          child.kill();
          resolve(got);
        }
      });
      child.on('error', (e) => {
        clearTimeout(timer);
        reject(e);
      });
      const send = (m: unknown) => child.stdin.write(`${JSON.stringify(m)}\n`);
      send({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'smoke', version: '1' } },
      });
      send({ jsonrpc: '2.0', method: 'notifications/initialized' });
      send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    });
    const init = JSON.parse(lines[0]) as { result: { serverInfo: { name: string } } };
    expect(init.result.serverInfo.name).toBe('CyberRiskScape');
    const list = JSON.parse(lines[1]) as { result: { tools: { name: string }[] } };
    expect(list.result.tools).toHaveLength(10);
    expect(list.result.tools.map((t) => t.name)).toContain('analyze_threats');
  }, 60_000);
});
