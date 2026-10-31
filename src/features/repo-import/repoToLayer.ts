import { z } from 'zod';
import type {
  AuthType,
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  EncryptionType,
  EnvValueKind,
  EnvVarInventoryItem,
  LayerData,
  NetworkType,
  NodePosture,
  PackageInventoryItem,
} from '../../core/model/types';
import { getLocale, translate } from '../../i18n';
import { isInternalHost } from '../kongctl-import/kongctlToLayer';

/**
 * コーディングエージェントの作業ディレクトリ（リポジトリ）から、開発環境と依存パッケージの構成図の下書き
 * （1 レイヤー分）を作る純粋関数。ファイルの収集は `collectRepo.ts`（CLI 専用）が行い、ここは中身だけを読む。
 *
 * 方針（`kongctl-import/kongctlToLayer.ts` と同じ）：
 * - **秘密情報を読まない・残さない。** `.env` の値は種類と長さに変換したら捨てる。`.mcp.json` の env / headers は
 *   キー名だけ、`.npmrc` は `ignore-scripts` と `registry` の行だけ、URL は userinfo・パス・クエリを捨てホストだけ。
 *   `.claude/settings*.json` の許可ルールは、コマンドの中身にトークンが混じりうるため一覧を出さず、件数と
 *   ツール名、および固定一覧に一致した「広い許可」だけを書く。
 * - **脅威の知識は持たない。** ファイルの事実を図の要素・運用状況（posture）に置き換えるだけ。
 * - 大方針「未入力＝悪い値」：分からない項目は安全と断定せず未入力のままにする。
 *
 * 出力はテンプレート取り込みと同じ形（`seq` なし）。
 */

export interface RepoFile {
  /** リポジトリ直下からの相対パス（`/` 区切り）。 */
  path: string;
  text: string;
}

export interface RepoImportOptions {
  /** 収集時刻（ISO 8601）。インベントリの collectedAt に入れる。 */
  collectedAt: string;
  /** `.env` 系ファイルの相対パス → git 管理外か。不明なら省略。 */
  gitIgnored?: Record<string, boolean>;
  repoName: string;
}

export interface RepoImportSummary {
  manifests: number;
  packages: number;
  installScriptPackages: number;
  envFiles: number;
  mcpServers: number;
  skills: number;
  commands: number;
  warnings: string[];
}

export type RepoImportResult =
  | { ok: true; name: string; layer: LayerData; summary: RepoImportSummary }
  | { ok: false; error: string };

// ── 小さな部品 ──────────────────────────────────────────────

const slug = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, '-')
    .replace(/^-+|-+$/g, '') || 'x';

const dirOf = (p: string) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
const baseOf = (p: string) => p.slice(p.lastIndexOf('/') + 1);

/** URL からホスト名と平文かどうかだけを取り出す（userinfo・パス・クエリは捨てる）。`git+https://` にも対応。 */
function hostOf(url: unknown): { host: string; plain: boolean } | undefined {
  if (typeof url !== 'string') return undefined;
  try {
    const u = new URL(url.replace(/^git\+/, ''));
    if (!u.hostname) return undefined;
    return { host: u.hostname, plain: u.protocol === 'http:' };
  } catch {
    return undefined;
  }
}

/** 版の指定として記録してよい文字列か（URL・パス・git 参照は、資格情報を含みうるので記録しない）。 */
const SAFE_VERSION = /^[\w.^~<>=|* ,+-]{1,80}$/;
const safeVersion = (v: unknown): string | undefined =>
  typeof v === 'string' && SAFE_VERSION.test(v) ? v : undefined;

const EXACT_VERSION = /^\d+(\.\d+){0,3}(-[\w.]+)?(\+[\w.]+)?$/;

// ── .env ────────────────────────────────────────────────────

/** 値の種類を単純な規則で判定する。値そのものは返さない。 */
export function classifyEnvValue(value: string): EnvValueKind {
  const v = value.trim();
  if (v === '') return 'empty';
  if (v.includes('-----BEGIN')) return 'private-key';
  if (/^eyJ[\w-]+\.[\w-]+\.[\w-]*$/.test(v)) return 'jwt';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return 'url';
  if (/^(true|false|yes|no|on|off)$/i.test(v)) return 'boolean';
  if (/^-?\d+(\.\d+)?$/.test(v)) return 'number';
  if (/^(\/|\.{1,2}\/|~\/|[A-Za-z]:[\\/])/.test(v)) return 'path';
  if (v.length >= 20 && /^[A-Za-z0-9+/_=.-]+$/.test(v) && /\d/.test(v) && /[A-Za-z]/.test(v)) return 'secret-like';
  return 'text';
}

/** `.env` のテキストから変数名・値の種類・長さを取り出す。複数行の引用値は最後まで読み飛ばす。 */
export function parseEnv(text: string): EnvVarInventoryItem[] {
  const items: EnvVarInventoryItem[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === '' || line.startsWith('#')) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=(.*)$/.exec(line);
    if (!m) continue;
    let value = m[2].trim();
    const q = value[0];
    if ((q === '"' || q === "'") && !(value.length > 1 && value.endsWith(q))) {
      // 閉じ引用が来るまで続く値（PEM 等）。続きの行は変数名として読まないよう消費する。
      while (i + 1 < lines.length) {
        i++;
        value += `\n${lines[i]}`;
        if (lines[i].trimEnd().endsWith(q)) break;
      }
    }
    if ((q === '"' || q === "'") && value.length >= 2 && value.endsWith(q)) value = value.slice(1, -1);
    items.push({ name: m[1], valueKind: classifyEnvValue(value), length: value.length });
  }
  return items;
}

const isEnvFile = (name: string) => name === '.env' || name.startsWith('.env.');
const isEnvTemplate = (name: string) => /\.(example|sample|template)$/i.test(name);

// ── npm ─────────────────────────────────────────────────────

const flag = z.boolean().optional().catch(undefined);
const str = z.string().optional().catch(undefined);
const PackageJsonSchema = z.object({
  dependencies: z.record(z.unknown()).optional().catch(undefined),
  devDependencies: z.record(z.unknown()).optional().catch(undefined),
  optionalDependencies: z.record(z.unknown()).optional().catch(undefined),
});
const LockSchema = z.object({
  packages: z
    .record(
      z.object({
        version: str,
        dev: flag,
        optional: flag,
        hasInstallScript: flag,
        resolved: str,
        integrity: str,
        link: flag,
      }),
    )
    .optional()
    .catch(undefined),
});

interface ParsedManifest {
  items: PackageInventoryItem[];
  /** 取得元ホスト → 平文か。 */
  hosts: Map<string, boolean>;
  locked: boolean;
}

function addHost(hosts: Map<string, boolean>, url: unknown): void {
  const h = hostOf(url);
  if (h) hosts.set(h.host, (hosts.get(h.host) ?? false) || h.plain);
}

function parseNpm(manifestText: string, lockText: string | undefined, warn: (m: string) => void, path: string): ParsedManifest | undefined {
  let pkg: z.infer<typeof PackageJsonSchema>;
  try {
    pkg = PackageJsonSchema.parse(JSON.parse(manifestText));
  } catch {
    warn(`${path}: JSON として読み込めません`);
    return undefined;
  }
  const hosts = new Map<string, boolean>();
  let lockPackages: NonNullable<z.infer<typeof LockSchema>['packages']> | undefined;
  if (lockText !== undefined) {
    try {
      lockPackages = LockSchema.parse(JSON.parse(lockText)).packages;
    } catch {
      warn(`${dirOf(path) ? `${dirOf(path)}/` : ''}package-lock.json: JSON として読み込めません`);
    }
    if (lockText !== undefined && lockPackages === undefined) {
      warn(`${dirOf(path) ? `${dirOf(path)}/` : ''}package-lock.json: packages がありません（lockfileVersion 1 は未対応。package.json の指定だけを使います）`);
    }
  }

  if (lockPackages) {
    const seen = new Set<string>();
    const items: PackageInventoryItem[] = [];
    for (const [key, e] of Object.entries(lockPackages)) {
      if (key === '' || e.link) continue;
      const idx = key.lastIndexOf('node_modules/');
      if (idx < 0) continue; // ワークスペース自身など
      const name = key.slice(idx + 'node_modules/'.length);
      const version = safeVersion(e.version);
      const dedup = `${name}@${version ?? ''}`;
      if (seen.has(dedup)) continue;
      seen.add(dedup);
      const item: PackageInventoryItem = { name, pinned: true, hasIntegrity: !!e.integrity };
      if (version) item.version = version;
      if (e.dev) item.dev = true;
      if (e.optional) item.optional = true;
      if (e.hasInstallScript) item.hasInstallScript = true;
      const h = hostOf(e.resolved);
      if (h) {
        item.resolvedHost = h.host;
        addHost(hosts, e.resolved);
      }
      items.push(item);
    }
    items.sort((a, b) => a.name.localeCompare(b.name) || (a.version ?? '').localeCompare(b.version ?? ''));
    return { items, hosts, locked: items.length > 0 && items.every((i) => i.hasIntegrity) };
  }

  const items: PackageInventoryItem[] = [];
  const add = (rec: Record<string, unknown> | undefined, extra: Partial<PackageInventoryItem>) => {
    for (const [name, spec] of Object.entries(rec ?? {})) {
      const version = safeVersion(spec);
      items.push({
        name,
        ...(version ? { version } : {}),
        ...extra,
        pinned: typeof spec === 'string' && EXACT_VERSION.test(spec),
      });
    }
  };
  add(pkg.dependencies, {});
  add(pkg.devDependencies, { dev: true });
  add(pkg.optionalDependencies, { optional: true });
  items.sort((a, b) => a.name.localeCompare(b.name));
  return { items, hosts, locked: false };
}

/** `.npmrc` から `ignore-scripts` と registry のホストだけを読む（トークン等の行は見ない）。 */
function parseNpmrc(text: string): { ignoreScripts: boolean; hosts: Map<string, boolean> } {
  let ignoreScripts = false;
  const hosts = new Map<string, boolean>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const m = /^(ignore-scripts|(?:@[\w.-]+:)?registry)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    if (m[1] === 'ignore-scripts') ignoreScripts = m[2].trim().replace(/["']/g, '').toLowerCase() === 'true';
    else addHost(hosts, m[2].trim().replace(/["']/g, ''));
  }
  return { ignoreScripts, hosts };
}

// ── pip ─────────────────────────────────────────────────────

function parsePip(text: string): ParsedManifest {
  const hosts = new Map<string, boolean>();
  // 行末の `\` で続く行をつなぐ。
  const logical: string[] = [];
  let cur = '';
  for (const raw of text.split(/\r?\n/)) {
    const joined = cur + raw;
    if (/\\\s*$/.test(joined)) {
      cur = `${joined.replace(/\\\s*$/, '')} `;
    } else {
      logical.push(joined);
      cur = '';
    }
  }
  if (cur) logical.push(cur);

  const items: PackageInventoryItem[] = [];
  for (const raw of logical) {
    const line = raw.replace(/(^|\s)#.*$/, '').trim();
    if (line === '') continue;
    const idx = /^(?:--index-url|--extra-index-url|-i)(?:\s+|=)(\S+)/.exec(line);
    if (idx) {
      addHost(hosts, idx[1]);
      continue;
    }
    if (line.startsWith('-') || /^[./]/.test(line) || /^[a-z+]+:\/\//i.test(line)) continue;
    const hasIntegrity = /--hash[=\s]/.test(line);
    const body = line.split(/\s--/)[0].split(';')[0].trim();
    const nm = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$/.exec(body);
    if (!nm) continue;
    const name = nm[1];
    const rest = nm[2].trim();
    const exact = /^={2,3}\s*([^\s,]+)$/.exec(rest);
    const pinned = !!exact && !exact[1].includes('*');
    // `name @ URL` の直接参照は URL に資格情報が入りうるので版を記録しない。
    const version = rest.startsWith('@') ? undefined : safeVersion(pinned ? exact![1] : rest || undefined);
    items.push({ name, ...(version ? { version } : {}), hasIntegrity, pinned });
  }
  items.sort((a, b) => a.name.localeCompare(b.name));
  return { items, hosts, locked: items.length > 0 && items.every((i) => i.pinned && i.hasIntegrity) };
}

const isPipFile = (name: string) => /(^|[-_.])requirements[\w.-]*\.(txt|lock|in)$/i.test(name);

// ── .mcp.json / .claude/settings*.json ──────────────────────

const McpSchema = z.object({
  mcpServers: z
    .record(
      z.object({
        command: str,
        type: str,
        url: str,
        env: z.record(z.unknown()).optional().catch(undefined),
        headers: z.record(z.unknown()).optional().catch(undefined),
      }),
    )
    .optional()
    .catch(undefined),
});

const strList = z.array(z.unknown()).optional().catch(undefined);
const SettingsSchema = z.object({
  permissions: z
    .object({ allow: strList, deny: strList, defaultMode: str })
    .optional()
    .catch(undefined),
  sandbox: z.object({ enabled: flag }).optional().catch(undefined),
  hooks: z.record(z.unknown()).optional().catch(undefined),
});

/** 任意コードの実行を許す実行ファイル（`Bash(<これ> *)` の形で許可すると広い許可になる）。 */
const BROAD_COMMANDS = new Set([
  'npx',
  'node',
  'python',
  'python3',
  'sh',
  'bash',
  'zsh',
  'npm exec',
  'pnpm dlx',
  'pnpm exec',
  'yarn dlx',
  'bunx',
  'uvx',
  'deno',
  'pwsh',
  'powershell',
  'cmd',
  'eval',
  'sudo',
]);

/** 広い許可なら、その正規化した形（固定一覧に一致したものだけ）を返す。 */
function broadAllow(entry: string): string | undefined {
  const m = /^Bash(?:\((.*)\))?$/.exec(entry.trim());
  if (!m) return undefined;
  const inner = (m[1] ?? '').trim().replace(/\s*(:\*|\*)$/, '').trim();
  if (inner === '') return 'Bash(*)';
  return BROAD_COMMANDS.has(inner) ? `Bash(${inner} *)` : undefined;
}

const toolName = (entry: string) => entry.split('(')[0].trim();

// ── 組み立て ────────────────────────────────────────────────

export function repoToLayer(files: RepoFile[], opts: RepoImportOptions): RepoImportResult {
  const locale = getLocale();
  const t = (key: Parameters<typeof translate>[0], params?: Record<string, string | number>) =>
    translate(key, locale, params);
  const sorted = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const byPath = new Map(sorted.map((f) => [f.path, f]));
  const warnings: string[] = [];
  const warn = (m: string) => warnings.push(m);

  const nodes: DiagramNode[] = [];
  const edges: DiagramEdge[] = [];
  const nodeIds = new Set<string>();
  const addNode = (n: Omit<DiagramNode, 'id'> & { id: string }): DiagramNode => {
    let id = n.id;
    for (let k = 2; nodeIds.has(id); k++) id = `${n.id}-${k}`;
    nodeIds.add(id);
    const node = { ...n, id };
    nodes.push(node);
    return node;
  };
  const addEdge = (
    source: string,
    target: string,
    auth: AuthType,
    network: NetworkType,
    encryption: EncryptionType,
    extra: Partial<DiagramEdge> = {},
  ) => {
    const id = `${source}--${target}`;
    if (edges.some((e) => e.id === id)) return;
    edges.push({ id, source, target, auth, network, encryption, ...extra });
  };

  // ── 入力の仕分け ──
  const envFiles = sorted.filter((f) => isEnvFile(baseOf(f.path)));
  const manifestsNpm = sorted.filter((f) => baseOf(f.path) === 'package.json');
  const manifestsPip = sorted.filter((f) => isPipFile(baseOf(f.path)));
  const mcpFile = byPath.get('.mcp.json');
  const settingsFiles = ['.claude/settings.json', '.claude/settings.local.json']
    .map((p) => byPath.get(p))
    .filter((f): f is RepoFile => !!f);
  const skillNames = new Set<string>();
  const commandNames = new Set<string>();
  for (const f of sorted) {
    const sm = /^\.claude\/skills\/([^/]+)\//.exec(f.path);
    if (sm) skillNames.add(sm[1]);
    const cm = /^\.claude\/commands\/(.+)$/.exec(f.path);
    if (cm) commandNames.add(cm[1].replace(/\.[^./]+$/, ''));
  }
  const hasAgent = sorted.some((f) => f.path.startsWith('.claude/'));

  if (
    envFiles.length + manifestsNpm.length + manifestsPip.length + settingsFiles.length === 0 &&
    !mcpFile &&
    skillNames.size + commandNames.size === 0
  ) {
    return { ok: false, error: t('repo.error.noTargets') };
  }

  // 座標：端末・エージェント・（内部の要素）・Internet の 4 列。
  const COL = { pc: 60, agent: 340, internal: 640, external: 940 };
  const ROW = 150;
  const TOP = 120;
  let internalRow = 0;
  let externalRow = 0;
  const internalIds: string[] = [];
  const externalIds: string[] = [];
  const place = (internal: boolean) => {
    const y = TOP + (internal ? internalRow++ : externalRow++) * ROW;
    return { x: internal ? COL.internal : COL.external, y };
  };

  // ── 開発端末（PC）とその内包 ──
  const pc = addNode({ id: 'repo-pc', type: 'PC', x: COL.pc, y: TOP, label: t('repo.node.pc') });
  addNode({
    id: 'repo-source',
    type: 'SOURCE_CODE',
    x: pc.x,
    y: pc.y,
    parentId: pc.id,
    label: opts.repoName,
    description: t('repo.desc.repo', { name: opts.repoName }),
  });
  let envCount = 0;
  for (const f of envFiles) {
    const name = baseOf(f.path);
    const template = isEnvTemplate(name);
    const items = parseEnv(f.text);
    envCount++;
    const ignored = opts.gitIgnored?.[f.path];
    addNode({
      id: `repo-env-${slug(f.path)}`,
      type: 'CREDENTIAL',
      x: pc.x,
      y: pc.y,
      parentId: pc.id,
      label: f.path,
      description: t('repo.desc.env', { count: items.length, template: template ? t('repo.word.template') : '' }),
      inventory: {
        kind: 'env',
        source: f.path,
        collectedAt: opts.collectedAt,
        template,
        ...(ignored === undefined ? {} : { gitIgnored: ignored }),
        items,
      },
    });
  }

  // ── エージェント（.claude/ があるときだけ）──
  let agent: DiagramNode | undefined;
  if (hasAgent) {
    const allow: string[] = [];
    const deny: string[] = [];
    let sandbox = false;
    let hooks = false;
    let bypass = false;
    for (const f of settingsFiles) {
      let parsed: z.infer<typeof SettingsSchema>;
      try {
        parsed = SettingsSchema.parse(JSON.parse(f.text));
      } catch {
        warn(`${f.path}: JSON として読み込めません`);
        continue;
      }
      const strs = (l: unknown[] | undefined) => (l ?? []).filter((x): x is string => typeof x === 'string');
      allow.push(...strs(parsed.permissions?.allow));
      deny.push(...strs(parsed.permissions?.deny));
      if (parsed.permissions?.defaultMode === 'bypassPermissions') bypass = true;
      if (parsed.sandbox?.enabled === true) sandbox = true;
      if (parsed.hooks && Object.keys(parsed.hooks).length > 0) hooks = true;
    }
    const broad = [...new Set(allow.map(broadAllow).filter((x): x is string => !!x))];
    if (bypass) broad.push('defaultMode: bypassPermissions');
    const posture: NodePosture = {};
    if (broad.length > 0) posture.commandAllowScope = 'Broad';
    if (sandbox) posture.agentSandbox = 'Enforced';
    const tools = [...new Set(allow.map(toolName).filter((n) => /^[\w.:-]{1,40}$/.test(n)))].sort();
    agent = addNode({
      id: 'repo-agent',
      type: 'AGENT',
      x: COL.agent,
      y: TOP,
      label: t('repo.node.agent'),
      description:
        t('repo.desc.agent', {
          allow: allow.length,
          tools: tools.join(', ') || '-',
          deny: deny.length,
          sandbox: t(sandbox ? 'repo.word.enabled' : 'repo.word.unset'),
          hooks: t(hooks ? 'repo.word.yes' : 'repo.word.no'),
        }) + (broad.length > 0 ? t('repo.desc.broad', { entries: broad.join(', ') }) : ''),
      ...(Object.keys(posture).length > 0 ? { posture } : {}),
      inventory: {
        kind: 'agent',
        source: '.claude/',
        collectedAt: opts.collectedAt,
        allowCount: allow.length,
        denyCount: deny.length,
        tools,
        broadAllows: broad,
        sandbox,
        hooks,
        items: [
          ...[...skillNames].sort().map((name) => ({ name, kind: 'skill' as const })),
          ...[...commandNames].sort().map((name) => ({ name: `/${name}`, kind: 'command' as const })),
        ],
      },
    });
    addEdge(agent.id, pc.id, 'None', 'VPC', 'Plain', { dataFlow: 'bidirectional' });

    // skill・command は 1 件ずつ描くと図が読めなくなるため、種類ごとに 1 ノードへ集約する。
    // 名前の一覧はエージェントのインベントリに置き、ダッシュボードで見る（steps-2026-11 §2.112）。
    const addSkillGroup = (id: string, count: number, label: string) => {
      if (count === 0) return;
      const n = addNode({ id, type: 'AGENT_SKILL', ...place(true), label });
      internalIds.push(n.id);
      addEdge(agent!.id, n.id, 'None', 'VPC', 'Plain', { dataFlow: 'outbound' });
    };
    addSkillGroup('repo-skills', skillNames.size, t('repo.node.skills', { count: skillNames.size }));
    addSkillGroup('repo-commands', commandNames.size, t('repo.node.commands', { count: commandNames.size }));
  }

  // ── MCP サーバー ──
  let mcpCount = 0;
  if (mcpFile) {
    let servers: NonNullable<z.infer<typeof McpSchema>['mcpServers']> = {};
    try {
      servers = McpSchema.parse(JSON.parse(mcpFile.text)).mcpServers ?? {};
    } catch {
      warn('.mcp.json: JSON として読み込めません');
    }
    for (const [name, s] of Object.entries(servers).sort(([a], [b]) => (a < b ? -1 : 1))) {
      mcpCount++;
      const envKeys = Object.keys(s.env ?? {}).sort().join(', ') || '-';
      const remote = hostOf(s.url);
      const isRemote = s.url !== undefined && !s.command;
      const internal = !isRemote || (remote !== undefined && isInternalHost(remote.host));
      let description: string;
      if (isRemote) {
        description = t('repo.desc.mcpRemote', {
          host: remote?.host ?? '-',
          headers: Object.keys(s.headers ?? {}).sort().join(', ') || '-',
          env: envKeys,
        });
      } else {
        const exe = baseOf((s.command ?? '').trim().split(/\s+/)[0].replace(/\\/g, '/')) || '-';
        description = t('repo.desc.mcpStdio', { exe, env: envKeys });
      }
      const n = addNode({
        id: `repo-mcp-${slug(name)}`,
        type: 'MCP_SERVER',
        ...place(internal),
        label: name,
        description,
        ...(isRemote ? {} : { attackSurface: { hasGlobalIp: false } }),
      });
      (internal ? internalIds : externalIds).push(n.id);
      if (agent) {
        const headerKeys = Object.keys(s.headers ?? {});
        addEdge(
          agent.id,
          n.id,
          isRemote ? (headerKeys.length > 0 ? 'Token' : 'None') : 'None',
          isRemote ? (internal ? 'VPC' : 'Internet') : 'VPC',
          isRemote ? (remote && !remote.plain ? 'TLS' : 'Plain') : 'Plain',
          { dataFlow: 'bidirectional', semantic: 'tool_invocation' },
        );
      }
    }
  }

  // ── 依存パッケージ ──
  let manifestCount = 0;
  let packageCount = 0;
  let scriptPackages = 0;
  const registries = new Map<string, { plain: boolean; id: string }>();
  const ensureRegistry = (host: string, plain: boolean): string => {
    const known = registries.get(host);
    if (known) {
      known.plain = known.plain || plain;
      return known.id;
    }
    const internal = isInternalHost(host);
    const n = addNode({
      id: `repo-registry-${slug(host)}`,
      type: 'PACKAGE_REGISTRY',
      ...place(internal),
      label: t('repo.node.registry', { host }),
    });
    (internal ? internalIds : externalIds).push(n.id);
    registries.set(host, { plain, id: n.id });
    return n.id;
  };
  const registryEdges: Array<{ dep: string; host: string }> = [];

  const addManifest = (
    path: string,
    kind: 'npm' | 'pypi',
    parsed: ParsedManifest,
    posture: NodePosture,
    defaultHost: string,
    extraHosts?: Map<string, boolean>,
  ) => {
    manifestCount++;
    packageCount += parsed.items.length;
    const scripts = parsed.items.filter((i) => i.hasInstallScript).length;
    scriptPackages += scripts;
    const dep = addNode({
      id: `repo-deps-${slug(path)}`,
      type: 'PACKAGE_DEPENDENCIES',
      ...place(true),
      label: path,
      description: t('repo.desc.deps', {
        kind,
        count: parsed.items.length,
        scripts,
        lock: t(parsed.locked ? 'repo.word.locked' : 'repo.word.unlocked'),
      }),
      ...(Object.keys(posture).length > 0 ? { posture } : {}),
      inventory: { kind, source: path, collectedAt: opts.collectedAt, items: parsed.items },
    });
    internalIds.push(dep.id);
    if (agent) addEdge(agent.id, dep.id, 'None', 'VPC', 'Plain', { dataFlow: 'outbound' });
    const hosts = new Map(parsed.hosts);
    for (const [h, p] of extraHosts ?? []) hosts.set(h, (hosts.get(h) ?? false) || p);
    if (hosts.size === 0) hosts.set(defaultHost, false);
    for (const [host, plain] of hosts) {
      ensureRegistry(host, plain);
      registryEdges.push({ dep: dep.id, host });
    }
  };

  const npmrcFor = (dir: string) => {
    for (let d = dir; ; d = dirOf(d)) {
      const f = byPath.get(d ? `${d}/.npmrc` : '.npmrc');
      if (f) return parseNpmrc(f.text);
      if (d === '') return undefined;
    }
  };

  for (const f of manifestsNpm) {
    const dir = dirOf(f.path);
    const lock = byPath.get(dir ? `${dir}/package-lock.json` : 'package-lock.json');
    const parsed = parseNpm(f.text, lock?.text, warn, f.path);
    if (!parsed) continue;
    const npmrc = npmrcFor(dir);
    const posture: NodePosture = { dependencyLockfile: parsed.locked ? 'Locked' : 'Unlocked' };
    if (npmrc?.ignoreScripts) posture.installScripts = 'Disabled';
    else if (parsed.items.some((i) => i.hasInstallScript)) posture.installScripts = 'Allowed';
    addManifest(f.path, 'npm', parsed, posture, 'registry.npmjs.org', npmrc?.hosts);
  }
  for (const f of manifestsPip) {
    const parsed = parsePip(f.text);
    addManifest(f.path, 'pypi', parsed, { dependencyLockfile: parsed.locked ? 'Locked' : 'Unlocked' }, 'pypi.org');
  }
  for (const { dep, host } of registryEdges) {
    const r = registries.get(host)!;
    const internal = isInternalHost(host);
    addEdge(dep, r.id, 'None', internal ? 'VPC' : 'Internet', r.plain ? 'Plain' : 'TLS', { dataFlow: 'bidirectional' });
  }

  // ── 信頼境界：開発端末＝Internal（Office Area）、外部＝Internet ──
  const boundaries: DiagramBoundary[] = [];
  const box = (
    id: string,
    ids: string[],
    type: DiagramBoundary['type'],
    trustLevel: DiagramBoundary['trustLevel'],
    extra: Partial<DiagramBoundary> = {},
  ) => {
    const members = nodes.filter((n) => ids.includes(n.id));
    if (members.length === 0) return;
    const PAD = 40;
    const x = Math.min(...members.map((n) => n.x)) - PAD;
    const y = Math.min(...members.map((n) => n.y)) - PAD - 30;
    const right = Math.max(...members.map((n) => n.x + 128)) + PAD;
    const bottom = Math.max(...members.map((n) => n.y + 96)) + PAD;
    boundaries.push({ id, type, x, y, width: right - x, height: bottom - y, trustLevel, ...extra });
  };
  box('repo-b-dev', [pc.id, ...(agent ? [agent.id] : []), ...internalIds], 'ROUNDED', 'Internal', {
    macroTrust: 'Office Area',
  });
  box('repo-b-internet', externalIds, 'RECT', 'Internet');

  return {
    ok: true,
    name: t('repo.templateName'),
    layer: { nodes, edges, boundaries, annotations: [] },
    summary: {
      manifests: manifestCount,
      packages: packageCount,
      installScriptPackages: scriptPackages,
      envFiles: envCount,
      mcpServers: mcpCount,
      skills: skillNames.size,
      commands: commandNames.size,
      warnings,
    },
  };
}
