import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { getLocale, translate } from '../../i18n';
import type { RepoFile } from './repoToLayer';

/**
 * `import-repo` の収集部（CLI 専用）。ディレクトリを辿り、`repoToLayer` が読む対象ファイルだけを集める。
 * 秘密の扱い（`.env` の値を捨てる等）は `repoToLayer` 側。ここは「何を読むか」と上限だけを決める。
 *
 * - `node_modules`・`.git`・ビルド出力などは辿らない。シンボリックリンクは辿らない（リポジトリ外を読まない）。
 * - 深さ・読むファイル数・1 ファイルのサイズに上限があり、超えたら読み飛ばして警告に積む。
 * - `.claude/skills`・`.claude/commands` は名前だけ使うので中身は読まない（text は空）。
 */

export const LIMITS = {
  maxDepth: 8,
  maxFiles: 500,
  maxNameOnly: 2000,
  maxFileBytes: 10 * 1024 * 1024,
} as const;

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'dist-cli',
  'build',
  'out',
  '.next',
  '.nuxt',
  '.turbo',
  '.cache',
  '.venv',
  'venv',
  '__pycache__',
  'target',
  'coverage',
]);

const isTargetName = (name: string) =>
  name === 'package.json' ||
  name === 'package-lock.json' ||
  name === '.npmrc' ||
  name === '.env' ||
  name.startsWith('.env.') ||
  /(^|[-_.])requirements[\w.-]*\.(txt|lock|in)$/i.test(name);

export interface CollectedRepo {
  files: RepoFile[];
  repoName: string;
  /** `.env` 系ファイルの相対パス → git 管理外か（git が使えない・リポジトリでないときは含まない）。 */
  gitIgnored: Record<string, boolean>;
  warnings: string[];
}

/** `git check-ignore` で管理外かを調べる。引数は配列で渡し、シェルを経由しない。 */
function checkIgnored(root: string, relPath: string): boolean | undefined {
  try {
    execFileSync('git', ['-C', root, 'check-ignore', '-q', '--', relPath], { stdio: 'ignore' });
    return true;
  } catch (e) {
    return (e as { status?: number }).status === 1 ? false : undefined;
  }
}

export function collectRepo(dir: string): CollectedRepo {
  const t = (key: Parameters<typeof translate>[0], params?: Record<string, string | number>) =>
    translate(key, getLocale(), params);
  const root = resolve(dir);
  const files: RepoFile[] = [];
  const warnings: string[] = [];
  let textCount = 0;
  let nameOnlyCount = 0;
  let warnedFiles = false;
  let warnedDepth = false;

  const readTarget = (rel: string, abs: string) => {
    if (textCount >= LIMITS.maxFiles) {
      if (!warnedFiles) warnings.push(t('repo.warn.maxFiles', { max: LIMITS.maxFiles }));
      warnedFiles = true;
      return;
    }
    try {
      if (statSync(abs).size > LIMITS.maxFileBytes) {
        warnings.push(t('repo.warn.tooLarge', { path: rel }));
        return;
      }
      files.push({ path: rel, text: readFileSync(abs, 'utf-8') });
      textCount++;
    } catch {
      warnings.push(t('repo.warn.unreadable', { path: rel }));
    }
  };

  const nameOnly = (rel: string) => {
    if (nameOnlyCount++ < LIMITS.maxNameOnly) files.push({ path: rel, text: '' });
  };

  /** `.claude/skills`・`.claude/commands` 配下（名前だけ）。 */
  const walkNames = (rel: string, abs: string, depth: number) => {
    if (depth > LIMITS.maxDepth) return;
    for (const e of readdirSync(abs, { withFileTypes: true })) {
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) walkNames(`${rel}/${e.name}`, join(abs, e.name), depth + 1);
      else if (e.isFile()) nameOnly(`${rel}/${e.name}`);
    }
  };

  const walk = (rel: string, abs: string, depth: number) => {
    let entries;
    try {
      entries = readdirSync(abs, { withFileTypes: true });
    } catch {
      warnings.push(t('repo.warn.unreadable', { path: rel || '.' }));
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      const childAbs = join(abs, e.name);
      if (e.isDirectory()) {
        if (rel === '' && e.name === '.claude') {
          for (const sub of ['skills', 'commands']) {
            try {
              walkNames(`.claude/${sub}`, join(childAbs, sub), 1);
            } catch {
              // ディレクトリが無ければ何もしない
            }
          }
          continue;
        }
        if (SKIP_DIRS.has(e.name)) continue;
        if (depth + 1 > LIMITS.maxDepth) {
          if (!warnedDepth) warnings.push(t('repo.warn.maxDepth', { max: LIMITS.maxDepth }));
          warnedDepth = true;
          continue;
        }
        walk(childRel, childAbs, depth + 1);
      } else if (e.isFile()) {
        if (rel === '' && e.name === '.mcp.json') readTarget(childRel, childAbs);
        else if (isTargetName(e.name)) readTarget(childRel, childAbs);
      }
    }
  };

  // `.claude/settings*.json` は直下のファイルだけ読む。
  walk('', root, 0);
  for (const name of ['settings.json', 'settings.local.json']) {
    try {
      if (statSync(join(root, '.claude', name)).isFile()) readTarget(`.claude/${name}`, join(root, '.claude', name));
    } catch {
      // 無ければ何もしない
    }
  }

  const gitIgnored: Record<string, boolean> = {};
  for (const f of files) {
    const name = f.path.slice(f.path.lastIndexOf('/') + 1);
    if (name === '.env' || name.startsWith('.env.')) {
      const r = checkIgnored(root, f.path);
      if (r !== undefined) gitIgnored[f.path] = r;
    }
  }

  return { files, repoName: basename(root), gitIgnored, warnings };
}
