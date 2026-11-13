import { execFileSync } from 'node:child_process';
import { realpathSync, statSync } from 'node:fs';
import { isAbsolute, normalize, relative, resolve, sep } from 'node:path';
import type { ModelSnapshot } from '../features/event-log/types';

/**
 * `export-event-log` の履歴の読み取り部（CLI 専用、docs/log §2.136）。
 * git の履歴から、指定したモデル JSON の各版（コミットごと）を古い順に取り出す。
 *
 * - git は execFileSync で引数を配列で渡し、シェルを経由しない。パスは `--` の後ろに置き、
 *   リビジョンは 40／64 桁の hex だけを受け付ける（引数の差し込みを防ぐ）。
 * - パスはリポジトリからの相対パスで、リポジトリの外を指せない。
 * - 版の数・1 版の大きさに上限がある。超えたら古い版から読まずに切り捨て、警告に積む。
 * - ファイルを書き込まない（読み取りのみ）。
 */

export const HISTORY_LIMITS = {
  /** 既定で読む版の最大数（新しい側から数える）。 */
  maxCommits: 500,
  /** 指定できる版の最大数。 */
  maxCommitsCap: 5000,
  /** 1 版の最大バイト数（MCP の読み込み上限と同程度）。 */
  maxBytes: 20 * 1024 * 1024,
} as const;

export interface ReadHistoryOptions {
  /** この日時（ISO 8601 の日付・日時）以降のコミットだけ。 */
  since?: string;
  maxCommits?: number;
}

export interface ReadHistoryResult {
  snapshots: ModelSnapshot[];
  warnings: string[];
}

const HASH_RE = /^[0-9a-f]{40}([0-9a-f]{24})?$/;
const SINCE_RE = /^\d{4}-\d{2}-\d{2}(T[0-9:.+\-Z]{1,40})?$/;

function git(repo: string, args: string[], maxBuffer: number): string {
  return execFileSync('git', ['-C', repo, ...args], {
    encoding: 'utf-8',
    maxBuffer,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
}

/** リポジトリのルートと、ルートからの相対パス（/ 区切り）を確かめる。 */
export function resolveRepoPath(repoDir: string, modelPath: string): { root: string; rel: string } {
  if (modelPath.length === 0 || modelPath.length > 1024 || modelPath.includes('\0')) {
    throw new Error('--path が不正です。');
  }
  const dir = resolve(repoDir);
  if (!statSync(dir).isDirectory()) throw new Error(`--repo はディレクトリを指定してください: ${repoDir}`);
  let top: string;
  try {
    top = git(dir, ['rev-parse', '--show-toplevel'], 1024 * 1024).trim();
  } catch {
    throw new Error(`git のリポジトリではありません: ${repoDir}`);
  }
  const root = realpathSync(top);
  const abs = isAbsolute(modelPath) ? normalize(modelPath) : resolve(dir, modelPath);
  const rel = relative(root, abs);
  if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) {
    throw new Error('--path はリポジトリの中のファイルを指定してください。');
  }
  if (!/\.json$/i.test(rel)) throw new Error('--path は拡張子 .json のファイルを指定してください。');
  return { root, rel: rel.split(sep).join('/') };
}

/** 指定パスの各版を古い順に返す。ファイルが無い版（削除されたコミット）は飛ばす。 */
export function readModelHistory(repoDir: string, modelPath: string, opts: ReadHistoryOptions = {}): ReadHistoryResult {
  const { root, rel } = resolveRepoPath(repoDir, modelPath);
  const max = opts.maxCommits ?? HISTORY_LIMITS.maxCommits;
  if (!Number.isInteger(max) || max < 1 || max > HISTORY_LIMITS.maxCommitsCap) {
    throw new Error(`--max-commits は 1〜${HISTORY_LIMITS.maxCommitsCap} の整数で指定してください。`);
  }
  if (opts.since !== undefined && !SINCE_RE.test(opts.since)) {
    throw new Error('--since は YYYY-MM-DD か ISO 8601 の日時で指定してください。');
  }
  const warnings: string[] = [];

  // 区切りは制御文字（US・RS）。作者名に何が入っても行の解析が崩れないようにする。
  const args = ['log', '--no-color', '--no-renames', `--max-count=${max + 1}`, '--format=%H%x1f%cI%x1f%an%x1f%s%x1e'];
  if (opts.since) args.push(`--since=${opts.since}`);
  args.push('--', rel);
  const out = git(root, args, 64 * 1024 * 1024);
  const entries = out
    .split('\x1e')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map((s) => {
      const [hash, time, author, subject] = s.split('\x1f');
      return { hash, time, author, subject };
    })
    .filter((e) => HASH_RE.test(e.hash ?? ''));
  if (entries.length > max) {
    warnings.push(`版が ${max} を超えるため、新しい ${max} 版だけを読みました（--max-commits で増やせます）。`);
    entries.length = max;
  }

  const snapshots: ModelSnapshot[] = [];
  for (const e of entries.reverse()) {
    let text: string;
    try {
      text = git(root, ['show', '--no-color', `${e.hash}:${rel}`], HISTORY_LIMITS.maxBytes + 1);
    } catch {
      // その版にファイルが無い（削除のコミット）・大きすぎる
      warnings.push(`${e.hash.slice(0, 12)}：ファイルを読めないため飛ばしました。`);
      continue;
    }
    if (Buffer.byteLength(text, 'utf-8') > HISTORY_LIMITS.maxBytes) {
      warnings.push(`${e.hash.slice(0, 12)}：大きすぎるため飛ばしました。`);
      continue;
    }
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch {
      warnings.push(`${e.hash.slice(0, 12)}：JSON として読めないため飛ばしました。`);
      continue;
    }
    snapshots.push({
      revision: e.hash,
      time: e.time,
      ...(e.author ? { author: e.author } : {}),
      ...(e.subject ? { message: e.subject } : {}),
      raw,
    });
  }
  return { snapshots, warnings };
}
