import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { readModelHistory, resolveRepoPath } from './gitHistory';

let repo: string;
const run = (...args: string[]) =>
  execFileSync('git', ['-C', repo, ...args], {
    stdio: 'ignore',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Tester One',
      GIT_AUTHOR_EMAIL: 'tester@example.invalid',
      GIT_COMMITTER_NAME: 'Tester One',
      GIT_COMMITTER_EMAIL: 'tester@example.invalid',
    },
  });
const commit = (file: string, body: unknown, msg: string, date: string) => {
  writeFileSync(path.join(repo, file), JSON.stringify(body));
  run('add', '--', file);
  execFileSync('git', ['-C', repo, 'commit', '-q', '-m', msg], {
    stdio: 'ignore',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Tester One',
      GIT_AUTHOR_EMAIL: 'tester@example.invalid',
      GIT_COMMITTER_NAME: 'Tester One',
      GIT_COMMITTER_EMAIL: 'tester@example.invalid',
      GIT_AUTHOR_DATE: date,
      GIT_COMMITTER_DATE: date,
    },
  });
};

beforeAll(() => {
  repo = mkdtempSync(path.join(tmpdir(), 'crs-githist-'));
  run('init', '-q');
  mkdirSync(path.join(repo, 'tm'));
  commit('tm/model.json', { v: 1 }, 'first', '2026-01-01T00:00:00Z');
  commit('other.json', { x: 1 }, 'unrelated', '2026-01-02T00:00:00Z');
  commit('tm/model.json', { v: 2 }, 'second', '2026-01-03T00:00:00Z');
  writeFileSync(path.join(repo, 'tm/model.json'), '{ broken');
  run('add', '--', 'tm/model.json');
  execFileSync('git', ['-C', repo, 'commit', '-q', '-m', 'broken'], {
    stdio: 'ignore',
    env: { ...process.env, GIT_AUTHOR_NAME: 'T', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 'T', GIT_COMMITTER_EMAIL: 't@example.invalid', GIT_AUTHOR_DATE: '2026-01-04T00:00:00Z', GIT_COMMITTER_DATE: '2026-01-04T00:00:00Z' },
  });
});

afterAll(() => {
  rmSync(repo, { recursive: true, force: true });
});

describe('readModelHistory', () => {
  it('指定したファイルの版だけを古い順に返し、作者・時刻・件名を付ける', () => {
    const r = readModelHistory(repo, 'tm/model.json');
    expect(r.snapshots.map((s) => s.raw)).toEqual([{ v: 1 }, { v: 2 }]);
    expect(r.snapshots[0]).toMatchObject({ author: 'Tester One', message: 'first' });
    expect(r.snapshots[0].revision).toMatch(/^[0-9a-f]{40}$/);
    expect(new Date(r.snapshots[1].time).toISOString()).toBe('2026-01-03T00:00:00.000Z');
  });

  it('JSON として読めない版は飛ばして警告する', () => {
    const r = readModelHistory(repo, 'tm/model.json');
    expect(r.warnings.some((w) => w.includes('JSON'))).toBe(true);
  });

  it('--max-commits を超える分は古い側を切り捨てて警告する', () => {
    const r = readModelHistory(repo, 'tm/model.json', { maxCommits: 2 });
    expect(r.snapshots.map((s) => s.raw)).toEqual([{ v: 2 }]);
    expect(r.warnings.some((w) => w.includes('--max-commits'))).toBe(true);
  });

  it('--since で期間を絞れる', () => {
    const r = readModelHistory(repo, 'tm/model.json', { since: '2026-01-02' });
    expect(r.snapshots.map((s) => s.raw)).toEqual([{ v: 2 }]);
  });

  it('不正な --since・--max-commits は失敗する', () => {
    expect(() => readModelHistory(repo, 'tm/model.json', { since: '--all' })).toThrow();
    expect(() => readModelHistory(repo, 'tm/model.json', { maxCommits: 0 })).toThrow();
  });
});

describe('resolveRepoPath', () => {
  it('リポジトリの外・.json 以外・オプションに見える値は拒否する', () => {
    expect(() => resolveRepoPath(repo, '../x.json')).toThrow();
    expect(() => resolveRepoPath(repo, 'tm/model.txt')).toThrow();
    expect(() => resolveRepoPath(repo, '--output=x.json')).not.toThrow(); // リポジトリ内の相対パスとして扱われ、git には -- の後ろで渡る
  });
});
