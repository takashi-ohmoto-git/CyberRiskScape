import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { MAX_LINE_BYTES, readEvidence } from './readEvidence';

const root = mkdtempSync(join(tmpdir(), 'crs-evidence-'));
afterAll(() => rmSync(root, { recursive: true, force: true }));

const jsonl = (rows: unknown[]) => `${rows.map((r) => JSON.stringify(r)).join('\n')}\n`;
const write = (path: string, text: string) => {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, text, 'utf-8');
};

/** Velociraptor の collection container を展開した形を合成する。 */
function collection(dir: string, host: string | null, results: Record<string, string>, ts = [1760000100, 1760000000]) {
  if (host !== null) write(join(dir, 'client_info.json'), JSON.stringify({ Hostname: host, HostID: 'C.1' }));
  write(join(dir, 'collection_context.json'), '{}');
  write(join(dir, 'log.json'), jsonl(ts.map((_ts) => ({ _ts, client_time: _ts, level: 'INFO', message: 'm' }))));
  for (const [name, text] of Object.entries(results)) write(join(dir, 'results', name), text);
  mkdirSync(join(dir, 'uploads'), { recursive: true });
}

describe('readEvidence', () => {
  it('Velociraptor の収集（client_info・log.json・results の JSONL・%2F の名前）を読む', () => {
    const dir = join(root, 'c1');
    collection(dir, 'web01', {
      'Linux.Search.FileFinder.json': jsonl([{ FullPath: '/var/www/a.php' }, { FullPath: '/var/www/b.php' }]),
      'Linux.Sys.Pslist.json': jsonl([{ Pid: 1 }]),
      'Generic.Detection.WebShells%2FYaraHits.json': jsonl([{ Rule: 'x' }]),
    });
    const r = readEvidence([dir], 'ja');
    expect(r.rejected).toEqual([]);
    expect(r.evidence).toHaveLength(1);
    const e = r.evidence[0];
    expect(e.source).toBe('velociraptor');
    expect(e.host).toBe('web01');
    expect(e.traceCount).toBe(2);
    expect(e.reference).toEqual([{ name: 'Linux.Sys.Pslist', count: 1 }]);
    expect(e.unmapped).toEqual([{ name: 'Generic.Detection.WebShells', count: 1 }]);
    expect(e.collectedAt).toMatch(/^2025-10-0\d$/);
  });

  it('hunt の書き出し（深い階層に複数の収集）を再帰的に探し、client_info が無ければ Fqdn を使う', () => {
    const hunt = join(root, 'hunt');
    collection(join(hunt, 'a', 'C.1'), 'db01', { 'Linux.Sys.LogGrep.json': jsonl([]) });
    collection(join(hunt, 'b', 'C.2'), null, {
      'Linux.Sys.LogGrep.json': jsonl([{ ClientId: 'C.2', Fqdn: 'app02.example.local', Line: 'x' }]),
    });
    const r = readEvidence([hunt], 'ja');
    expect(r.evidence.map((e) => e.host).sort()).toEqual(['app02.example.local', 'db01']);
  });

  it('トリアージの JSON をファイル・フォルダーのどちらでも読み、他の JSON は無視する', () => {
    const dir = join(root, 't');
    const t = { format: 'cyberriskscape-triage', version: 1, host: 'web01', collectedAt: '2026-10-22T00:00:00', scanned: [], skipped: [], hits: [] };
    write(join(dir, 'sub', 'report.json'), JSON.stringify(t));
    write(join(dir, 'other.json'), '{"a":1}');
    write(join(dir, 'data.csv'), '=cmd|calc');
    const viaDir = readEvidence([dir], 'ja');
    expect(viaDir.evidence).toHaveLength(1);
    expect(viaDir.rejected).toEqual([]);
    const viaFile = readEvidence([join(dir, 'sub', 'report.json'), join(dir, 'other.json')], 'ja');
    expect(viaFile.evidence).toHaveLength(1);
    expect(viaFile.rejected).toHaveLength(1);
  });

  it('不正・巨大な入力で落ちず、理由つきで扱う', () => {
    const dir = join(root, 'bad');
    collection(dir, 'web01', {
      'Linux.Search.FileFinder.json': `${jsonl([{ a: 1 }])}not json\n{"big":"${'x'.repeat(MAX_LINE_BYTES + 10)}"}\n`,
    });
    write(join(root, 'broken.json'), '{ not json');
    write(join(root, 'badtriage.json'), JSON.stringify({ format: 'cyberriskscape-triage', hits: 5 }));
    const r = readEvidence([dir, join(root, 'broken.json'), join(root, 'badtriage.json'), join(root, 'missing.json')], 'ja');
    expect(r.evidence).toHaveLength(1);
    expect(r.evidence[0].traceCount).toBe(1);
    expect(r.evidence[0].skipped.length).toBeGreaterThan(0);
    expect(r.rejected).toHaveLength(3);
  });

  it('results/ が空のフォルダーは理由つきで報告する', () => {
    const dir = join(root, 'empty');
    mkdirSync(join(dir, 'results'), { recursive: true });
    const r = readEvidence([dir], 'ja');
    expect(r.evidence).toEqual([]);
    expect(r.rejected).toHaveLength(1);
  });
});
