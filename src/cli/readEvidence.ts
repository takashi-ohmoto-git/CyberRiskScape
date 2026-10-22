import { closeSync, lstatSync, openSync, readSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { translate, type Locale } from '../i18n';
import {
  buildVelociraptorEvidence,
  clip,
  isTriageJson,
  loadArtifactKnowledge,
  parseTriageEvidence,
  type EvidenceSkip,
  type HostEvidence,
  type VelociraptorRaw,
} from '../features/investigation-report/evidence';
import type { RejectedInput } from '../features/investigation-report/buildInvestigationReport';

/**
 * `investigation-report` の証拠（トリアージの JSON・Velociraptor の収集結果）をファイルから読む。
 * - 読むのは JSON / JSONL だけ（CSV は読まない: Velociraptor の CSV 書き出しには数式インジェクションがある）。zip は読まない。
 * - 入力は信頼できないデータ。シンボリックリンクは辿らない／巨大なファイルは先頭だけ読む／1 行が長すぎる行は読まない。
 *   指定したフォルダーの外へは出ない（子の名前を `join` するだけで、`..` は辿らない）。
 */

export const MAX_FILE_BYTES = 64 * 1024 * 1024;
export const MAX_LINE_BYTES = 1024 * 1024;
const MAX_DEPTH = 8;
const MAX_ENTRIES = 20000;

export interface ReadEvidenceResult {
  evidence: HostEvidence[];
  rejected: RejectedInput[];
}

/** ファイルを最大 MAX_FILE_BYTES だけ読む。 */
function readCapped(file: string, size: number): { text: string; truncated: boolean } {
  const len = Math.min(size, MAX_FILE_BYTES);
  const buf = Buffer.alloc(len);
  const fd = openSync(file, 'r');
  try {
    let off = 0;
    while (off < len) {
      const n = readSync(fd, buf, off, len - off, off);
      if (n === 0) break;
      off += n;
    }
    return { text: buf.subarray(0, off).toString('utf-8'), truncated: size > MAX_FILE_BYTES };
  } finally {
    closeSync(fd);
  }
}

/** 1 行 1 JSON を読む。解析できない行・長すぎる行は数えるだけで捨てる。 */
function readJsonl(file: string, size: number): { rows: unknown[]; badLines: number; truncated: boolean } {
  const { text, truncated } = readCapped(file, size);
  const lines = text.split('\n');
  // 途中で切れた最後の行は捨てる。
  if (truncated) lines.pop();
  const rows: unknown[] = [];
  let badLines = 0;
  for (const line of lines) {
    const l = line.trim();
    if (!l) continue;
    if (l.length > MAX_LINE_BYTES) {
      badLines++;
      continue;
    }
    try {
      rows.push(JSON.parse(l));
    } catch {
      badLines++;
    }
  }
  return { rows, badLines, truncated };
}

function lstatOrNull(p: string) {
  try {
    return lstatSync(p);
  } catch {
    return null;
  }
}

export function readEvidence(paths: string[], locale: Locale): ReadEvidenceResult {
  const t = (key: Parameters<typeof translate>[0], params?: Record<string, string | number>) =>
    translate(key, locale, params);
  const knowledge = loadArtifactKnowledge();
  const evidence: HostEvidence[] = [];
  const rejected: RejectedInput[] = [];
  const reject = (path: string, reason: string) => rejected.push({ path: clip(path, 400), reason });
  let entries = 0;

  /** JSON ファイル 1 つ。explicit=true は利用者が直接指定したもの（対応しない形式は報告する）。 */
  const readJsonFile = (file: string, size: number, explicit: boolean): void => {
    let text: string;
    try {
      text = readCapped(file, size).text;
    } catch {
      reject(file, t('investigationReport.read.notFound'));
      return;
    }
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch {
      if (explicit) reject(file, t('investigationReport.read.notJson'));
      return;
    }
    if (!isTriageJson(raw)) {
      if (explicit) reject(file, t('investigationReport.read.unsupported'));
      return;
    }
    const r = parseTriageEvidence(raw, file);
    if (r.ok) evidence.push(r.evidence);
    else reject(file, t('investigationReport.read.invalid', { error: r.error }));
  };

  const readCollection = (dir: string): void => {
    const skipped: EvidenceSkip[] = [];
    const raw: VelociraptorRaw = { path: dir, results: [], skipped };
    const info = join(dir, 'client_info.json');
    const infoStat = lstatOrNull(info);
    if (infoStat?.isFile() && infoStat.size <= MAX_LINE_BYTES) {
      try {
        raw.clientInfo = JSON.parse(readCapped(info, infoStat.size).text);
      } catch {
        skipped.push({ path: 'client_info.json', reason: t('investigationReport.read.notJson') });
      }
    }
    const log = join(dir, 'log.json');
    const logStat = lstatOrNull(log);
    if (logStat?.isFile()) {
      try {
        let min: number | undefined;
        for (const row of readJsonl(log, logStat.size).rows) {
          const ts = (row as { _ts?: unknown } | null)?._ts;
          if (typeof ts === 'number' && Number.isFinite(ts) && ts > 0 && (min === undefined || ts < min)) min = ts;
        }
        if (min !== undefined) raw.minLogTs = min;
      } catch {
        skipped.push({ path: 'log.json', reason: t('investigationReport.read.notFound') });
      }
    }
    const resultsDir = join(dir, 'results');
    let names: string[] = [];
    try {
      names = readdirSync(resultsDir).filter((n) => /\.json$/i.test(n));
    } catch {
      // 読めない results/ は、結果が無い扱い（下で報告する）
    }
    for (const name of names.slice(0, MAX_ENTRIES)) {
      const file = join(resultsDir, name);
      const st = lstatOrNull(file);
      if (!st) continue;
      if (!st.isFile()) {
        skipped.push({ path: name, reason: t('investigationReport.read.symlink') });
        continue;
      }
      try {
        const r = readJsonl(file, st.size);
        const unreadable: string[] = [];
        if (r.truncated) unreadable.push(t('investigationReport.read.truncated', { mb: MAX_FILE_BYTES / 1024 / 1024 }));
        if (r.badLines > 0) unreadable.push(t('investigationReport.read.badLines', { count: r.badLines }));
        raw.results.push({ fileName: name, rows: r.rows, unreadable });
      } catch {
        skipped.push({ path: name, reason: t('investigationReport.read.notFound') });
      }
    }
    if (raw.results.length === 0 && skipped.length === 0) {
      reject(dir, t('investigationReport.read.noResults'));
      return;
    }
    evidence.push(buildVelociraptorEvidence(raw, knowledge));
  };

  /** フォルダーを再帰的に探す。`results/` を持つフォルダーは 1 つの収集として扱い、その中は辿らない。 */
  const walk = (dir: string, depth: number): void => {
    const rs = lstatOrNull(join(dir, 'results'));
    if (rs?.isDirectory()) {
      readCollection(dir);
      return;
    }
    if (depth >= MAX_DEPTH) return;
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      reject(dir, t('investigationReport.read.notFound'));
      return;
    }
    for (const name of names) {
      if (++entries > MAX_ENTRIES) {
        reject(dir, t('investigationReport.read.tooManyEntries'));
        return;
      }
      const child = join(dir, name);
      const st = lstatOrNull(child);
      if (!st || st.isSymbolicLink()) continue;
      if (st.isDirectory()) walk(child, depth + 1);
      else if (st.isFile() && /\.json$/i.test(name) && st.size <= MAX_FILE_BYTES) readJsonFile(child, st.size, false);
    }
  };

  for (const p of paths) {
    const st = lstatOrNull(p);
    if (!st) reject(p, t('investigationReport.read.notFound'));
    else if (st.isSymbolicLink()) reject(p, t('investigationReport.read.symlink'));
    else if (st.isDirectory()) walk(p, 0);
    else if (st.isFile()) readJsonFile(p, st.size, true);
    else reject(p, t('investigationReport.read.notFound'));
  }
  return { evidence, rejected };
}
