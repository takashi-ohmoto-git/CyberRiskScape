import type { Finding, FindingEpss } from '../../core/model/types';

/**
 * FIRST EPSS の日次 CSV の照合（docs/architecture.md §8.11）。
 * 利用者が渡した epss_scores の CSV を読み、指摘の CVE 識別子（scheme 'cve'）と突き合わせて `epss` を付け外しする。
 * CSV は同梱せず、ネットワークにも出ない。EPSS は 30 日以内に悪用の動きが観測される確率の推定で、悪用の事実ではない。
 */

/** 読む行数の上限（実物は約 30 万行）。 */
export const MAX_EPSS_ROWS = 1_000_000;

export interface EpssScores {
  /** CVE ID（大文字）→ 確率。 */
  scores: Map<string, { score: number; percentile?: number }>;
  /** 先頭コメントの score_date（文字列のまま）。 */
  date?: string;
  modelVersion?: string;
  /** 読めなかった行の数。 */
  invalid: number;
}

export type ParseEpssResult = ({ ok: true } & EpssScores) | { ok: false; error: string };

const CVE_RE = /^CVE-\d{4}-\d{4,}$/;
const HEADER_ERROR = 'EPSS の CSV の形式が不正です（ヘッダ cve,epss,percentile が必要です）。';

/** 0〜1 の数値だけ受ける（空文字・NaN・範囲外は undefined）。 */
function unit(s: string | undefined): number | undefined {
  if (s === undefined || s.trim() === '') return undefined;
  const n = Number(s);
  return Number.isFinite(n) && n >= 0 && n <= 1 ? n : undefined;
}

/** FIRST の epss_scores CSV（先頭コメント行は任意。ヘッダは cve,epss,percentile）を読む。 */
export function parseEpssCsv(text: string): ParseEpssResult {
  const scores: EpssScores['scores'] = new Map();
  let date: string | undefined;
  let modelVersion: string | undefined;
  let invalid = 0;
  let headerSeen = false;
  let rows = 0;
  let pos = 0;
  while (pos <= text.length) {
    let end = text.indexOf('\n', pos);
    if (end === -1) end = text.length;
    const line = text.slice(pos, end).replace(/\r$/, '').trim();
    pos = end + 1;
    if (line === '') continue;
    if (line.startsWith('#')) {
      for (const part of line.slice(1).split(',')) {
        const i = part.indexOf(':');
        if (i < 0) continue;
        const k = part.slice(0, i).trim();
        const v = part.slice(i + 1).trim();
        if (k === 'score_date' && v) date = v.slice(0, 40);
        if (k === 'model_version' && v) modelVersion = v.slice(0, 50);
      }
      continue;
    }
    if (!headerSeen) {
      const cols = line.toLowerCase().split(',').map((c) => c.trim());
      if (cols[0] !== 'cve' || cols[1] !== 'epss') return { ok: false, error: HEADER_ERROR };
      headerSeen = true;
      continue;
    }
    if (++rows > MAX_EPSS_ROWS) {
      return { ok: false, error: `EPSS の CSV の行数が上限（${MAX_EPSS_ROWS} 行）を超えています。` };
    }
    const cols = line.split(',');
    const cve = cols[0]?.trim().toUpperCase();
    const score = unit(cols[1]);
    if (!cve || !CVE_RE.test(cve) || score === undefined) {
      invalid++;
      continue;
    }
    const percentile = unit(cols[2]);
    scores.set(cve, { score, ...(percentile !== undefined ? { percentile } : {}) });
  }
  if (!headerSeen) return { ok: false, error: HEADER_ERROR };
  return { ok: true, scores, ...(date ? { date } : {}), ...(modelVersion ? { modelVersion } : {}), invalid };
}

export interface EpssApplyResult {
  findings: Finding[];
  /** CVE の識別子を持つ指摘の数（照合の対象）。 */
  checked: number;
  /** 今回 epss が付いている指摘の数。 */
  matched: number;
  /** epss を外した指摘の数（前回は付いていたが、今回の一覧に CVE が無い）。 */
  removed: number;
}

/** 指摘に epss を付け外しした一覧を返す純粋関数。CVE が複数なら最大の score。CVE を持たない指摘は触らない。 */
export function applyEpss(findings: readonly Finding[], parsed: Pick<EpssScores, 'scores' | 'date'>): EpssApplyResult {
  let checked = 0;
  let matched = 0;
  let removed = 0;
  const out = findings.map((f) => {
    const cves = f.identifiers.filter((i) => i.scheme.toLowerCase() === 'cve');
    if (cves.length === 0) return f;
    checked++;
    let best: { score: number; percentile?: number } | undefined;
    for (const i of cves) {
      const hit = parsed.scores.get(i.value.trim().toUpperCase());
      if (hit && (!best || hit.score > best.score)) best = hit;
    }
    if (best) {
      matched++;
      const epss: FindingEpss = {
        score: best.score,
        ...(best.percentile !== undefined ? { percentile: best.percentile } : {}),
        ...(parsed.date ? { date: parsed.date } : {}),
      };
      return { ...f, epss };
    }
    if (f.epss) {
      removed++;
      const { epss: _epss, ...rest } = f;
      return rest;
    }
    return f;
  });
  return { findings: out, checked, matched, removed };
}
