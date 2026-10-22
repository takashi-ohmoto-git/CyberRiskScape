import { z } from 'zod';
import { formatLocalDate } from '../../core/model/localDate';
import { getInvestigationViewpoints } from '../investigation-plan/viewpoints';

/**
 * 侵害調査の証拠（トリアージツールの JSON・Velociraptor の収集結果）を、ホスト単位の共通の形にする。
 *
 * - 入力は信頼できないデータとして扱う。Zod でゆるく検証し（未知キーは無視）、長い文字列は切り詰める。
 *   証拠の内容を実行・評価しない。
 * - どの artifact の行を「痕跡」とみなすかは `data/investigation-templates/compromise.yaml`
 *   （`tools.velociraptor[].findings`）が決める。コードは持たない。
 * - ファイルの読み込み（fs）は `src/cli/readEvidence.ts`。ここは読み込み済みの値を受け取る純粋関数。
 */

export const MAX_TEXT = 200;
export const MAX_TOP = 5;
const MAX_CATEGORIES = 50;
const MAX_REFERENCE = 100;

export type EvidenceSource = 'triage' | 'velociraptor';

export interface EvidenceHit {
  /** 分類（トリアージ）または artifact 名（Velociraptor）。 */
  category: string;
  location: string;
  content: string;
}

export interface EvidenceCount {
  name: string;
  count: number;
}

export interface EvidenceSkip {
  path: string;
  reason: string;
}

/** 調べた期間の観測値。日付は `YYYY-MM-DD`（文字列の先頭を使い、UTC への変換はしない）。 */
export interface ObservedPeriod {
  from: string;
  to?: string;
}

export interface HostEvidence {
  source: EvidenceSource;
  /** 証拠のホスト名（無ければ空文字）。 */
  host: string;
  /** 証拠の場所（ファイルまたはフォルダー）。 */
  path: string;
  /** 収集日時 `YYYY-MM-DD`（不明なら undefined）。 */
  collectedAt?: string;
  observed?: ObservedPeriod;
  /** 痕跡を探す結果（トリアージ、または findings の artifact）が 1 つでも含まれるか。 */
  searched: boolean;
  traceCount: number;
  categories: EvidenceCount[];
  top: EvidenceHit[];
  /** 参考情報の artifact（件数だけ）。 */
  reference: EvidenceCount[];
  /** YAML に載っていない artifact（件数だけ）。 */
  unmapped: EvidenceCount[];
  /** 読めなかったもの。 */
  skipped: EvidenceSkip[];
}

export const clip = (s: unknown, max = MAX_TEXT): string => {
  const text = typeof s === 'string' ? s : s == null ? '' : String(s);
  const one = text.replace(/[\r\n\t]+/g, ' ').trim();
  return one.length > max ? `${one.slice(0, max)}…` : one;
};

/** 日時文字列の先頭 `YYYY-MM-DD` を返す。形式が違えば undefined。 */
export function datePart(s: unknown): string | undefined {
  if (typeof s !== 'string') return undefined;
  const m = /^(\d{4}-\d{2}-\d{2})/.exec(s.trim());
  return m ? m[1] : undefined;
}

// ── トリアージの JSON ──

const TriageSchema = z.object({
  format: z.literal('cyberriskscape-triage'),
  host: z.string().optional(),
  collectedAt: z.string().optional(),
  scanned: z.array(z.object({ firstTime: z.string().nullish() })).default([]),
  skipped: z.array(z.object({ path: z.string(), reason: z.string().optional() })).default([]),
  hits: z
    .array(
      z.object({
        category: z.string().optional(),
        pattern: z.string().optional(),
        path: z.string().optional(),
        line: z.number().nullish(),
        content: z.string().optional(),
      }),
    )
    .default([]),
});

export function isTriageJson(raw: unknown): boolean {
  return typeof raw === 'object' && raw !== null && (raw as { format?: unknown }).format === 'cyberriskscape-triage';
}

export type ParseResult = { ok: true; evidence: HostEvidence } | { ok: false; error: string };

function tally(names: Iterable<string>, limit: number): EvidenceCount[] {
  const m = new Map<string, number>();
  for (const n of names) m.set(n, (m.get(n) ?? 0) + 1);
  return [...m.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
    .slice(0, limit);
}

export function parseTriageEvidence(raw: unknown, path: string): ParseResult {
  const parsed = TriageSchema.safeParse(raw);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    return { ok: false, error: clip(issue ? `${issue.path.join('.')}: ${issue.message}` : 'invalid') };
  }
  const d = parsed.data;

  // 調べた期間の観測値: 走査したファイルの先頭時刻のうち最も古いもの 〜 収集日時。
  let earliest: { ms: number; date: string } | undefined;
  for (const s of d.scanned) {
    const date = datePart(s.firstTime);
    const ms = s.firstTime ? Date.parse(s.firstTime) : NaN;
    if (date && !Number.isNaN(ms) && (!earliest || ms < earliest.ms)) earliest = { ms, date };
  }
  const collectedAt = datePart(d.collectedAt);

  const category = (h: (typeof d.hits)[number]) => clip(h.category || h.pattern || '?', 80);
  return {
    ok: true,
    evidence: {
      source: 'triage',
      host: clip(d.host, 255),
      path,
      ...(collectedAt ? { collectedAt } : {}),
      ...(earliest ? { observed: { from: earliest.date, ...(collectedAt ? { to: collectedAt } : {}) } } : {}),
      searched: true,
      traceCount: d.hits.length,
      categories: tally(d.hits.map(category), MAX_CATEGORIES),
      top: d.hits.slice(0, MAX_TOP).map((h) => ({
        category: category(h),
        location: clip(`${h.path ?? ''}${h.line != null ? `:${h.line}` : ''}`),
        content: clip(h.content),
      })),
      reference: [],
      unmapped: [],
      skipped: d.skipped.map((s) => ({ path: clip(s.path), reason: clip(s.reason) })),
    },
  };
}

// ── Velociraptor の収集結果 ──

/** ファイルシステムから読み込んだ、1 つの収集（`results/` を持つフォルダー）の生の値。 */
export interface VelociraptorRaw {
  path: string;
  clientInfo?: unknown;
  /** `log.json` の `_ts`（epoch 秒）の最小値。 */
  minLogTs?: number;
  results: { fileName: string; rows: unknown[]; unreadable: string[] }[];
  /** 読めなかったファイルなど（理由は呼び出し側で作る）。 */
  skipped: EvidenceSkip[];
}

export interface ArtifactKnowledge {
  /** artifact 名 → 痕跡とみなすか。YAML に無い artifact は含まれない。 */
  findings: Map<string, boolean>;
}

/** YAML（`tools.velociraptor`）から、artifact ごとの扱いを引く。 */
export function loadArtifactKnowledge(): ArtifactKnowledge {
  const findings = new Map<string, boolean>();
  for (const v of getInvestigationViewpoints('ja')) {
    for (const step of v.tools?.velociraptor ?? []) {
      findings.set(step.artifact, (findings.get(step.artifact) ?? false) || step.findings === true);
    }
  }
  return { findings };
}

/** `results/` のファイル名 → artifact 名。`%2F` 以降のソース名は落とす。 */
export function artifactNameOf(fileName: string): string {
  const base = fileName.replace(/\.json$/i, '');
  let decoded = base;
  try {
    decoded = decodeURIComponent(base);
  } catch {
    // 壊れたエスケープはそのまま使う
  }
  return clip(decoded.split('/')[0] ?? decoded, 120);
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

export function buildVelociraptorEvidence(raw: VelociraptorRaw, knowledge: ArtifactKnowledge): HostEvidence {
  let host = isObj(raw.clientInfo) && typeof raw.clientInfo.Hostname === 'string' ? raw.clientInfo.Hostname : '';
  if (!host) {
    // client_info.json が無い hunt の書き出し: 行の Fqdn を使う。
    outer: for (const r of raw.results) {
      for (const row of r.rows) {
        if (isObj(row) && typeof row.Fqdn === 'string' && row.Fqdn) {
          host = row.Fqdn;
          break outer;
        }
      }
    }
  }

  const traceNames: string[] = [];
  const top: EvidenceHit[] = [];
  const reference = new Map<string, number>();
  const unmapped = new Map<string, number>();
  const skipped = [...raw.skipped];
  let searched = false;
  for (const r of raw.results) {
    const artifact = artifactNameOf(r.fileName);
    const isFinding = knowledge.findings.get(artifact);
    if (r.unreadable.length > 0) skipped.push(...r.unreadable.map((reason) => ({ path: clip(r.fileName), reason })));
    if (isFinding === undefined) {
      if (r.rows.length > 0) unmapped.set(artifact, (unmapped.get(artifact) ?? 0) + r.rows.length);
    } else if (isFinding) {
      searched = true;
      for (const row of r.rows) {
        traceNames.push(artifact);
        if (top.length < MAX_TOP) top.push({ category: artifact, location: clip(r.fileName), content: clip(JSON.stringify(row)) });
      }
    } else if (r.rows.length > 0) {
      reference.set(artifact, (reference.get(artifact) ?? 0) + r.rows.length);
    }
  }
  const toList = (m: Map<string, number>): EvidenceCount[] =>
    [...m.entries()]
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
      .slice(0, MAX_REFERENCE);

  let collectedAt: string | undefined;
  if (raw.minLogTs !== undefined && Number.isFinite(raw.minLogTs) && raw.minLogTs > 0) {
    const d = new Date(raw.minLogTs * 1000);
    if (!Number.isNaN(d.getTime())) collectedAt = formatLocalDate(d);
  }

  return {
    source: 'velociraptor',
    host: clip(host, 255),
    path: raw.path,
    ...(collectedAt ? { collectedAt } : {}),
    searched,
    traceCount: traceNames.length,
    categories: tally(traceNames, MAX_CATEGORIES),
    top,
    reference: toList(reference),
    unmapped: toList(unmapped),
    skipped,
  };
}
