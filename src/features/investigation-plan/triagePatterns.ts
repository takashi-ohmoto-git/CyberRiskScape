import type { InvestigationViewpoint } from './viewpoints';

/**
 * 調査観点の `tools.triage` を 1 つのパターンファイル（`tools/triage/crs_triage.py --patterns`）にまとめる。
 * 正規表現は大文字小文字を区別せずに使われる。Python と JS で共通の構文に限ること。
 */

export const TRIAGE_PATTERNS_FORMAT = 'cyberriskscape-triage-patterns';

export interface TriagePatternsFile {
  format: typeof TRIAGE_PATTERNS_FORMAT;
  version: 1;
  id: string;
  logPatterns: { id: string; category: string; regex: string; priority: number }[];
  accessLog?: { method: string; statuses: number[] };
  webroot?: { extensions: string[]; filenames: string[] };
  notes: string[];
}

export function buildTriagePatterns(viewpoints: InvestigationViewpoint[], id = 'compromise'): TriagePatternsFile {
  const out: TriagePatternsFile = { format: TRIAGE_PATTERNS_FORMAT, version: 1, id, logPatterns: [], notes: [] };
  const uniq = (xs: string[]) => [...new Set(xs)];
  for (const vp of viewpoints) {
    const t = vp.tools?.triage;
    if (!t) continue;
    for (const p of t.logPatterns) {
      if (out.logPatterns.some((x) => x.id === p.id)) {
        throw new Error(`[triage-patterns] duplicate pattern id "${p.id}"`);
      }
      out.logPatterns.push({ ...p });
    }
    if (t.accessLog) {
      if (out.accessLog && out.accessLog.method !== t.accessLog.method) {
        throw new Error('[triage-patterns] accessLog.method differs between viewpoints');
      }
      const statuses = [...(out.accessLog?.statuses ?? []), ...t.accessLog.statuses];
      out.accessLog = { method: t.accessLog.method, statuses: [...new Set(statuses)].sort((a, b) => a - b) };
    }
    if (t.webroot) {
      out.webroot = {
        extensions: uniq([...(out.webroot?.extensions ?? []), ...t.webroot.extensions]),
        filenames: uniq([...(out.webroot?.filenames ?? []), ...t.webroot.filenames]),
      };
    }
    out.notes.push(...(t.notes ?? []));
  }
  out.notes = uniq(out.notes);
  return out;
}
