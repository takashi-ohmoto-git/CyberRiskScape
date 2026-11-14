import { resolveProject } from './analyze';
import { normalizeScopeValue, type ServiceScopeEntry, type ServiceScopeKind } from '../core/model/serviceScope';

/**
 * CLI `export-scope`：サービスの担当範囲（projectMeta.serviceScope）を、ASM・DAST・ペンテストの探索の起点として
 * 書き出す（docs/org-view.md §2.3）。値は正規化して出す。解釈できない値は出さずに `invalid` に並べる。
 * ファイル I/O は呼び出し側（main.ts）。
 */

export interface ExportScopeResult {
  schemaVersion: 1;
  kind: 'cyberriskscape-service-scope';
  projectId?: string;
  entries: ServiceScopeEntry[];
  invalid: ServiceScopeEntry[];
}

export function exportScope(rawProject: unknown, kind?: ServiceScopeKind): ExportScopeResult {
  const resolved = resolveProject(rawProject);
  const entries: ServiceScopeEntry[] = [];
  const invalid: ServiceScopeEntry[] = [];
  for (const e of resolved.projectMeta.serviceScope ?? []) {
    if (kind && e.kind !== kind) continue;
    const value = normalizeScopeValue(e.kind, e.value);
    if (value === undefined) invalid.push(e);
    else if (!entries.some((x) => x.kind === e.kind && x.value === value)) entries.push({ ...e, value });
  }
  return {
    schemaVersion: 1,
    kind: 'cyberriskscape-service-scope',
    ...(resolved.projectId ? { projectId: resolved.projectId } : {}),
    entries,
    invalid,
  };
}

/**
 * 1 行 1 件で出す。種類を絞ったときは値だけ（ASM・スキャナーの入力にそのまま渡せる形）、
 * 絞らないときは `種類<TAB>値`（ホストとドメイン配下の区別が値だけでは付かないため）。
 */
export function exportScopeToText(r: ExportScopeResult, kind?: ServiceScopeKind): string {
  const lines = r.entries.map((e) => (kind ? e.value : `${e.kind}\t${e.value}`));
  return lines.join('\n') + (lines.length ? '\n' : '');
}
