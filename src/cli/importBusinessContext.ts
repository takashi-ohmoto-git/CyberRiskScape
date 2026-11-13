import { deserializeProject } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import { applyBusinessContext, type ApplyBusinessContextSummary } from '../features/business-context/applyBusinessContext';
import type { BusinessContextTable } from '../features/business-context/parseBusinessContextTable';

/**
 * CLI `import-business-context`：業務の文脈の表（CSV / JSON）を読み、ノードの businessContext に反映する。
 * 表の形式と重要度の決め方は features/business-context。ファイル I/O は呼び出し側（main.ts）。
 */

export interface ImportBusinessContextOutput {
  project: PersistedProject;
  summary: ApplyBusinessContextSummary;
}

export function importBusinessContext(rawProject: unknown, table: BusinessContextTable, now: Date = new Date()): ImportBusinessContextOutput {
  const loaded = deserializeProject(rawProject);
  if (!loaded) throw new Error('プロジェクト JSON の形式が不正です。');
  const r = applyBusinessContext(loaded.layers ?? {}, table.rows, { now, ...(table.source ? { source: table.source } : {}) });
  const project: PersistedProject = { ...loaded };
  if (loaded.layers) project.layers = r.layers as NonNullable<PersistedProject['layers']>;
  return { project, summary: r.summary };
}

const nodeName = (n: { seq?: number; nodeId: string; label?: string }): string =>
  `${n.seq !== undefined ? `C${n.seq}` : n.nodeId}${n.label ? ` ${n.label}` : ''}`;

export function businessContextReportToText(s: ApplyBusinessContextSummary): string {
  const basis = { value: '金額', cases: '件数', none: 'なし' }[s.basis];
  const lines = [
    '# 業務の文脈の取り込み',
    '',
    `- 表の行: ${s.rows} / 反映したノード: ${s.applied.length} / 決められず見送り: ${s.skipped.length} / 図に無い参照: ${s.unknownRefs.length} / 特定できない参照: ${s.ambiguousRefs.length}`,
    `- 割合の基準: ${basis}（30% 以上=High・10% 以上=Medium・それ未満=Low。行に重要度があればそれを優先）`,
    '',
  ];
  for (const a of s.applied) {
    const how = a.criticalitySource === 'declared' ? '表に記載' : `割合から${a.share !== undefined ? ` ${(a.share * 100).toFixed(1)}%` : ''}`;
    lines.push(`- ${nodeName(a)}: ${a.criticality}（${how}・プロセス ${a.processCount} 件）`);
  }
  for (const k of s.skipped) lines.push(`- ${nodeName(k)}: 重要度を決められないため見送り（表に criticality・金額・件数のどれも無い）`);
  if (s.unknownRefs.length > 0) lines.push('', `図に無いノードの参照: ${s.unknownRefs.join(', ')}`);
  if (s.ambiguousRefs.length > 0) lines.push('', `複数のノードに当たる参照（ID で指定してください）: ${s.ambiguousRefs.join(', ')}`);
  for (const n of s.notes) lines.push(`- 注意: ${n}`);
  return lines.join('\n');
}

export function businessContextReportToJson(s: ApplyBusinessContextSummary): Record<string, unknown> {
  return { schemaVersion: 1, kind: 'cyberriskscape-business-context-import-report', ...s };
}
