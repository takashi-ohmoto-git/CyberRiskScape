import { resolveProject } from './analyze';
import { LAYER_KEYS } from '../core/model/types';
import { formatElementalId } from '../core/model/elementalId';
import { deserializeProject } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import { applyEpss, type EpssScores } from '../features/epss-import/applyEpss';

/**
 * CLI `import-epss`：利用者が渡した FIRST EPSS の CSV を保存済みの指摘と照合し、`epss` を付け外しする
 * （docs/architecture.md §8.11）。ファイル I/O は呼び出し側（main.ts）。
 */

export interface ImportEpssOutput {
  project: PersistedProject;
  /** CSV の score_date（文字列のまま）。 */
  date?: string;
  modelVersion?: string;
  /** CSV の読めなかった行の数。 */
  invalid: number;
  checked: number;
  matched: number;
  removed: number;
  /** epss が付いている指摘のノード別の件数（未結合は node が null）。 */
  byNode: { node: string | null; count: number }[];
}

export function importEpss(rawProject: unknown, parsed: Pick<EpssScores, 'scores' | 'date' | 'modelVersion' | 'invalid'>): ImportEpssOutput {
  const resolved = resolveProject(rawProject);
  const loaded = deserializeProject(rawProject);
  if (!loaded) throw new Error('プロジェクト JSON の形式が不正です。');

  const r = applyEpss(loaded.findings ?? [], parsed);

  const nodeName = new Map<string, string>();
  for (const layer of LAYER_KEYS) {
    for (const n of resolved.layers[layer].nodes) {
      nodeName.set(`${layer}:${n.id}`, `${n.seq != null ? formatElementalId('node', n.seq) : n.id} ${n.label?.trim() || n.type}`);
    }
  }
  const counts = new Map<string | null, number>();
  for (const f of r.findings) {
    if (!f.epss) continue;
    const key = f.subject ? (nodeName.get(`${f.subject.layer}:${f.subject.nodeId}`) ?? null) : null;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  const project: PersistedProject = { ...loaded };
  if (r.findings.length > 0) project.findings = r.findings;
  else delete project.findings;
  return {
    project,
    ...(parsed.date ? { date: parsed.date } : {}),
    ...(parsed.modelVersion ? { modelVersion: parsed.modelVersion } : {}),
    invalid: parsed.invalid,
    checked: r.checked,
    matched: r.matched,
    removed: r.removed,
    byNode: [...counts].map(([node, count]) => ({ node, count })),
  };
}

export function epssReportToMarkdown(out: ImportEpssOutput): string {
  const lines = [
    '# EPSS 照合レポート',
    '',
    '- EPSS は 30 日以内に悪用の動きが観測される確率の推定で、悪用の事実ではない。低いことは「悪用されない」を意味しない。',
    `- スコア日: ${out.date ?? '不明'} / モデル版: ${out.modelVersion ?? '不明'}`,
    `- 照合した指摘（CVE を持つもの）: ${out.checked} 件 / epss を付けた指摘: ${out.matched} 件 / 外した指摘: ${out.removed} 件 / 読めなかった CSV の行: ${out.invalid} 行`,
    '',
  ];
  if (out.byNode.length > 0) {
    lines.push('## ノード別（epss が付いている指摘）', '');
    for (const b of out.byNode) lines.push(`- ${b.node ?? '（未結合）'}: ${b.count} 件`);
    lines.push('');
  }
  lines.push('- epss は --out のプロジェクト JSON に保存され、`findings-priority` が優先度（悪用状況）に使う');
  return lines.join('\n');
}

/** 機械処理用の JSON オブジェクト（キーは英語固定）。 */
export function epssReportToJson(out: ImportEpssOutput): Record<string, unknown> {
  return {
    schemaVersion: 1,
    kind: 'cyberriskscape-epss-import-report',
    date: out.date ?? null,
    modelVersion: out.modelVersion ?? null,
    invalidRows: out.invalid,
    checked: out.checked,
    matched: out.matched,
    removed: out.removed,
    byNode: out.byNode,
  };
}
