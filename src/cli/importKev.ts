import { resolveProject } from './analyze';
import { LAYER_KEYS } from '../core/model/types';
import { formatElementalId } from '../core/model/elementalId';
import { deserializeProject } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import { applyKev, type KevCatalog } from '../features/kev-import/applyKev';

/**
 * CLI `import-kev`：利用者が渡した CISA KEV カタログを保存済みの指摘と照合し、`kev` の印を付け外しする。
 * ファイル I/O は呼び出し側（main.ts）。
 */

export interface ImportKevOutput {
  project: PersistedProject;
  catalogVersion?: string;
  checked: number;
  marked: number;
  cleared: number;
  /** 印を付けた指摘のノード別の件数（未結合は label が null）。 */
  byNode: { node: string | null; count: number }[];
}

export function importKev(rawProject: unknown, catalog: KevCatalog): ImportKevOutput {
  const resolved = resolveProject(rawProject);
  const loaded = deserializeProject(rawProject);
  if (!loaded) throw new Error('プロジェクト JSON の形式が不正です。');

  const r = applyKev(loaded.findings ?? [], catalog);

  const nodeName = new Map<string, string>();
  for (const layer of LAYER_KEYS) {
    for (const n of resolved.layers[layer].nodes) {
      nodeName.set(`${layer}:${n.id}`, `${n.seq != null ? formatElementalId('node', n.seq) : n.id} ${n.label?.trim() || n.type}`);
    }
  }
  const counts = new Map<string | null, number>();
  for (const f of r.findings) {
    if (!f.kev) continue;
    const key = f.subject ? (nodeName.get(`${f.subject.layer}:${f.subject.nodeId}`) ?? null) : null;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  const project: PersistedProject = { ...loaded };
  if (r.findings.length > 0) project.findings = r.findings;
  else delete project.findings;
  return {
    project,
    ...(catalog.catalogVersion ? { catalogVersion: catalog.catalogVersion } : {}),
    checked: r.checked,
    marked: r.marked,
    cleared: r.cleared,
    byNode: [...counts].map(([node, count]) => ({ node, count })),
  };
}

export function kevReportToMarkdown(out: ImportKevOutput): string {
  const lines = [
    '# KEV 照合レポート',
    '',
    '- CISA KEV に載っている＝CISA が悪用を確認した事実。載っていないことは「悪用されていない」を意味しない。',
    `- カタログ版: ${out.catalogVersion ?? '不明'}`,
    `- 照合した指摘（CVE を持つもの）: ${out.checked} 件 / 印を付けた指摘: ${out.marked} 件 / 印を外した指摘: ${out.cleared} 件`,
    '',
  ];
  if (out.byNode.length > 0) {
    lines.push('## ノード別（印を付けた指摘）', '');
    for (const b of out.byNode) lines.push(`- ${b.node ?? '（未結合）'}: ${b.count} 件`);
    lines.push('');
  }
  lines.push('- 印は --out のプロジェクト JSON に保存され、`findings-priority` が優先度（悪用状況）に使う');
  return lines.join('\n');
}

/** 機械処理用の JSON オブジェクト（キーは英語固定）。 */
export function kevReportToJson(out: ImportKevOutput): Record<string, unknown> {
  return {
    schemaVersion: 1,
    kind: 'cyberriskscape-kev-import-report',
    catalogVersion: out.catalogVersion ?? null,
    checked: out.checked,
    marked: out.marked,
    cleared: out.cleared,
    byNode: out.byNode,
  };
}
