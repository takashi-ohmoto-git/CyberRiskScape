import { resolveProject } from './analyze';
import { LAYER_KEYS, MAX_ASSETS, MAX_FINDINGS } from '../core/model/types';
import { deserializeProject } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import type { ImportNodeRef } from '../features/findings-import/resolveNode';
import { replaceFindings } from '../features/findings-import/replaceFindings';
import { BUNDLED_OCSF_MAP, type OcsfProductMap } from '../features/ocsf-import/ocsfMap';
import { ocsfToProject } from '../features/ocsf-import/ocsfToProject';
import type { ParsedOcsf } from '../features/ocsf-import/parseOcsf';

/**
 * CLI `import-ocsf`：OCSF の検査結果（Detection Finding・Compliance Finding。製品を問わない）を、
 * 指摘（FAIL）とクラウドのリソースの資産としてプロジェクト JSON に保存する（plan §2.149）。
 * 置き換えは製品 × scope の単位。運用状況（posture）は埋めない（Prowler で埋めるときは import-prowler）。
 * ファイル I/O は呼び出し側（main.ts）。
 */

export interface ImportOcsfOptions {
  scope: string;
  nodeMap?: Readonly<Record<string, string>>;
  map?: readonly OcsfProductMap[];
  importedAt?: string;
}

export interface ImportOcsfOutput {
  project: PersistedProject;
  scope: string;
  products: { product: string; findings: number; added: number; resolved: number; continued: number }[];
  truncated: number;
  skipped: ParsedOcsf['skipped'];
  statusCounts: { pass: number; fail: number; manual: number };
  resources: { total: number; linked: number; providers: string[]; accounts: string[] };
  unmappedChecks: { product: string; checkId: string; count: number }[];
  /** Prowler の指摘が import-prowler（scope なし）でも保存されていて、重複している。 */
  prowlerOverlap: boolean;
}

export function importOcsf(rawProject: unknown, parsed: ParsedOcsf, options: ImportOcsfOptions): ImportOcsfOutput {
  const resolved = resolveProject(rawProject);
  const loaded = deserializeProject(rawProject);
  if (!loaded) throw new Error('プロジェクト JSON の形式が不正です。');
  const nodes: ImportNodeRef[] = LAYER_KEYS.flatMap((layer) =>
    resolved.layers[layer].nodes.map((n) => ({ id: n.id, layer, seq: n.seq, type: n.type, label: n.label })),
  );
  const importedAt = options.importedAt ?? new Date().toISOString();
  const conv = ocsfToProject({
    findings: parsed.findings,
    map: options.map ?? BUNDLED_OCSF_MAP,
    nodes,
    ...(options.nodeMap ? { nodeMap: options.nodeMap } : {}),
    scope: options.scope,
    importedAt,
  });

  const productNames = [...new Set(parsed.findings.map((f) => f.product))];
  let findings = loaded.findings;
  const products: ImportOcsfOutput['products'] = [];
  for (const product of productNames) {
    const incoming = conv.findingsByProduct.get(product) ?? [];
    const r = replaceFindings(findings, incoming, product, options.scope);
    findings = r.findings;
    products.push({ product, findings: incoming.length, ...r.diff });
  }
  if (findings && findings.length > MAX_FINDINGS) throw new Error(`指摘が上限（${MAX_FINDINGS} 件）を超えます: ${findings.length} 件`);

  const replaced = new Set(productNames);
  const others = (loaded.assets ?? []).filter((a) => !(a.source.format === 'ocsf' && replaced.has(a.source.product) && a.source.scope === options.scope));
  const assets = [...others, ...conv.assets];
  if (assets.length > MAX_ASSETS) throw new Error(`資産が上限（${MAX_ASSETS} 件）を超えます: ${assets.length} 件`);

  const project: PersistedProject = { ...loaded };
  if (findings && findings.length > 0) project.findings = findings;
  else delete project.findings;
  if (assets.length > 0) project.assets = assets;
  else delete project.assets;

  const count = (s: string) => parsed.findings.filter((f) => f.status === s).length;
  const uniq = (xs: (string | undefined)[]) => [...new Set(xs.filter((x): x is string => !!x))].sort();
  return {
    project,
    scope: options.scope,
    products,
    truncated: conv.truncated,
    skipped: parsed.skipped,
    statusCounts: { pass: count('PASS'), fail: count('FAIL'), manual: count('MANUAL') },
    resources: {
      total: conv.assets.length,
      linked: conv.assets.filter((a) => a.subject).length,
      providers: uniq(conv.assets.map((a) => a.cloud?.provider)),
      accounts: uniq(conv.assets.map((a) => a.cloud?.account)),
    },
    unmappedChecks: conv.unmappedChecks,
    prowlerOverlap:
      productNames.some((p) => p.toLowerCase() === 'prowler') &&
      (findings ?? []).some((f) => f.source.product === 'Prowler' && f.source.scope === undefined),
  };
}

const cell = (s: string) => s.replace(/[\r\n]+/g, ' ').replace(/\|/g, '\\|');

export function ocsfReportToMarkdown(out: ImportOcsfOutput): string {
  const lines = [
    '# OCSF の取り込みレポート',
    '',
    `- scope: ${out.scope}（同じ製品 × scope の指摘・リソースを置き換えた）`,
    `- 検査結果：FAIL ${out.statusCounts.fail} 件・PASS ${out.statusCounts.pass} 件・要確認 ${out.statusCounts.manual} 件（指摘として保存するのは FAIL だけ）`,
    `- 読まなかったもの：形が読めない ${out.skipped.invalid} 件・対象外のクラス ${out.skipped.otherClass} 件・抑止・解決済み ${out.skipped.closed} 件`,
    `- クラウドのリソース：${out.resources.total} 件（図のノードに結びついた ${out.resources.linked} 件。事業者 ${out.resources.providers.join('・') || '—'}・アカウント ${out.resources.accounts.length} 件）`,
    '- リソースの ID はアカウント ID を含む完全な形で保存している（露出している可能性のある資産を特定するため）。プロジェクト JSON を共有するときは注意する',
    '- 運用状況（posture）は埋めない。Prowler の結果で埋めるときは import-prowler を使う',
    '',
    '## 製品ごとの指摘',
    '',
    '| 製品 | 指摘 | 新規 | 解消 | 継続 |',
    '| --- | --- | --- | --- | --- |',
    ...out.products.map((p) => `| ${cell(p.product)} | ${p.findings} | ${p.added} | ${p.resolved} | ${p.continued} |`),
  ];
  if (out.prowlerOverlap) {
    lines.push('', '- **注意**：Prowler の指摘が import-prowler でも保存されているため重複している。どちらか一方の取り込みにする（運用状況も埋めるなら import-prowler）');
  }
  if (out.truncated > 0) lines.push('', `- 上限を超えた指摘 ${out.truncated} 件は保存していない`);
  lines.push('', `## 脅威と結ばなかった検査（対応表に無い。${out.unmappedChecks.length} 種類）`, '');
  lines.push('> 指摘としては保存している。data/finding-maps/ocsf.yaml に製品と検査 ID を足すと、図の脅威と結びつく。', '');
  if (out.unmappedChecks.length === 0) lines.push('- 該当なし');
  else lines.push('| 製品 | 検査 ID | 件数 |', '| --- | --- | --- |', ...out.unmappedChecks.slice(0, 100).map((u) => `| ${cell(u.product)} | ${cell(u.checkId)} | ${u.count} |`));
  if (out.unmappedChecks.length > 100) lines.push(`- ほか ${out.unmappedChecks.length - 100} 種類`);
  lines.push('', '- 図に無いクラウドのリソースは `asm-reconcile` で出る。ノードとの対応はリソースのタグ `crs-node` か `--map`');
  return lines.join('\n');
}

export function ocsfReportToJson(out: ImportOcsfOutput): Record<string, unknown> {
  const { project: _project, ...rest } = out;
  return { schemaVersion: 1, kind: 'cyberriskscape-ocsf-import-report', ...rest };
}
