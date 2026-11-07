import { resolveProject } from './analyze';
import { LAYER_KEYS, MAX_FINDINGS } from '../core/model/types';
import { formatElementalId } from '../core/model/elementalId';
import { deserializeProject } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import { replaceFindings, type FindingsDiff } from '../features/findings-import/replaceFindings';
import { lookupNode, type ImportNodeRef } from '../features/findings-import/resolveNode';
import { BUNDLED_FINDING_MAP, type FindingMapping } from '../features/findings-report/findingMap';
import type { NucleiResult } from '../features/nuclei-import/parseNuclei';
import { nucleiToFindings, type NucleiReport } from '../features/nuclei-import/nucleiToFindings';

/**
 * CLI `import-nuclei`：Nuclei の結果（JSONL / JSON）を共通モデルの指摘としてプロジェクト JSON に保存する。
 * 取り込み直しは製品 × scope の単位で置き換える。ファイル I/O は呼び出し側（main.ts）。
 */

export interface ImportNucleiOptions {
  scope: string;
  node?: string;
  map?: readonly FindingMapping[];
  importedAt?: string;
  /** 読めなかった行・要素の数（parseNuclei の結果）。 */
  invalid?: number;
}

export interface ImportNucleiOutput {
  project: PersistedProject;
  scope: string;
  linked?: string;
  unlinkedReason?: 'unknownNode' | 'ambiguous';
  report: NucleiReport;
  invalid: number;
  replaced: { product: string } & FindingsDiff;
  stored: number;
  truncated: number;
}

export function importNuclei(rawProject: unknown, parsed: { results: NucleiResult[] }, options: ImportNucleiOptions): ImportNucleiOutput {
  const resolved = resolveProject(rawProject);
  const loaded = deserializeProject(rawProject);
  if (!loaded) throw new Error('プロジェクト JSON の形式が不正です。');
  const nodes: ImportNodeRef[] = LAYER_KEYS.flatMap((layer) =>
    resolved.layers[layer].nodes.map((n) => ({ id: n.id, layer, seq: n.seq, type: n.type, label: n.label })),
  );
  const lookup = options.node === undefined ? undefined : lookupNode(nodes, options.node);
  const found = lookup?.kind === 'found' ? lookup.node : undefined;

  const conv = nucleiToFindings({
    results: parsed.results,
    map: options.map ?? BUNDLED_FINDING_MAP,
    scope: options.scope,
    ...(found ? { subject: { layer: found.layer, nodeId: found.id } } : {}),
    importedAt: options.importedAt ?? new Date().toISOString(),
  });

  const r = replaceFindings(loaded.findings ?? [], conv.findings, conv.report.product, options.scope.slice(0, 200));
  const project: PersistedProject = { ...loaded };
  if (r.findings.length > 0) project.findings = r.findings;
  else delete project.findings;
  return {
    project,
    scope: options.scope,
    ...(found
      ? { linked: `${found.seq != null ? formatElementalId('node', found.seq) : found.id} ${found.label?.trim() || found.type}` }
      : lookup && lookup.kind !== 'found'
        ? { unlinkedReason: lookup.kind === 'ambiguous' ? ('ambiguous' as const) : ('unknownNode' as const) }
        : {}),
    report: conv.report,
    invalid: options.invalid ?? 0,
    replaced: { product: conv.report.product, ...r.diff },
    stored: conv.report.stored,
    truncated: conv.report.truncated,
  };
}

export function nucleiReportToMarkdown(out: ImportNucleiOutput): string {
  const r = out.report;
  const lines: string[] = [
    '# Nuclei 取り込みレポート',
    '',
    '- Nuclei の結果（info と、マッチしなかった結果を除く）を指摘として保存した。',
    '- 同じ製品・同じ scope の指摘を置き換える（他の製品・scope の指摘は消さない）。',
    `- scope: ${out.scope} / 結果 ${r.results} 件 → 保存 ${r.stored} 件`,
    out.linked
      ? `- ノード: ${out.linked}`
      : `- ノード: 未結合（${out.unlinkedReason === 'ambiguous' ? 'C 番号が複数のレイヤーに該当（ノード ID で指定してください）' : out.unlinkedReason === 'unknownNode' ? '指定されたノードが図に無い' : '--node の指定が無い'}）`,
    '',
    `- 除外 ${r.excludedInfo + r.excludedNoMatch} 件（info ${r.excludedInfo} / マッチしなかった結果 ${r.excludedNoMatch}）`,
    `- 読めなかった行 ${out.invalid} 件`,
    `- CVE を持つ指摘 ${r.withCve} 件（「既知の脆弱性に対するパッチの未適用」に対応づけ）`,
    `- CWE が辞書に無く脅威に対応づけられない指摘 ${r.cweUnmapped} 件`,
  ];
  if (r.truncated > 0) lines.push(`- 上限（${MAX_FINDINGS} 件）を超えたため保存しなかった指摘 ${r.truncated} 件`);
  lines.push(
    '',
    '## 保存しなかった情報',
    '',
    '- 要求・応答・curl コマンド・抽出値・インタラクション・メタ情報・テンプレート本体・説明文・IP アドレス',
    '- 場所の URL のクエリ・フラグメント・userinfo',
    '',
    `- ${out.replaced.product}: 新規 ${out.replaced.added} / 解消 ${out.replaced.resolved} / 継続 ${out.replaced.continued}`,
    '- 指摘は --out のプロジェクト JSON に保存され、`analyze --fail-on-findings` で判定、`import-kev` で KEV を照合できる',
  );
  return lines.join('\n');
}

/** 機械処理用の JSON オブジェクト（キーは英語固定）。 */
export function nucleiReportToJson(out: ImportNucleiOutput): Record<string, unknown> {
  return {
    schemaVersion: 1,
    kind: 'cyberriskscape-nuclei-import-report',
    scope: out.scope,
    linked: out.linked ?? null,
    stored: out.stored,
    truncated: out.truncated,
    invalid: out.invalid,
    report: out.report,
    replaced: out.replaced,
  };
}
