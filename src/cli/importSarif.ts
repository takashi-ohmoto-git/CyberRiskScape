import { resolveProject } from './analyze';
import { LAYER_KEYS, MAX_FINDINGS, type Finding } from '../core/model/types';
import { formatElementalId } from '../core/model/elementalId';
import { deserializeProject } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import { replaceFindings, type FindingsDiff } from '../features/findings-import/replaceFindings';
import { lookupNode, type ImportNodeRef } from '../features/findings-import/resolveNode';
import { BUNDLED_FINDING_MAP, type FindingMapping } from '../features/findings-report/findingMap';
import type { SarifRun } from '../features/sarif-import/parseSarif';
import { sarifToFindings, type SarifRunReport } from '../features/sarif-import/sarifToFindings';
import type { SarifCategory } from '../features/sarif-import/sarifCategories';
import type { SecretDetail } from '../features/sarif-import/secretDetails';

/**
 * CLI `import-sarif`：汎用の SARIF 2.1.0（Semgrep・CodeQL 等の SAST）を共通モデルの指摘としてプロジェクト JSON に保存する。
 * 取り込み直しは製品 × scope の単位で置き換える。ファイル I/O は呼び出し側（main.ts）。
 */

export interface ImportSarifOptions {
  scope: string;
  node?: string;
  map?: readonly FindingMapping[];
  importedAt?: string;
  /** 利用者が指定した分類（`--category`）。 */
  category?: SarifCategory;
  /** 報告にだけ出す生の情報（`--show-secrets`）。プロジェクトには入れない。 */
  rawDetails?: SecretDetail[];
}

export interface ImportSarifOutput {
  project: PersistedProject;
  scope: string;
  /** 結びついたノード（--node 指定時）。 */
  linked?: string;
  /** 結びついたノードの型。 */
  linkedType?: string;
  unlinkedReason?: 'unknownNode' | 'ambiguous';
  runs: SarifRunReport[];
  /** 製品ごとの置き換えの結果。 */
  replaced: ({ product: string } & FindingsDiff)[];
  stored: number;
  truncated: number;
  category?: SarifCategory;
  /** 分類を指定したときの件数の内訳（規則ごと・ファイルの数）。値は持たない。 */
  breakdown?: { byRule: { rule: string; count: number }[]; files: number };
  rawDetails?: SecretDetail[];
}

export function importSarif(rawProject: unknown, sarif: { runs: SarifRun[] }, options: ImportSarifOptions): ImportSarifOutput {
  const resolved = resolveProject(rawProject);
  const loaded = deserializeProject(rawProject);
  if (!loaded) throw new Error('プロジェクト JSON の形式が不正です。');
  const nodes: ImportNodeRef[] = LAYER_KEYS.flatMap((layer) =>
    resolved.layers[layer].nodes.map((n) => ({ id: n.id, layer, seq: n.seq, type: n.type, label: n.label })),
  );
  const lookup = options.node === undefined ? undefined : lookupNode(nodes, options.node);
  const found = lookup?.kind === 'found' ? lookup.node : undefined;

  const conv = sarifToFindings({
    runs: sarif.runs,
    map: options.map ?? BUNDLED_FINDING_MAP,
    scope: options.scope,
    ...(found ? { subject: { layer: found.layer, nodeId: found.id } } : {}),
    importedAt: options.importedAt ?? new Date().toISOString(),
    ...(options.category ? { category: options.category } : {}),
  });

  let findings: Finding[] = loaded.findings ?? [];
  const replaced: ImportSarifOutput['replaced'] = [];
  const scope = options.scope.slice(0, 200);
  for (const product of [...new Set(conv.runs.map((r) => r.product))]) {
    const r = replaceFindings(findings, conv.findings.filter((f) => f.source.product === product), product, scope);
    findings = r.findings;
    replaced.push({ product, ...r.diff });
  }

  const project: PersistedProject = { ...loaded };
  if (findings.length > 0) project.findings = findings;
  else delete project.findings;
  return {
    project,
    scope: options.scope,
    ...(found
      ? { linked: `${found.seq != null ? formatElementalId('node', found.seq) : found.id} ${found.label?.trim() || found.type}`, linkedType: found.type }
      : lookup && lookup.kind !== 'found'
        ? { unlinkedReason: lookup.kind === 'ambiguous' ? ('ambiguous' as const) : ('unknownNode' as const) }
        : {}),
    runs: conv.runs,
    replaced,
    stored: conv.findings.length,
    truncated: conv.runs.reduce((a, r) => a + r.truncated, 0),
    ...(options.category ? { category: options.category, breakdown: breakdownOf(conv.findings) } : {}),
    ...(options.rawDetails ? { rawDetails: options.rawDetails } : {}),
  };
}

/** 規則ごとの件数とファイルの数（場所は「ファイル:行」から行を外して数える）。 */
function breakdownOf(findings: readonly Finding[]): NonNullable<ImportSarifOutput['breakdown']> {
  const byRule = new Map<string, number>();
  const files = new Set<string>();
  for (const f of findings) {
    const rule = f.title ?? f.identifiers.find((i) => i.scheme === 'rule')?.value ?? 'unknown';
    byRule.set(rule, (byRule.get(rule) ?? 0) + 1);
    if (f.resource?.label) files.add(f.resource.label.replace(/:\d+$/, ''));
  }
  return {
    byRule: [...byRule].map(([rule, count]) => ({ rule, count })).sort((a, b) => b.count - a.count || a.rule.localeCompare(b.rule)),
    files: files.size,
  };
}

export function sarifReportToMarkdown(out: ImportSarifOutput): string {
  const lines: string[] = [
    '# SARIF 取り込みレポート',
    '',
    '- SARIF の結果（抑制済み・解消済み・合格／対象外／情報の結果を除く）を指摘として保存した。message の本文・コード片は保存しない。',
    '- 同じ製品・同じ scope の指摘を置き換える（他の製品・scope の指摘は消さない）。',
    `- scope: ${out.scope} / run ${out.runs.length} 件 / 保存 ${out.stored} 件`,
    out.linked
      ? `- ノード: ${out.linked}`
      : `- ノード: 未結合（${out.unlinkedReason === 'ambiguous' ? 'C 番号が複数のレイヤーに該当（ノード ID で指定してください）' : out.unlinkedReason === 'unknownNode' ? '指定されたノードが図に無い' : '--node の指定が無い'}）`,
    ...(out.category
      ? [
          `- 分類: ${out.category.title}（すべての結果を同じ脅威に結んだ。${out.category.useMessageAsTitle ? '' : 'message は題名にも使っていない。'}秘密の値は保存しない）`,
          ...(out.linkedType && out.category.nodeTypes.includes(out.linkedType)
            ? []
            : [`- この分類の脅威は図の ${out.category.nodeTypes.join('・')} のノードに出る。--node でそのノードを指定すると、脅威カードに結びつく`]),
        ]
      : []),
    '',
  ];
  out.runs.forEach((r, i) => {
    const x = r.excluded;
    lines.push(`## run ${i + 1}: ${r.product}${r.productVersion ? ` ${r.productVersion}` : ''}`, '');
    lines.push(`- 結果 ${r.results} 件 → 保存 ${r.stored} 件`);
    lines.push(`- 除外 ${x.suppressed + x.absent + x.kind} 件（抑制 ${x.suppressed} / 解消済み ${x.absent} / 合格・対象外・情報 ${x.kind}）`);
    lines.push(`- CWE が辞書に無く脅威に対応づけられない指摘 ${r.cweUnmapped} 件`);
    if (r.truncated > 0) lines.push(`- 上限（${MAX_FINDINGS} 件）を超えたため保存しなかった指摘 ${r.truncated} 件`);
    lines.push('');
  });
  for (const p of out.replaced) lines.push(`- ${p.product}: 新規 ${p.added} / 解消 ${p.resolved} / 継続 ${p.continued}`);
  if (out.breakdown) {
    lines.push('', `## 件数の内訳（規則ごと。ファイル ${out.breakdown.files} 件）`, '', '| 規則 | 件数 |', '| --- | --- |');
    for (const b of out.breakdown.byRule) lines.push(`| ${cell(b.rule)} | ${b.count} |`);
    if (!out.rawDetails) {
      lines.push('', '> 秘密の値・場所の詳細は出していない。調査で要るときは --show-secrets を付ける（報告にだけ出し、プロジェクトには保存しない）。');
    }
  }
  if (out.rawDetails) {
    lines.push(
      '',
      `## 生の情報（--show-secrets。${out.rawDetails.length} 件）`,
      '',
      '> **秘密の値を含む。** この報告を共有・保存しないこと。調べ終えたら消し、見つかった秘密は失効・作り直す。プロジェクト JSON には保存していない。',
      '',
      '| 規則 | 場所 | 付随情報 | 秘密の値 |',
      '| --- | --- | --- | --- |',
    );
    for (const d of out.rawDetails) {
      const ctx = Object.entries(d.context)
        .map(([k, v]) => `${k}=${v}`)
        .join('; ');
      lines.push(`| ${cell(d.rule)} | ${cell(d.location ?? '—')} | ${cell(ctx || '—')} | ${cell(d.secret ?? '—')} |`);
    }
  }
  lines.push('', '- 指摘は --out のプロジェクト JSON に保存され、`analyze --fail-on-findings` で判定、`--format sarif --with-findings` で書き出せる');
  return lines.join('\n');
}

const cell = (s: string) => s.replace(/[\r\n]+/g, ' ').replace(/\|/g, '\\|');

/** 機械処理用の JSON オブジェクト（キーは英語固定）。 */
export function sarifReportToJson(out: ImportSarifOutput): Record<string, unknown> {
  return {
    schemaVersion: 1,
    kind: 'cyberriskscape-sarif-import-report',
    scope: out.scope,
    linked: out.linked ?? null,
    stored: out.stored,
    truncated: out.truncated,
    runs: out.runs,
    replaced: out.replaced,
    ...(out.category ? { category: out.category.id, breakdown: out.breakdown } : {}),
    ...(out.rawDetails ? { rawDetails: out.rawDetails } : {}),
  };
}
