import { resolveProject } from './analyze';
import { LAYER_KEYS, MAX_FINDINGS, type Finding } from '../core/model/types';
import { formatElementalId } from '../core/model/elementalId';
import { deserializeProject } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import { replaceFindings, type FindingsDiff } from '../features/findings-import/replaceFindings';
import { lookupNode, type ImportNodeRef } from '../features/findings-import/resolveNode';
import {
  BUNDLED_SECURITY_AUDIT_MAP,
  attackClassToCanonicalIds,
  type SecurityAuditMapping,
} from '../features/findings-report/findingMap';
import type { AuditItem, LedgerUnit } from '../features/security-audit-import/parseSecurityAudit';
import {
  SECURITY_AUDIT_PRODUCT,
  securityAuditToFindings,
  type SecurityAuditReport,
} from '../features/security-audit-import/securityAuditToFindings';

/**
 * CLI `import-security-audit`：AI によるソース監査（Cloudflare security-audit スキル）の `findings.json`
 * （＋任意で `coverage-ledger.json`）を共通モデルの指摘としてプロジェクト JSON に保存する（docs/architecture.md §8.9）。
 * 取り込み直しは製品 × scope の単位で置き換える。ファイル I/O は呼び出し側（main.ts）。
 */

export const DEFAULT_SECURITY_AUDIT_SCOPE = 'default';

export interface ImportSecurityAuditOptions {
  /** 置き換えの範囲。省略時は 'default'。 */
  scope?: string;
  node?: string;
  map?: readonly SecurityAuditMapping[];
  /** 台帳の単位（coverage-ledger.json）。 */
  ledger?: readonly LedgerUnit[];
  /** 形が合わず読めなかった要素の数（parse の結果）。 */
  invalid?: number;
  importedAt?: string;
}

export interface ImportSecurityAuditOutput {
  project: PersistedProject;
  scope: string;
  /** 結びついたノード（--node 指定時）。 */
  linked?: string;
  unlinkedReason?: 'unknownNode' | 'ambiguous';
  report: SecurityAuditReport;
  /** 形が合わず読めなかった要素の数。 */
  invalid: number;
  ledgerGiven: boolean;
  /** 台帳で指摘に結びついたが、対応表に載っていない攻撃クラス（人が判断する材料）。 */
  unmappedClasses: string[];
  stored: number;
  diff: FindingsDiff;
}

export function importSecurityAudit(
  rawProject: unknown,
  items: readonly AuditItem[],
  options: ImportSecurityAuditOptions = {},
): ImportSecurityAuditOutput {
  const resolved = resolveProject(rawProject);
  const loaded = deserializeProject(rawProject);
  if (!loaded) throw new Error('プロジェクト JSON の形式が不正です。');
  const nodes: ImportNodeRef[] = LAYER_KEYS.flatMap((layer) =>
    resolved.layers[layer].nodes.map((n) => ({ id: n.id, layer, seq: n.seq, type: n.type, label: n.label })),
  );
  const lookup = options.node === undefined ? undefined : lookupNode(nodes, options.node);
  const found = lookup?.kind === 'found' ? lookup.node : undefined;
  const map = options.map ?? BUNDLED_SECURITY_AUDIT_MAP;
  // 既定の scope は結びつけたノードの ID（別ノードに別リポジトリの結果を取り込んでも互いに消さない）。ノードが無ければ固定値
  const scope = (options.scope ?? found?.id ?? DEFAULT_SECURITY_AUDIT_SCOPE).slice(0, 200);

  const conv = securityAuditToFindings({
    items,
    ...(options.ledger ? { ledger: options.ledger } : {}),
    map,
    scope,
    ...(found ? { subject: { layer: found.layer, nodeId: found.id } } : {}),
    importedAt: options.importedAt ?? new Date().toISOString(),
  });
  if (conv.findings.length > MAX_FINDINGS) throw new Error(`指摘が上限（${MAX_FINDINGS} 件）を超えます。`);

  const r = replaceFindings(loaded.findings, conv.findings, SECURITY_AUDIT_PRODUCT, scope);
  if (r.findings.length > MAX_FINDINGS) {
    throw new Error(`指摘が上限（${MAX_FINDINGS} 件）を超えます: ${r.findings.length} 件`);
  }

  const classes = new Set<string>();
  for (const f of conv.findings as Finding[]) {
    for (const i of f.identifiers) if (i.scheme === 'security-audit-attack-class') classes.add(i.value);
  }
  const unmappedClasses = [...classes].filter((c) => attackClassToCanonicalIds(map, c) === undefined).sort();

  const project: PersistedProject = { ...loaded };
  if (r.findings.length > 0) project.findings = r.findings;
  else delete project.findings;
  return {
    project,
    scope,
    ...(found
      ? { linked: `${found.seq != null ? formatElementalId('node', found.seq) : found.id} ${found.label?.trim() || found.type}` }
      : lookup && lookup.kind !== 'found'
        ? { unlinkedReason: lookup.kind === 'ambiguous' ? ('ambiguous' as const) : ('unknownNode' as const) }
        : {}),
    report: conv.report,
    invalid: options.invalid ?? 0,
    ledgerGiven: options.ledger !== undefined,
    unmappedClasses,
    stored: conv.findings.length,
    diff: r.diff,
  };
}

export function securityAuditReportToMarkdown(out: ImportSecurityAuditOutput): string {
  const r = out.report;
  const lines: string[] = [
    '# ソース監査の取り込みレポート（Cloudflare security-audit）',
    '',
    '- findings.json の confirmed と needs_validation を指摘として保存した。execution（payloads）・修正コード・evidence・root_cause の本文は保存しない。',
    '- 同じ製品・同じ scope の指摘を置き換える（他の製品・scope の指摘は消さない）。',
    `- scope: ${out.scope}`,
    out.linked
      ? `- ノード: ${out.linked}`
      : `- ノード: 未結合（${out.unlinkedReason === 'ambiguous' ? 'C 番号が複数のレイヤーに該当（ノード ID で指定してください）' : out.unlinkedReason === 'unknownNode' ? '指定されたノードが図に無い' : '--node の指定が無い'}）`,
    '',
    '## 件数',
    '',
    `- 保存 ${out.stored} 件（新規 ${out.diff.added} / 解消 ${out.diff.resolved} / 継続 ${out.diff.continued}）`,
    `- 成立を確認した指摘（confirmed） ${r.confirmed} 件`,
    `- 要確認の指摘（needs_validation。重大度なし・ゲートや優先度づけの対象外） ${r.unverified} 件`,
    `- 反証されたため保存しなかった指摘（rejected） ${r.rejected} 件`,
  ];
  if (out.invalid > 0) lines.push(`- 形が合わず読めなかった要素 ${out.invalid} 件`);
  if (r.duplicates > 0) lines.push(`- 指紋が重複していたため捨てた指摘 ${r.duplicates} 件`);
  if (r.overLimit > 0) lines.push(`- 上限（${MAX_FINDINGS} 件）を超えたため保存しなかった指摘 ${r.overLimit} 件`);
  lines.push('', '## 脅威への対応づけ', '');
  lines.push(
    out.ledgerGiven
      ? `- 台帳（coverage-ledger.json）の攻撃クラスから対応づけた。対応づけできなかった指摘 ${r.unmapped} 件（脅威カードには載らない）`
      : `- 台帳（--ledger）が無いため攻撃クラスを引けない。対応づけできなかった指摘 ${r.unmapped} 件（脅威カードには載らない）`,
  );
  if (out.unmappedClasses.length > 0) {
    lines.push('- 対応表（data/finding-maps/security-audit.yaml）に載っていない攻撃クラス:');
    for (const c of out.unmappedClasses.slice(0, 20)) lines.push(`  - ${c}`);
    if (out.unmappedClasses.length > 20) lines.push(`  - ほか ${out.unmappedClasses.length - 20} 件`);
  }
  lines.push('', '- 指摘は --out のプロジェクト JSON に保存され、`analyze --fail-on-findings` で判定、`--format sarif --with-findings` で書き出せる');
  return lines.join('\n');
}

/** 機械処理用の JSON オブジェクト（キーは英語固定）。 */
export function securityAuditReportToJson(out: ImportSecurityAuditOutput): Record<string, unknown> {
  return {
    schemaVersion: 1,
    kind: 'cyberriskscape-security-audit-import-report',
    product: SECURITY_AUDIT_PRODUCT,
    scope: out.scope,
    linked: out.linked ?? null,
    stored: out.stored,
    ...out.report,
    invalid: out.invalid,
    ledgerGiven: out.ledgerGiven,
    unmappedClasses: out.unmappedClasses,
    diff: out.diff,
  };
}
