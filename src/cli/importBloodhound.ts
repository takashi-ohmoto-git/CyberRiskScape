import { resolveProject } from './analyze';
import { LAYER_KEYS, MAX_FINDINGS } from '../core/model/types';
import { formatElementalId } from '../core/model/elementalId';
import { deserializeProject } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import { replaceFindings, type FindingsDiff } from '../features/findings-import/replaceFindings';
import { lookupNode, type ImportNodeRef } from '../features/findings-import/resolveNode';
import { BUNDLED_BLOODHOUND_QUERIES, type BloodhoundQuery } from '../features/bloodhound-import/bloodhoundQueries';
import { parseCypherResponse, type CypherNode } from '../features/bloodhound-import/parseCypherResponse';
import {
  BLOODHOUND_PRODUCT,
  bloodhoundToFindings,
  type BloodhoundQueryReport,
} from '../features/bloodhound-import/bloodhoundToFindings';

/**
 * CLI `import-bloodhound`：BloodHound CE の問い合わせの結果を指摘としてプロジェクト JSON に保存する（plan §2.141）。
 * 指摘は図の DIRECTORY（AD CS の問い合わせは CERTIFICATE_AUTHORITY、Entra ID の問い合わせは IDENTITY_PROVIDER）に載せる。取り込み直しは製品 × scope の単位で置き換える。
 * ファイル・API の I/O は呼び出し側（main.ts）。
 */

export const DEFAULT_BLOODHOUND_SCOPE = 'default';

export interface ImportBloodhoundOptions {
  /** 指摘を載せる DIRECTORY（C 番号かノード ID）。省略時は図にちょうど 1 つあればそれ。 */
  node?: string;
  /** AD CS の指摘を載せる CERTIFICATE_AUTHORITY。省略時は図にちょうど 1 つあればそれ、無ければ DIRECTORY。 */
  caNode?: string;
  /** Entra ID の指摘を載せる IDENTITY_PROVIDER。省略時は図にちょうど 1 つあればそれ。無ければ未結合。 */
  idpNode?: string;
  /** Azure の管理の範囲・コード実行の指摘を載せる IAAS / PAAS。省略時は図にちょうど 1 つあればそれ。無ければ未結合。 */
  cloudNode?: string;
  /** Key Vault の指摘を載せる SECRETS_VAULT。省略時は図にちょうど 1 つあればそれ。無ければ未結合。 */
  vaultNode?: string;
  scope?: string;
  queries?: readonly BloodhoundQuery[];
  importedAt?: string;
}

export type BindResult =
  | { kind: 'found'; node: ImportNodeRef }
  | { kind: 'none' }
  | { kind: 'many' }
  | { kind: 'unknownNode' }
  | { kind: 'ambiguous' }
  | { kind: 'wrongType' };

export interface ImportBloodhoundOutput {
  project: PersistedProject;
  scope: string;
  directory: BindResult;
  ca: BindResult;
  idp: BindResult;
  cloud: BindResult;
  vault: BindResult;
  reports: BloodhoundQueryReport[];
  /** 応答の形が合わなかった問い合わせ。 */
  invalid: { queryId: string; error: string }[];
  stored: number;
  diff: FindingsDiff;
}

function bind(nodes: readonly ImportNodeRef[], type: string | readonly string[], ref: string | undefined): BindResult {
  const types: readonly string[] = typeof type === 'string' ? [type] : type;
  if (ref !== undefined) {
    const r = lookupNode(nodes, ref);
    if (r.kind !== 'found') return r.kind === 'ambiguous' ? { kind: 'ambiguous' } : { kind: 'unknownNode' };
    return types.includes(r.node.type) ? r : { kind: 'wrongType' };
  }
  const hits = nodes.filter((n) => types.includes(n.type));
  if (hits.length === 1) return { kind: 'found', node: hits[0] };
  return hits.length === 0 ? { kind: 'none' } : { kind: 'many' };
}

/** 問い合わせ ID → 応答の JSON（ファイルまたは API）から取り込む。 */
export function importBloodhound(
  rawProject: unknown,
  responses: ReadonlyMap<string, unknown>,
  options: ImportBloodhoundOptions = {},
): ImportBloodhoundOutput {
  const resolved = resolveProject(rawProject);
  const loaded = deserializeProject(rawProject);
  if (!loaded) throw new Error('プロジェクト JSON の形式が不正です。');
  const nodes: ImportNodeRef[] = LAYER_KEYS.flatMap((layer) =>
    resolved.layers[layer].nodes.map((n) => ({ id: n.id, layer, seq: n.seq, type: n.type, label: n.label })),
  );
  const directory = bind(nodes, 'DIRECTORY', options.node);
  const ca = bind(nodes, 'CERTIFICATE_AUTHORITY', options.caNode);
  const idp = bind(nodes, 'IDENTITY_PROVIDER', options.idpNode);
  const cloud = bind(nodes, ['IAAS', 'PAAS'], options.cloudNode);
  const vault = bind(nodes, 'SECRETS_VAULT', options.vaultNode);
  const subjectOf = (b: BindResult) => (b.kind === 'found' ? { layer: b.node.layer, nodeId: b.node.id } : undefined);
  const scope = (options.scope ?? DEFAULT_BLOODHOUND_SCOPE).slice(0, 200);
  const queries = options.queries ?? BUNDLED_BLOODHOUND_QUERIES;

  const results = new Map<string, CypherNode[]>();
  const invalid: ImportBloodhoundOutput['invalid'] = [];
  for (const q of queries) {
    if (!responses.has(q.id)) continue;
    const parsed = parseCypherResponse(responses.get(q.id));
    if (parsed.ok) results.set(q.id, parsed.nodes);
    else invalid.push({ queryId: q.id, error: parsed.error });
  }

  const dirSubject = subjectOf(directory);
  const caSubject = subjectOf(ca);
  const idpSubject = subjectOf(idp);
  const cloudSubject = subjectOf(cloud);
  const vaultSubject = subjectOf(vault);
  const conv = bloodhoundToFindings({
    queries,
    results,
    subjects: {
      ...(dirSubject ? { directory: dirSubject } : {}),
      ...(caSubject ? { ca: caSubject } : {}),
      ...(idpSubject ? { idp: idpSubject } : {}),
      ...(cloudSubject ? { cloud: cloudSubject } : {}),
      ...(vaultSubject ? { vault: vaultSubject } : {}),
    },
    scope,
    importedAt: options.importedAt ?? new Date().toISOString(),
  });
  const r = replaceFindings(loaded.findings, conv.findings, BLOODHOUND_PRODUCT, scope);
  if (r.findings.length > MAX_FINDINGS) throw new Error(`指摘が上限（${MAX_FINDINGS} 件）を超えます: ${r.findings.length} 件`);

  const project: PersistedProject = { ...loaded };
  if (r.findings.length > 0) project.findings = r.findings;
  else delete project.findings;
  return { project, scope, directory, ca, idp, cloud, vault, reports: conv.reports, invalid, stored: conv.findings.length, diff: r.diff };
}

const nodeName = (n: ImportNodeRef) => `${n.seq != null ? formatElementalId('node', n.seq) : n.id} ${n.label?.trim() || n.type}`;

function bindText(b: BindResult, typeLabel: string, option: string): string {
  switch (b.kind) {
    case 'found':
      return nodeName(b.node);
    case 'none':
      return `未結合（図に${typeLabel}が無い）`;
    case 'many':
      return `未結合（図に${typeLabel}が複数ある。${option} で指定してください）`;
    case 'unknownNode':
      return '未結合（指定されたノードが図に無い）';
    case 'ambiguous':
      return '未結合（C 番号が複数のレイヤーに該当。ノード ID で指定してください）';
    case 'wrongType':
      return `未結合（指定されたノードが${typeLabel}ではない）`;
  }
}

export function bloodhoundReportToMarkdown(out: ImportBloodhoundOutput): string {
  const caText =
    out.ca.kind === 'found' ? nodeName(out.ca.node) : out.ca.kind === 'none' ? 'ディレクトリに載せる（図に認証局が無い）' : bindText(out.ca, '認証局', '--ca-node');
  const lines = [
    '# BloodHound CE の取り込みレポート',
    '',
    '- 問い合わせの結果（問題を持つ主体）を指摘として保存した。ユーザーの名前・SID 等の識別子は保存しない（件数だけ）。',
    '- Tier Zero の主体は、Tier Zero 以外を数える問い合わせでは数えない（判定は BloodHound の Tier Zero の印）。',
    '- 同じ製品・同じ scope の指摘を置き換える（他の製品・scope の指摘は消さない）。',
    `- scope: ${out.scope}`,
    `- ディレクトリ: ${bindText(out.directory, 'ディレクトリ', '--node')}`,
    `- 認証局（AD CS の指摘）: ${caText}`,
    `- IdP（Entra ID の指摘）: ${bindText(out.idp, 'IdP', '--idp-node')}`,
    `- IaaS / PaaS（Azure の管理の範囲・コード実行の指摘）: ${bindText(out.cloud, 'IaaS・PaaS', '--cloud-node')}`,
    `- シークレット管理（Key Vault の指摘）: ${bindText(out.vault, 'シークレット管理', '--vault-node')}`,
    '',
    `## 件数（保存 ${out.stored} 件。新規 ${out.diff.added} / 解消 ${out.diff.resolved} / 継続 ${out.diff.continued}）`,
    '',
    '| 問い合わせ | 件数 | Tier Zero で除外 | 内訳 |',
    '| --- | --- | --- | --- |',
    ...out.reports.map((r) =>
      r.evaluated
        ? `| ${r.title} | ${r.count} | ${r.excludedTierZero} | ${Object.entries(r.byKind).map(([k, n]) => `${k} ${n}`).join('・') || '—'} |`
        : `| ${r.title} | 未評価 | — | — |`,
    ),
    '',
  ];
  if (out.invalid.length > 0) {
    lines.push('## 読めなかった応答', '', ...out.invalid.map((i) => `- ${i.queryId}: ${i.error}`), '');
  }
  return lines.join('\n');
}

export function bloodhoundReportToJson(out: ImportBloodhoundOutput): Record<string, unknown> {
  const b = (x: BindResult) => (x.kind === 'found' ? { kind: 'found', node: nodeName(x.node) } : { kind: x.kind });
  return {
    schemaVersion: 1,
    kind: 'cyberriskscape-bloodhound-import',
    scope: out.scope,
    directory: b(out.directory),
    ca: b(out.ca),
    idp: b(out.idp),
    cloud: b(out.cloud),
    vault: b(out.vault),
    stored: out.stored,
    diff: out.diff,
    queries: out.reports,
    invalid: out.invalid,
  };
}
