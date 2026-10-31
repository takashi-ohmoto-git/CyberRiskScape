import { resolveProject } from './analyze';
import { LAYER_KEYS, MAX_FINDINGS, type Finding } from '../core/model/types';
import { formatElementalId } from '../core/model/elementalId';
import { deserializeProject } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import { replaceFindings, type FindingsDiff } from '../features/findings-import/replaceFindings';
import type { ImportNodeRef } from '../features/findings-import/resolveNode';
import type { ScapFormat, ScapHost } from '../features/scap-import/parseScap';
import { scapToFindings, type HostConversion } from '../features/scap-import/scapToFindings';
import { BUNDLED_XCCDF_MAP, type XccdfMap } from '../features/scap-import/xccdfMap';

/**
 * CLI `import-findings`：SCAP の結果（XCCDF・ARF・OVAL）を共通モデルの指摘としてプロジェクト JSON に保存する。
 * 取り込み直しはホスト（scope）単位で置き換える。入力が同じなら出力も同じ（`importedAt` を固定したとき）。
 * ファイル I/O は呼び出し側（main.ts）。
 */

export interface ImportFindingsOptions {
  nodeMap?: Readonly<Record<string, string>>;
  nodeRef?: string;
  map?: XccdfMap;
  importedAt?: string;
}

export interface HostReport extends FindingsDiff {
  scope: string;
  product: string;
  /** 結びついたノード（無ければ未結合とその理由）。 */
  linked?: string;
  unlinkedReason?: 'none' | 'unknownNode' | 'ambiguous';
  ref?: string;
  counts: HostConversion['counts'];
  /** 保存した指摘の数。 */
  stored: number;
  truncated: number;
  unmapped: HostConversion['unmapped'];
}

export interface ImportFindingsOutput {
  format: ScapFormat;
  project: PersistedProject;
  hosts: HostReport[];
  stored: number;
  truncated: number;
}

export function importFindings(
  rawProject: unknown,
  parsed: { format: ScapFormat; hosts: ScapHost[] },
  options: ImportFindingsOptions = {},
): ImportFindingsOutput {
  const resolved = resolveProject(rawProject);
  const nodes: ImportNodeRef[] = LAYER_KEYS.flatMap((layer) =>
    resolved.layers[layer].nodes.map((n) => ({
      id: n.id,
      layer,
      seq: n.seq,
      type: n.type,
      label: n.label,
      posture: n.posture,
      attackSurface: n.attackSurface,
    })),
  );
  const loaded = deserializeProject(rawProject);
  if (!loaded) throw new Error('プロジェクト JSON の形式が不正です。');

  const conv = scapToFindings({
    format: parsed.format,
    hosts: parsed.hosts,
    map: options.map ?? BUNDLED_XCCDF_MAP,
    nodes,
    nodeMap: options.nodeMap,
    nodeRef: options.nodeRef,
    importedAt: options.importedAt ?? new Date().toISOString(),
  });

  let findings: Finding[] = loaded.findings ?? [];
  const hosts: HostReport[] = [];
  for (const h of conv.perHost) {
    const r = replaceFindings(findings, h.findings, h.host.product, h.host.scope.slice(0, 200));
    findings = r.findings;
    const res = h.resolution;
    hosts.push({
      scope: h.host.scope,
      product: h.host.product,
      ...(res.kind === 'found'
        ? {
            linked: `${res.node.seq != null ? formatElementalId('node', res.node.seq) : res.node.id} ${res.node.label?.trim() || res.node.type}`,
          }
        : { unlinkedReason: res.reason, ...(res.ref ? { ref: res.ref } : {}) }),
      counts: h.counts,
      stored: h.findings.length,
      truncated: h.truncated,
      unmapped: h.unmapped,
      ...r.diff,
    });
  }

  const project: PersistedProject = { ...loaded };
  if (findings.length > 0) project.findings = findings;
  else delete project.findings;
  return { format: parsed.format, project, hosts, stored: conv.findings.length, truncated: conv.truncated };
}

const REASON_TEXT = {
  none: '--node も --map の対応も無い',
  unknownNode: '指定されたノードが図に無い',
  ambiguous: 'C 番号が複数のレイヤーに該当（ノード ID で指定してください）',
} as const;

export function findingsReportToMarkdown(out: ImportFindingsOutput): string {
  const lines: string[] = [
    `# SCAP 取り込みレポート（${out.format.toUpperCase()}）`,
    '',
    '- SCAP の結果から、XCCDF の fail と OVAL の vulnerability/patch の true だけを指摘として保存した。ホスト単位で置き換える（他のホストの指摘は消さない）。',
    `- ホスト ${out.hosts.length} 台 / 保存 ${out.stored} 件`,
    '',
  ];
  for (const h of out.hosts) {
    const c = h.counts;
    lines.push(`## ${h.scope}（${h.product}）`, '');
    lines.push(
      h.linked
        ? `- ノード: ${h.linked}`
        : `- ノード: 未結合（${REASON_TEXT[h.unlinkedReason ?? 'none']}${h.ref ? `。指定: ${h.ref}` : ''}）`,
    );
    lines.push(`- 結果の内訳: pass ${c.pass} / fail ${c.fail} / error ${c.error} / unknown ${c.unknown} / その他 ${c.other}`);
    lines.push(`- 保存 ${h.stored} 件（新規 ${h.added} / 解消 ${h.resolved} / 継続 ${h.continued}）`);
    if (h.truncated > 0) lines.push(`- 上限（${MAX_FINDINGS} 件）を超えたため保存しなかった指摘 ${h.truncated} 件`);
    lines.push('', '### 対応づけできない（脅威の対応が無い指摘）', '');
    if (h.unmapped.length === 0) lines.push('なし');
    for (const u of h.unmapped.slice(0, 20)) {
      lines.push(`- ${u.id}${u.severity ? ` [${u.severity}]` : ''}${u.title ? ` ${u.title}` : ''}`);
    }
    if (h.unmapped.length > 20) lines.push(`- ほか ${h.unmapped.length - 20} 件`);
    lines.push('');
  }
  lines.push('- 指摘は --out のプロジェクト JSON に保存され、`analyze --format sarif --with-findings` で書き出せる');
  return lines.join('\n');
}

/** 機械処理用の JSON オブジェクト（キーは英語固定）。 */
export function findingsReportToJson(out: ImportFindingsOutput): Record<string, unknown> {
  return {
    schemaVersion: 1,
    kind: 'cyberriskscape-findings-import-report',
    format: out.format,
    stored: out.stored,
    truncated: out.truncated,
    hosts: out.hosts,
  };
}
