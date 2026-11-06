import { resolveProject } from './analyze';
import { LAYER_KEYS, MAX_BOM_COMPONENTS, MAX_FINDINGS, type BomComponent, type BomKind, type LayerKey } from '../core/model/types';
import { deserializeProject } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import { lookupNode, type ImportNodeRef } from '../features/findings-import/resolveNode';
import type { ParsedBom } from '../features/bom-import/parseBom';
import { vulnerabilitiesToFindings } from '../features/bom-import/vulnerabilitiesToFindings';
import { capFindings, replaceFindings } from '../features/findings-import/replaceFindings';

/**
 * CLI `import-sbom`：CycloneDX・SPDX の部品をプロジェクト JSON に保存する（docs/architecture.md §8.8）。
 * CycloneDX に vulnerabilities（VEX を含む）があれば、指摘（Finding）としても保存する（§8.2）。
 * 取り込み直しは形式 × scope の単位で置き換える（製品の版が変わっても同じ範囲を置き換えるため）。
 * ノードとの対応は引数で受け、推測しない。ファイル I/O は呼び出し側（main.ts）。
 */

type OkBom = Extract<ParsedBom, { ok: true }>;

export interface ImportBomOptions {
  scope: string;
  /** すべての部品を結びつけるノード（C 番号または ID）。無ければ未対応。 */
  node?: string;
  importedAt?: string;
}

export interface ImportBomOutput {
  project: PersistedProject;
  format: OkBom['format'];
  specVersion: string;
  product: string;
  scope: string;
  stored: number;
  /** 上限で保存しなかった件数。 */
  truncated: number;
  byKind: Partial<Record<BomKind, number>>;
  /** CycloneDX の vulnerabilities から作った指摘。SPDX では全部 0。 */
  findings: {
    stored: number;
    /** VEX（not_affected・false_positive・resolved）で除外した件数。 */
    excluded: number;
    /** 上限で保存しなかった件数。 */
    truncated: number;
    /** 影響部品を特定できず、指摘にしなかった脆弱性の件数。 */
    withoutAffects: number;
  };
  /** 図に無い、または特定できないノードの指定。 */
  badNodeRef?: string;
  linked: boolean;
}

/** 上限を超えたときに残す順。暗号と AI は他の手段で補いにくいので先に残す。 */
const KIND_PRIORITY: Record<BomKind, number> = { crypto: 0, 'ai-model': 1, dataset: 2, software: 3, other: 4 };

export function importBom(rawProject: unknown, bom: OkBom, options: ImportBomOptions): ImportBomOutput {
  const resolved = resolveProject(rawProject);
  const loaded = deserializeProject(rawProject);
  if (!loaded) throw new Error('プロジェクト JSON の形式が不正です。');

  const nodes: ImportNodeRef[] = LAYER_KEYS.flatMap((layer: LayerKey) =>
    resolved.layers[layer].nodes.map((n) => ({ id: n.id, layer, seq: n.seq, type: n.type, label: n.label })),
  );
  const lookup = options.node === undefined ? undefined : lookupNode(nodes, options.node);
  const subject = lookup?.kind === 'found' ? { layer: lookup.node.layer, nodeId: lookup.node.id } : undefined;

  const importedAt = options.importedAt ?? new Date().toISOString();
  const source = {
    format: bom.format,
    product: bom.product,
    ...(bom.productVersion ? { productVersion: bom.productVersion } : {}),
    scope: options.scope,
    importedAt,
  };

  const incoming = new Map<string, BomComponent>();
  for (const item of bom.items) {
    const id = `${bom.format}:${options.scope}:${item.externalId}`;
    if (incoming.has(id)) continue;
    incoming.set(id, {
      id,
      source,
      ...item,
      ...(subject ? { subject } : {}),
      ...(bom.observedAt ? { observedAt: bom.observedAt } : {}),
    });
  }

  const others = (loaded.bomComponents ?? []).filter(
    (c) => !(c.source.format === bom.format && c.source.scope === options.scope),
  );
  const room = Math.max(0, MAX_BOM_COMPONENTS - others.length);
  const kept = [...incoming.values()].sort((a, b) => KIND_PRIORITY[a.kind] - KIND_PRIORITY[b.kind]).slice(0, room);

  const project: PersistedProject = { ...loaded };
  const all = [...others, ...kept];
  if (all.length > 0) project.bomComponents = all;
  else delete project.bomComponents;

  const byKind: Partial<Record<BomKind, number>> = {};
  for (const c of kept) byKind[c.kind] = (byKind[c.kind] ?? 0) + 1;

  // 指摘は CycloneDX のときだけ、製品 × scope の単位で置き換える（vulnerabilities が無ければ空にする）。
  const findings = { stored: 0, excluded: 0, truncated: 0, withoutAffects: 0 };
  if (bom.format === 'cyclonedx') {
    const conv = vulnerabilitiesToFindings(
      bom.vulnerabilities ?? [],
      { format: 'cyclonedx', product: 'CycloneDX', scope: options.scope, importedAt, ...(bom.productVersion ? { productVersion: bom.productVersion } : {}) },
      subject,
      bom.observedAt,
    );
    const others = (loaded.findings ?? []).filter((f) => !(f.source.product === 'CycloneDX' && f.source.scope === options.scope));
    const capped = capFindings(conv.findings);
    const room = Math.max(0, MAX_FINDINGS - others.length);
    const incoming = capped.findings.slice(0, room);
    const replaced = replaceFindings(loaded.findings, incoming, 'CycloneDX', options.scope);
    if (replaced.findings.length > 0) project.findings = replaced.findings;
    else delete project.findings;
    findings.stored = incoming.length;
    findings.excluded = conv.excluded;
    findings.truncated = conv.findings.length - incoming.length;
    findings.withoutAffects = conv.withoutAffects;
  }

  return {
    project,
    format: bom.format,
    specVersion: bom.specVersion,
    product: bom.product,
    scope: options.scope,
    stored: kept.length,
    truncated: incoming.size - kept.length,
    byKind,
    findings,
    ...(options.node !== undefined && !subject ? { badNodeRef: options.node } : {}),
    linked: !!subject,
  };
}

export function bomReportToMarkdown(out: ImportBomOutput): string {
  return [
    `# 部品の取り込みレポート（${out.specVersion}・${out.product}）`,
    '',
    `- scope: ${out.scope}（同じ形式・同じ scope の部品を置き換えた）`,
    `- 保存 ${out.stored} 件（${Object.entries(out.byKind).map(([k, n]) => `${k} ${n}`).join(' / ') || 'なし'}）`,
    `- 上限（${MAX_BOM_COMPONENTS} 件）で保存しなかった件数 ${out.truncated} 件（暗号・AI モデル・データセットを優先して残す）`,
    `- 指摘 ${out.findings.stored} 件（除外 ${out.findings.excluded} 件）（CycloneDX の vulnerabilities。同じ scope の指摘を置き換えた）`,
    `  - 除外: VEX の状態が not_affected・false_positive・resolved のもの`,
    ...(out.findings.withoutAffects > 0 ? [`  - 影響を受ける部品（affects）を特定できず指摘にしなかった脆弱性 ${out.findings.withoutAffects} 件`] : []),
    ...(out.findings.truncated > 0 ? [`  - 上限（${MAX_FINDINGS} 件）で保存しなかった指摘 ${out.findings.truncated} 件（深刻度の高いものを優先して残す）`] : []),
    `- ノードとの対応: ${out.linked ? 'あり' : '無し（Asset タブで「未対応」になる）'}`,
    ...(out.badNodeRef ? [`- 図に無い、または特定できないノードの指定: ${out.badNodeRef}`] : []),
    '',
    '## 保存しなかった情報',
    '',
    '- 依存関係（dependencies・relationships）、提供元、証拠、外部参照',
    '- 脆弱性の説明文・詳細・推奨対応などの本文（ライセンスの適否も判定しない）',
    '- 暗号の鍵の値、purl の修飾子',
  ].join('\n');
}

/** 機械処理用の JSON オブジェクト（キーは英語固定）。 */
export function bomReportToJson(out: ImportBomOutput): Record<string, unknown> {
  return {
    schemaVersion: 1,
    kind: 'cyberriskscape-sbom-import-report',
    format: out.format,
    specVersion: out.specVersion,
    product: out.product,
    scope: out.scope,
    stored: out.stored,
    truncated: out.truncated,
    byKind: out.byKind,
    findings: out.findings,
    linked: out.linked,
    ...(out.badNodeRef ? { badNodeRef: out.badNodeRef } : {}),
  };
}
