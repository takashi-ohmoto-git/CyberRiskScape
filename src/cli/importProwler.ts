import { analyzeResolvedProject, resolveProject, type LayerAnalysisResult } from './analyze';
import { LAYER_KEYS, MAX_FINDINGS, type LayerKey } from '../core/model/types';
import { effectiveSeverity } from '../core/model/risk';
import { deserializeProject } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import {
  applyProwler,
  fillNodes,
  type BasisEntry,
  type ProwlerImportResult,
  type ThreatRef,
} from '../features/prowler-import/applyProwler';
import type { ImportNodeRef } from '../features/findings-import/resolveNode';
import { toFindings } from '../features/prowler-import/toFindings';
import { replaceFindings } from '../features/findings-import/replaceFindings';
import type { ParsedProwler } from '../features/prowler-import/parseProwlerOcsf';
import { BUNDLED_PROWLER_MAP, type FieldValue, type ProwlerMapping } from '../features/prowler-import/prowlerMap';

/**
 * CLI `import-prowler`：Prowler の OCSF の検査結果を、プロジェクト JSON のノードの運用状況・攻撃面属性に載せる。
 * 入力が同じなら出力も同じ（`updatedAt` 以外）。ファイル I/O は呼び出し側（main.ts）。
 */

export interface ImportProwlerOutput {
  result: ProwlerImportResult;
  /** 未入力の項目だけ埋めたプロジェクト。 */
  project: PersistedProject;
  skipped: ParsedProwler['skipped'];
  /** 保存した指摘（FAIL）の件数。`added/resolved/continued` は前回取り込みとの差。 */
  findings: { stored: number; truncated: number; added: number; resolved: number; continued: number };
}

/** 全レイヤーのノード自身の検出脅威を、突き合わせ用に（対象ノード id つきで）まとめる。 */
export function collectThreatRefs(results: readonly LayerAnalysisResult[]): ThreatRef[] {
  const out: ThreatRef[] = [];
  for (const r of results) {
    for (const t of r.threats) {
      if (!t.canonicalId) continue;
      // 突き合わせはノード自身の脅威だけ（エッジの脅威は端点のノードに結びつけない）
      if (t.subject?.kind !== 'node') continue;
      const nodeIds = [t.subject.id];
      out.push({ canonicalId: t.canonicalId, name: t.name ?? t.category, severity: effectiveSeverity(t), nodeIds });
    }
  }
  return out;
}

export function importProwler(
  rawProject: unknown,
  parsed: ParsedProwler,
  nodeMap: Readonly<Record<string, string>> = {},
  map: readonly ProwlerMapping[] = BUNDLED_PROWLER_MAP,
  importedAt: string = new Date().toISOString(),
): ImportProwlerOutput {
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
  const threats = collectThreatRefs(analyzeResolvedProject(resolved));
  const result = applyProwler({ nodes, findings: parsed.findings, map, nodeMap, threats });

  const loaded = deserializeProject(rawProject);
  if (!loaded) throw new Error('プロジェクト JSON の形式が不正です。');
  const project: PersistedProject = { ...loaded };
  if (loaded.layers) {
    const layers = { ...loaded.layers };
    for (const key of LAYER_KEYS) {
      const data = layers[key];
      if (data) layers[key] = { ...data, nodes: fillNodes(data.nodes, result.applied, key) };
    }
    project.layers = layers;
  } else if (loaded.nodes) {
    project.nodes = fillNodes(loaded.nodes, result.applied, 'L1' as LayerKey);
  }

  const converted = toFindings({
    findings: parsed.findings,
    map,
    nodes,
    nodeMap,
    productVersion: parsed.productVersion,
    importedAt,
  });
  const replaced = replaceFindings(loaded.findings, converted.findings, 'Prowler');
  if (replaced.findings.length > 0) project.findings = replaced.findings;
  else delete project.findings;
  return {
    result,
    project,
    skipped: parsed.skipped,
    findings: {
      stored: converted.findings.length,
      truncated: converted.truncated,
      ...replaced.diff,
    },
  };
}

const show = (v: FieldValue): string => String(v);

function basisLine(b: BasisEntry): string {
  return `${b.resource}（${b.checks.map((c) => `${c.checkId}=${show(c.value)}`).join('、')}）`;
}

function basisText(basis: readonly BasisEntry[]): string {
  return basis.map(basisLine).join(' / ');
}

const REASON_TEXT = {
  none: 'タグ crs-node も --map の対応も無い',
  unknownNode: '指定されたノードが図に無い',
  ambiguous: 'C 番号が複数のレイヤーに該当（ノード ID で指定してください）',
} as const;

export function prowlerReportToMarkdown(out: ImportProwlerOutput): string {
  const r = out.result;
  const s = r.summary;
  const lines: string[] = [
    '# Prowler 取り込みレポート',
    '',
    '- Prowler の検査結果を図のノードに載せた結果。入力済みの値は上書きしない（食い違いは下に出す）。',
    `- 検査結果 ${s.findings} 件（検査 ${s.mappedChecks} 種を対応表で処理 / 対応表に無い ${s.unknownChecks} 種 / MANUAL ${s.manual} 件）` +
      `（読めなかった ${out.skipped.invalid} 件・ミュート済み ${out.skipped.muted} 件は除外）`,
    `- 適用 ${s.applied} / 同じ値 ${s.unchanged} / 食い違い ${s.conflicts} / 適用できない ${s.notApplicable} / 対応するノードが無い資源 ${s.unmatchedResources}`,
    `- 図の脅威との突き合わせは、結びついたノード自身の脅威とだけ行う（ノードに結びつかない資源の FAIL ${s.unlinkedFails} 件は突き合わせていない）`,
    '',
    '## 適用した値（未入力だった項目）',
    '',
  ];
  if (r.applied.length === 0) lines.push('なし');
  for (const a of r.applied) lines.push(`- ${a.node} の ${a.field} = ${show(a.value)} ← ${basisText(a.basis)}`);

  lines.push('', '## 食い違い（入力済みの値と Prowler の値が違うため適用していない）', '');
  if (r.conflicts.length === 0) lines.push('なし');
  for (const c of r.conflicts) {
    lines.push(`- ${c.node} の ${c.field}: 現在 ${show(c.current)} / Prowler ${show(c.prowler)} ← ${basisText(c.basis)}`);
  }

  lines.push('', '## 適用できない（ノードの型がその項目を持たない）', '');
  if (r.notApplicable.length === 0) lines.push('なし');
  for (const n of r.notApplicable) {
    lines.push(`- ${n.node}（${n.type}）の ${n.field}: Prowler ${show(n.prowler)} ← ${basisText(n.basis)}`);
  }

  const keyTypeItems = r.applied.filter((a) => a.keyTypeUnverified);
  lines.push('', '## 鍵の種類を確認してください（Prowler では判別できない。CMK なら顧客管理の鍵に変更）', '');
  if (keyTypeItems.length === 0) lines.push('なし');
  for (const a of keyTypeItems) {
    const items = a.basis
      .filter((b) => b.keyTypeUnverified)
      .map(
        (b) =>
          `${b.resource}（${b.checks
            .filter((c) => c.value === 'ProviderManagedKey')
            .map((c) => c.checkId)
            .join('、')}）`,
      );
    lines.push(`- ${a.node} の ${a.field} = ${show(a.value)} ← ${items.join(' / ')}`);
  }

  if (r.unchanged.length > 0) {
    lines.push('', '## 同じ値（変更なし）', '');
    for (const u of r.unchanged) lines.push(`- ${u.node} の ${u.field} = ${show(u.value)}`);
  }

  lines.push('', '## 対応するノードが無い資源', '');
  if (r.unmatchedResources.length === 0) lines.push('なし');
  for (const u of r.unmatchedResources) {
    const where = [u.service, u.type, u.region].filter(Boolean).join(' / ');
    lines.push(
      `- ${u.resource}${where ? `（${where}）` : ''}: ${REASON_TEXT[u.reason]}${u.ref ? `（指定: ${u.ref}）` : ''} — 検査 ${u.checks.join(', ')}`,
    );
  }

  lines.push('', '## 図の脅威と突き合わせ（FAIL の検査）', '', '### 確認された（結びついたノードの脅威に Prowler の FAIL の裏付けがある）', '');
  if (r.confirmed.length === 0) lines.push('なし');
  for (const c of r.confirmed) {
    const names = [...new Set(c.threats.map((t) => `[${t.severity}] ${t.name}`))];
    lines.push(`- **${c.canonicalId}** — 図の脅威: ${names.join(' / ')}`);
    for (const h of c.hits) lines.push(`  - ${h.resource}${h.node ? `（${h.node}）` : ''} — ${h.checkId}`);
  }

  lines.push('', '### 図に無い候補（Prowler は FAIL だが図からは検出されていない）', '');
  if (r.notInModel.length === 0) lines.push('なし');
  for (const n of r.notInModel) {
    lines.push(`- **${n.canonicalId}**`);
    for (const h of n.hits) lines.push(`  - ${h.resource}${h.node ? `（${h.node}）` : ''} — ${h.checkId}`);
  }

  lines.push('', '### ノードに結びつかないため突き合わせていない（FAIL）', '');
  if (r.unlinkedFails.length === 0) lines.push('なし');
  for (const n of r.unlinkedFails) {
    lines.push(`- **${n.canonicalId}**`);
    for (const h of n.hits) lines.push(`  - ${h.resource} — ${h.checkId}`);
  }

  lines.push('', '### 対応づけできない（FAIL だが脅威の対応が無い検査）', '');
  if (r.unmappedChecks.length === 0) lines.push('なし');
  for (const u of r.unmappedChecks) {
    lines.push(`- ${u.checkId}${u.severity ? ` [${u.severity}]` : ''}${u.title ? ` ${u.title}` : ''} × ${u.count}`);
  }

  const f = out.findings;
  lines.push('', '## 保存した指摘（FAIL）', '');
  lines.push(`- 保存 ${f.stored} 件（新規 ${f.added} / 解消 ${f.resolved} / 継続 ${f.continued}）`);
  if (f.truncated > 0) lines.push(`- 上限（${MAX_FINDINGS} 件）を超えたため保存しなかった指摘 ${f.truncated} 件`);
  lines.push('- 指摘は --out のプロジェクト JSON に保存され、`analyze --format sarif --with-findings` で書き出せる');
  return lines.join('\n');
}

/** 機械処理用の JSON オブジェクト（キーは英語固定）。 */
export function prowlerReportToJson(out: ImportProwlerOutput): Record<string, unknown> {
  return {
    schemaVersion: 1,
    kind: 'cyberriskscape-prowler-import-report',
    skipped: out.skipped,
    findings: out.findings,
    ...out.result,
  };
}
