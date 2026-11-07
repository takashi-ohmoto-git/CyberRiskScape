import { resolveProject } from './analyze';
import { sbomAcceptance, type SbomAcceptanceResult } from '../features/bom-import/sbomAcceptance';

/**
 * CLI `sbom-report`：保存済みの SBOM の検収レポート（読み取り専用）。検収の補助であり、合否・ライセンスの適否は判定しない
 * （docs/research/nco-advisory-2026-11-05.md §3 候補 Z）。ファイル I/O は呼び出し側（main.ts）。
 */

export function sbomReport(rawProject: unknown, opts: { maxAgeDays?: number; now?: Date } = {}): SbomAcceptanceResult {
  const p = resolveProject(rawProject);
  return sbomAcceptance(
    { layers: p.layers, bomComponents: p.bomComponents, findings: p.findings },
    { now: opts.now ?? new Date(), ...(opts.maxAgeDays !== undefined ? { maxAgeDays: opts.maxAgeDays } : {}) },
  );
}

const cell = (s: string) => s.replace(/[\r\n]+/g, ' ').replace(/\|/g, '\\|');

export function sbomReportToMarkdown(r: SbomAcceptanceResult): string {
  const out: string[] = [
    '# SBOM の検収レポート',
    '',
    '> 検収の補助として事実を並べる。合否は判定しない。ライセンスの適否も判定しない。',
    '',
    `- 保存済みの部品 ${r.componentCount} 件（CycloneDX・SPDX から取り込んだもの）/ SBOM の無いノード ${r.nodesWithoutSbom.length} 件 / ライセンス欄が空の部品 ${r.licensesMissing} 件`,
    '',
    `## SBOM の無いノード（${r.nodesWithoutSbom.length} 件）`,
    '',
    '> 運用状況で patch・dependency を宣言する型のうち、結びついた部品が無いノード。',
    '',
    ...(r.nodesWithoutSbom.length ? r.nodesWithoutSbom.map((n) => `- ${n}`) : ['- 該当なし']),
    '',
    '## 取り込み単位ごとの状況',
    '',
  ];
  if (r.perSource.length === 0) out.push('- SBOM が未取り込み', '');
  else {
    out.push('| 製品 | scope | 部品数 | 結びついたノード | BOM 作成時刻（最も古い） | 状態 |', '| --- | --- | --- | --- | --- | --- |');
    for (const s of r.perSource) {
      const flags = [
        s.stale ? `${r.maxAgeDays} 日より古い` : '',
        s.noTimestamp ? '作成時刻なしの部品あり' : '',
      ].filter(Boolean);
      out.push(
        `| ${cell(s.product)} | ${cell(s.scope ?? '—')} | ${s.components} | ${cell(s.nodes.join('、') || '—')} | ${s.observedAt ?? '—'} | ${flags.join('・') || '—'} |`,
      );
    }
    out.push('');
  }

  out.push('## 図に結びついていない部品', '');
  if (r.unboundComponents.length === 0) out.push('- 該当なし', '');
  else {
    for (const g of r.unboundComponents) {
      out.push(`- ${g.product}${g.scope ? `（${g.scope}）` : ''}: ${g.count} 件（${g.names.join('、')}${g.count > g.names.length ? ' ほか' : ''}）`);
    }
    out.push('');
  }

  out.push('## 脆弱性（CycloneDX の vulnerabilities 由来の指摘）', '');
  if (r.vulnerabilities.length === 0) out.push('- 該当なし', '');
  else {
    out.push('| ノード | Critical | High | Medium | Low | KEV |', '| --- | --- | --- | --- | --- | --- |');
    for (const v of r.vulnerabilities) {
      out.push(`| ${cell(v.node ?? '（未結合）')} | ${v.counts.Critical} | ${v.counts.High} | ${v.counts.Medium} | ${v.counts.Low} | ${v.kev} |`);
    }
    out.push('');
  }
  return out.join('\n');
}

export function sbomReportToJson(r: SbomAcceptanceResult): Record<string, unknown> {
  return { schemaVersion: 1, kind: 'cyberriskscape-sbom-report', ...r };
}
