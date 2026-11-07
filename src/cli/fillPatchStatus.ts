import { deserializeProject } from '../features/persistence/serialize';
import { fillPatchStatus, type FillPatchStatusResult } from '../features/kev-import/fillPatchStatus';

/**
 * CLI `fill-patch-status`：CVE 付きの保存済み指摘があるノードの patchStatus 未入力を 'Missing' で埋める。
 * ファイル I/O は呼び出し側（main.ts）。
 */

export function runFillPatchStatus(rawProject: unknown): FillPatchStatusResult {
  const loaded = deserializeProject(rawProject);
  if (!loaded) throw new Error('プロジェクト JSON の形式が不正です。');
  return fillPatchStatus(loaded);
}

export function fillPatchStatusToMarkdown(out: FillPatchStatusResult, dryRun: boolean): string {
  const lines = [
    '# パッチ状況の補完レポート',
    '',
    '- CVE を持つ指摘（試行のみは除く）があるノードの patchStatus 未入力を「未適用（Missing）」にする。人の入力は上書きしない。',
    '- 「更新済み（UpToDate）」は書かない（指摘が無いことは更新済みの証明にならない）。',
    `- ${dryRun ? '補完の対象（--dry-run のため保存しない）' : '補完したノード'}: ${out.filled.length} 件`,
    `- 見送り: 入力済み ${out.skipped.alreadySet} / 型がパッチ状況を持たない ${out.skipped.noPatchGroup} / ノードに結びつかない指摘 ${out.skipped.unboundFindings}`,
    '',
  ];
  for (const f of out.filled) lines.push(`- ${f.layer} ${f.label}（${f.type}）: ${f.cves.join(', ')}`);
  return lines.join('\n');
}
