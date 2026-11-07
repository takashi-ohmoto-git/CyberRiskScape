import { resolveProject } from './analyze';
import {
  reconcileAsm,
  type ObservedLine,
  type ReconcileResult,
} from '../features/asm-import/reconcileAsm';

/**
 * CLI `asm-reconcile`：図の「外部公開」の入力と、ASM が観測した資産の食い違いを並べる読み取り専用の報告
 * （docs/research/nco-advisory-2026-11-05.md §3 候補 E）。判定はしない。ファイル I/O は呼び出し側（main.ts）。
 */

export function asmReconcile(rawProject: unknown, rawPrevious?: unknown): ReconcileResult {
  const cur = resolveProject(rawProject);
  const prev = rawPrevious === undefined ? undefined : resolveProject(rawPrevious).assets ?? [];
  return reconcileAsm({ layers: cur.layers, assets: cur.assets }, prev);
}

const cell = (s: string) => s.replace(/[\r\n]+/g, ' ').replace(/\|/g, '\\|');

function assetTable(lines: readonly ObservedLine[], withNode: boolean): string[] {
  const head = ['ホスト', 'IP', 'ポート', 'サービス', '製品', '観測時刻', ...(withNode ? ['ノード'] : [])];
  const rows = lines.map((l) =>
    [l.host, l.ip ?? '—', l.port != null ? String(l.port) : '—', l.serviceName ?? '—', l.product, l.observedAt ?? '—', ...(withNode ? [l.node ?? '—'] : [])]
      .map(cell)
      .join(' | '),
  );
  return [`| ${head.join(' | ')} |`, `| ${head.map(() => '---').join(' | ')} |`, ...rows.map((r) => `| ${r} |`), ''];
}

export function reconcileToMarkdown(r: ReconcileResult): string {
  const out: string[] = [
    '# ASM の観測と図の突き合わせ',
    '',
    '> 図の入力と ASM の観測の食い違いを事実として並べる。どちらが正しいかは判定しない。観測の範囲外のものは載らない。',
    '',
    `- 観測した資産 ${r.observedCount} 件 / 図に無い ${r.unbound.length} 件 / 非公開と入力 ${r.privateButObserved.length} 件 / 未入力 ${r.unsetButObserved.length} 件` +
      (r.publicButUnseen ? ` / 公開と入力したが観測に無い ${r.publicButUnseen.length} 件` : ''),
    '',
  ];

  const section = (title: string, lines: readonly ObservedLine[], withNode: boolean) => {
    out.push(`## ${title}（${lines.length} 件）`, '');
    if (lines.length === 0) out.push('- 該当なし', '');
    else out.push(...assetTable(lines, withNode));
  };
  section('図に無いのに外から見える', r.unbound, false);
  section('非公開と入力したのに外から見える', r.privateButObserved, true);
  out.push('> 攻撃面属性（Global IP）を入力すると、仮定の印が消える。', '');
  section('外から見えている（Global IP が未入力）', r.unsetButObserved, true);

  out.push('## 公開と入力したが観測に無い', '');
  if (r.publicButUnseen === null) {
    out.push('- ASM 結果が未取り込みのため、突き合わせできない。', '');
  } else if (r.publicButUnseen.length === 0) {
    out.push('- 該当なし', '');
  } else {
    out.push('> 観測の範囲外か、図が古い可能性がある。', '', ...r.publicButUnseen.map((n) => `- ${n.layer}: ${n.node}`), '');
  }

  if (r.diff) {
    out.push('## 前回との差分', '');
    out.push(`### 新しく見えた（${r.diff.appeared.length} 件）`, '');
    out.push(...(r.diff.appeared.length ? assetTable(r.diff.appeared, true) : ['- 該当なし', '']));
    out.push(`### 見えなくなった（${r.diff.disappeared.length} 件）`, '');
    out.push(...(r.diff.disappeared.length ? assetTable(r.diff.disappeared, false) : ['- 該当なし', '']));
  }
  return out.join('\n');
}

export function reconcileToJson(r: ReconcileResult): Record<string, unknown> {
  return { schemaVersion: 1, kind: 'cyberriskscape-asm-reconcile', ...r };
}
