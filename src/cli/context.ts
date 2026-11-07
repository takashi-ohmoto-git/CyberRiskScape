import { analyzeResolvedProject, resolveProject } from './analyze';
import { LAYER_KEYS } from '../core/model/types';
import { lookupNode } from '../features/findings-import/resolveNode';
import { ENTRY_SEARCH_APPLICABLE } from '../features/attack-tree/findEntryPoints';
import { lookupContext, type ContextQuery, type ContextResult } from '../features/attack-tree/lookupContext';

/**
 * CLI `context`：アラートの IP・ホスト名・purl から、図のノード・前段・脅威・指摘・露出を引く（読み取り専用）。
 * ファイル I/O は呼び出し側（main.ts）。MCP の lookup_context も同じ関数を使う。
 */

export interface ContextOptions {
  /** C 番号またはノード ID。無ければ各レイヤーの図の攻撃者ノードの先頭。 */
  attacker?: string;
}

export function contextLookup(rawProject: unknown, query: ContextQuery, options: ContextOptions = {}): ContextResult {
  const resolved = resolveProject(rawProject);
  const results = analyzeResolvedProject(resolved);

  let attackerId: string | undefined;
  if (options.attacker !== undefined) {
    const refs = LAYER_KEYS.flatMap((layer) =>
      resolved.layers[layer].nodes.map((n) => ({ id: n.id, layer, seq: n.seq, type: n.type, label: n.label })),
    );
    const found = lookupNode(refs, options.attacker);
    if (found.kind === 'ambiguous') throw new Error(`攻撃者 ${options.attacker} が複数のレイヤーに該当します（ノード ID で指定してください）。`);
    if (found.kind === 'unknown') throw new Error(`攻撃者 ${options.attacker} が図に見つかりません。`);
    if (!ENTRY_SEARCH_APPLICABLE.has(found.node.type)) {
      throw new Error(`ノード ${options.attacker} は攻撃者（AI エージェント攻撃者）の型ではありません。`);
    }
    attackerId = found.node.id;
  }

  return lookupContext(
    {
      layers: results.map((r) => ({ ...r.input, layer: r.layer, threats: r.threats })),
      assets: resolved.assets,
      bomComponents: resolved.bomComponents,
      findings: resolved.findings,
      ...(attackerId ? { attackerId } : {}),
    },
    query,
  );
}

const cell = (s: string) => s.replace(/[\r\n]+/g, ' ').replace(/\|/g, '\\|');

const EXPOSURE_TEXT: Record<string, string> = {
  entry: '入口',
  reachable: '入口の奥（到達）',
  unreachable: '到達なし',
  unbound: '未結合',
  unevaluated: '評価不可（攻撃者なし）',
};

export function contextToMarkdown(r: ContextResult): string {
  const q = r.query.ip ? `ip=${r.query.ip}` : r.query.host ? `host=${r.query.host}` : `purl=${r.query.purl}`;
  const lines: string[] = [
    `# 文脈の照会（${cell(q)}）`,
    '',
    '> 図と取り込み済みの記録に基づく事実の一覧。優先度は推奨であり、判断は人が行う。悪用できるとは言わない。',
    '> 「（仮定）」は未入力の攻撃面属性を悪い値と仮定した判定。',
    '',
  ];
  if (r.noAttacker) lines.push('- 図に攻撃者（AI エージェント攻撃者）のノードが無く、露出を評価できない。`--attacker` で指定するか、図に攻撃者を置く。', '');
  if (r.truncated) lines.push('- 一致が多いため先頭だけを表示している。', '');
  if (r.matches.length === 0) {
    lines.push('- 該当する資産・部品・ノードは見つからなかった。', '');
    return lines.join('\n');
  }
  r.matches.forEach((m, i) => {
    lines.push(`## 一致 ${i + 1}（${m.matchedBy}）`, '');
    lines.push(`- 記録: ${cell(JSON.stringify(m.record))}`);
    if (!m.bound || !m.node) {
      lines.push(`- 未結合: ${m.note ?? ''}`, '');
      return;
    }
    lines.push(`- ノード: ${m.node.layer} ${m.node.elementalId} ${cell(m.node.name)}（${m.node.type}）`);
    lines.push(`- 信頼境界: ${m.node.boundaries.map((b) => `${cell(b.label)}（${b.trustLevel}）`).join('、') || '—'}`);
    lines.push(`- 前段: ${(m.frontDoors ?? []).map((f) => `${f.elementalId} ${cell(f.name)}（${f.type}）`).join('、') || '—'}`);
    const ex = m.exposure!;
    lines.push(
      `- 露出: ${EXPOSURE_TEXT[ex.value]}${ex.assumed ? '（仮定）' : ''}／届く標的: ${ex.reachesTargets.map((t) => `${cell(t.name)}（${t.hops} ホップ）`).join('、') || '—'}`,
      '',
    );
    lines.push(`### 脅威（${m.threats!.length} 件）`, '');
    for (const t of m.threats!) {
      lines.push(`- ${t.effectiveSeverity}${t.suppressed ? '（対応方針で抑制済み）' : ''} ${cell(t.name)}${t.canonicalId ? ` [${t.canonicalId}]` : ''}`);
    }
    lines.push('', `### 指摘（${m.findings!.length} 件）`, '');
    if (m.findings!.length > 0) {
      lines.push('| 指摘 | 製品 | 元の深刻度 | 推奨 | 露出 | 届く標的 | KEV | 連鎖 |', '| --- | --- | --- | --- | --- | --- | --- | --- |');
      for (const f of m.findings!) {
        lines.push(
          `| ${cell(f.title ?? f.id)} | ${cell(f.product)} | ${f.severity} | ${f.priority} | ${EXPOSURE_TEXT[f.exposure]}${f.exposureAssumed ? '（仮定）' : ''} | ${cell(f.reachesTargets.map((t) => t.name).join('、') || '—')} | ${f.kev ? 'あり' : '—'} | ${f.chainCount} |`,
        );
      }
    }
    lines.push('');
  });
  return lines.join('\n');
}
