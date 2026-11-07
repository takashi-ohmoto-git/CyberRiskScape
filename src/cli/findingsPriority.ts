import { analyzeResolvedProject, resolveProject } from './analyze';
import { LAYER_KEYS, type DiagramNode, type Finding, type LayerKey } from '../core/model/types';
import { formatElementalId } from '../core/model/elementalId';
import { lookupNode } from '../features/findings-import/resolveNode';
import { ENTRY_SEARCH_APPLICABLE } from '../features/attack-tree/findEntryPoints';
import {
  DEFAULT_EPSS_THRESHOLD,
  prioritizeFindings,
  type FindingExposure,
  type FindingPriority,
  type PrioritizeResult,
} from '../features/attack-tree/prioritizeFindings';

/**
 * CLI `findings-priority`：保存済みの指摘を攻撃経路に載せ、推奨の優先度（P1〜P4）と根拠を出す
 * （docs/attack-tree-analysis.md §12）。ファイル I/O は呼び出し側（main.ts）。
 */

export interface FindingsPriorityOptions {
  /** C 番号またはノード ID。無ければ各レイヤーの図の攻撃者ノードの先頭。 */
  attacker?: string;
  layer?: LayerKey;
  /** EPSS がこの値以上の指摘は、入口・入口の奥にあれば優先度を 1 段上げる（既定 0.1）。 */
  epssThreshold?: number;
}

export interface FindingsPriorityOutput {
  result: PrioritizeResult;
  /** 要確認の指摘（outcome 'unverified'。重大度がないので優先度づけの対象外）。 */
  unverified: Finding[];
  /** ノード id（レイヤー付き）→ 表示名。 */
  names: Map<string, string>;
  /** 攻撃者を評価に使えたレイヤーが 1 つも無い。 */
  noAttacker: boolean;
  /** 優先度の引き上げに使った EPSS のしきい値。 */
  epssThreshold: number;
}

const nameKey = (layer: LayerKey, nodeId: string) => `${layer}:${nodeId}`;

function nodeName(n: DiagramNode): string {
  return `${n.seq != null ? formatElementalId('node', n.seq) : n.id} ${n.label?.trim() || n.type}`;
}

export function findingsPriority(rawProject: unknown, options: FindingsPriorityOptions = {}): FindingsPriorityOutput {
  const resolved = resolveProject(rawProject);
  const results = analyzeResolvedProject(resolved, options.layer ? { layer: options.layer } : {});

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

  // --layer 指定時は、そのレイヤーの指摘と未結合の指摘だけを評価する。
  const inScope = (resolved.findings ?? []).filter((f) => !options.layer || !f.subject || f.subject.layer === options.layer);
  const unverified = inScope.filter((f) => f.outcome === 'unverified');
  const findings = inScope.filter((f) => f.outcome !== 'unverified');
  const epssThreshold = options.epssThreshold ?? DEFAULT_EPSS_THRESHOLD;
  const result = prioritizeFindings(
    results.map((r) => ({ ...r.input, layer: r.layer, threats: r.threats })),
    findings,
    attackerId,
    { epssThreshold },
  );

  const names = new Map<string, string>();
  for (const r of results) for (const n of r.input.nodes) names.set(nameKey(r.layer, n.id), nodeName(n));
  return { result, unverified, names, noAttacker: Object.keys(result.attackers).length === 0, epssThreshold };
}

const EXPOSURE_TEXT: Record<FindingExposure, string> = {
  entry: '入口',
  reachable: '入口の奥（到達）',
  unreachable: '到達なし',
  unbound: '未結合',
  unevaluated: '評価不可（攻撃者なし）',
};

const PRIORITY_TEXT: Record<FindingPriority, string> = {
  P1: 'P1（先に確認）',
  P2: 'P2',
  P3: 'P3',
  P4: 'P4（経路上の根拠なし）',
};

/** 表のセルに入れる文字列の無害化（改行・縦線）。 */
const cell = (s: string) => s.replace(/[\r\n]+/g, ' ').replace(/\|/g, '\\|');

export function priorityToMarkdown(out: FindingsPriorityOutput): string {
  const { result, names } = out;
  const name = (layer: LayerKey | undefined, id: string | undefined) =>
    (layer && id ? names.get(nameKey(layer, id)) : undefined) ?? '（未結合）';
  const lines: string[] = [
    '# 指摘の優先度（推奨）',
    '',
    '> これは推奨と根拠であり、判断は人が行う。悪用できるとは言わない。元の深刻度は変えていない。',
    '> 露出は図の入力に基づく。「（仮定）」は未入力の攻撃面属性を悪い値と仮定した判定。経路の列挙は上限に達すると漏れうる。',
    '',
  ];
  if (out.noAttacker) {
    lines.push('- 図に攻撃者（AI エージェント攻撃者）のノードが無く、露出を評価できない。`--attacker` で指定するか、図に攻撃者を置く。KEV の印がある指摘だけ P1。', '');
  }
  lines.push(
    `- 根拠は露出・届く標的・KEV・EPSS・連鎖。KEV でなく EPSS が ${out.epssThreshold} 以上で、露出が入口・入口の奥の指摘は、優先度を 1 段上げている（EPSS が低くても下げない）。`,
    '',
  );
  if (result.truncated) lines.push('- 経路の列挙が上限に達したため、連鎖に漏れがありうる。', '');
  lines.push(`- 指摘 ${result.items.length} 件 / 連鎖 ${result.chains.length} 件`, '');

  for (const p of ['P1', 'P2', 'P3', 'P4'] as const) {
    const items = result.items.filter((i) => i.priority === p);
    if (items.length === 0) continue;
    lines.push(`## ${PRIORITY_TEXT[p]}（${items.length} 件）`, '');
    lines.push('| 指摘 | 製品 | 元の深刻度 | ノード | 露出 | 届く標的 | KEV | EPSS |', '| --- | --- | --- | --- | --- | --- | --- | --- |');
    for (const i of items) {
      const f = i.finding;
      const title = f.title ?? f.identifiers[0]?.value ?? f.id;
      const exposure = `${EXPOSURE_TEXT[i.exposure]}${i.exposureAssumed ? '（仮定）' : ''}`;
      const targets =
        i.reachesTargets.map((t) => `${name(i.layer, t.nodeId)}（${t.hops} ホップ）`).join('、') || '—';
      const kev = f.kev ? `あり${f.kev.dateAdded ? `（${f.kev.dateAdded}）` : ''}${f.kev.ransomware ? '・ランサムウェア利用' : ''}` : '—';
      const epss = f.epss ? f.epss.score.toFixed(2) : '—';
      lines.push(
        `| ${cell(title)} | ${cell(f.source.product)} | ${f.severity} | ${cell(i.nodeId ? name(i.layer, i.nodeId) : '（未結合）')} | ${exposure} | ${cell(targets)} | ${kev} | ${epss} |`,
      );
    }
    lines.push('');
  }

  if (out.unverified.length > 0) {
    lines.push(`## 要確認（重大度なし）（${out.unverified.length} 件）`, '');
    lines.push('- 根拠はあるが決め手の事実が未解決の指摘。重大度は付いておらず、優先度づけと連鎖の対象外。', '');
    lines.push('| 指摘 | 製品 | ノード |', '| --- | --- | --- |');
    for (const f of out.unverified) {
      lines.push(`| ${cell(f.title ?? f.identifiers[0]?.value ?? f.id)} | ${cell(f.source.product)} | ${cell(name(f.subject?.layer, f.subject?.nodeId))} |`);
    }
    lines.push('');
  }

  const low = result.chains.filter((c) => c.allMediumOrBelow);
  lines.push('## 組み合わさると標的に届く連鎖', '');
  if (result.chains.length === 0) {
    lines.push('- 経路上に指摘が 2 つ以上並ぶ連鎖は無い。', '');
  } else {
    lines.push(
      `- 経路上で指摘が 2 つ以上のノードに並ぶ連鎖 ${result.chains.length} 件のうち、個々の指摘はすべて Medium 以下 ${low.length} 件。`,
      '',
    );
    const byId = new Map(result.items.map((i) => [i.finding.id, i.finding]));
    for (const c of [...low, ...result.chains.filter((c) => !c.allMediumOrBelow)]) {
      const route = c.nodeIds.map((id) => name(c.layer, id)).join(' → ');
      const sevs = c.findingIds.map((id) => byId.get(id)?.severity ?? '?').join(' / ');
      lines.push(
        `- ${c.allMediumOrBelow ? '【個々は低いが連鎖で届く】' : ''}攻撃者 → ${route} → ${name(c.layer, c.targetId)}（指摘の深刻度: ${sevs}）`,
      );
    }
    lines.push('');
  }
  return lines.join('\n');
}

const SSVC_EXPOSURE: Partial<Record<FindingExposure, 'open' | 'controlled' | 'small'>> = {
  entry: 'open',
  reachable: 'controlled',
  unreachable: 'small',
};

/** 機械処理用の JSON オブジェクト（キーは英語固定）。SSVC は用語の対応であり、SSVC の判定はしない。 */
export function priorityToJson(out: FindingsPriorityOutput): Record<string, unknown> {
  const { result, names } = out;
  const name = (layer: LayerKey | undefined, id: string) => (layer ? names.get(nameKey(layer, id)) ?? null : null);
  return {
    schemaVersion: 1,
    kind: 'cyberriskscape-findings-priority',
    note: 'recommendation with grounds; decisions are made by people. This does not say a finding is exploitable.',
    ssvcMapping: {
      exploitation: 'Exploitation (active = on KEV, likely = no KEV mark and EPSS at or above the threshold, unknown = neither)',
      systemExposure: 'System Exposure (entry = open, reachable = controlled, unreachable = small)',
      reachesTargets: 'material for Mission Impact',
    },
    evaluated: !out.noAttacker,
    epssThreshold: out.epssThreshold,
    unverified: out.unverified.map((f) => ({
      id: f.id,
      title: f.title ?? null,
      product: f.source.product,
      layer: f.subject?.layer ?? null,
      node: f.subject ? name(f.subject.layer, f.subject.nodeId) : null,
    })),
    attackers: result.attackers,
    truncated: result.truncated,
    findings: result.items.map((i) => ({
      id: i.finding.id,
      title: i.finding.title ?? null,
      product: i.finding.source.product,
      severity: i.finding.severity,
      layer: i.layer ?? null,
      node: i.nodeId ? name(i.layer, i.nodeId) : null,
      priority: i.priority,
      exposure: i.exposure,
      exposureAssumed: i.exposureAssumed,
      exploitation: i.exploitation,
      kev: i.finding.kev ?? null,
      epss: i.finding.epss ?? null,
      reachesTargets: i.reachesTargets.map((t) => ({ nodeId: t.nodeId, node: name(i.layer, t.nodeId), hops: t.hops })),
      chains: i.chainIndexes,
      ssvc: {
        exploitation: i.exploitation === 'active' ? 'active' : 'none-or-unknown',
        systemExposure: SSVC_EXPOSURE[i.exposure] ?? null,
        missionImpactMaterial: i.reachesTargets.map((t) => t.nodeId),
      },
    })),
    chains: result.chains.map((c) => ({
      layer: c.layer,
      target: { nodeId: c.targetId, node: name(c.layer, c.targetId) },
      nodes: c.nodeIds.map((id) => ({ nodeId: id, node: name(c.layer, id) })),
      findingIds: c.findingIds,
      allMediumOrBelow: c.allMediumOrBelow,
    })),
  };
}
