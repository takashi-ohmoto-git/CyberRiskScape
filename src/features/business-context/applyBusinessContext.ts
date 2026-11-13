import {
  BUSINESS_CRITICALITIES,
  LAYER_KEYS,
  type BusinessCriticality,
  type BusinessCriticalitySource,
  type BusinessProcessRef,
  type ComponentTypeId,
  type LayerKey,
  type NodeBusinessContext,
} from '../../core/model/types';
import { lookupNode, type ImportNodeRef } from '../findings-import/resolveNode';
import type { BusinessContextRow } from './parseBusinessContextTable';

/**
 * 業務の文脈の表の行を、ノードの `businessContext` に反映する純粋関数（ベンダー非依存）。
 * - ノードは ID または C 番号で全レイヤーから引く（他の取り込みと同じ `lookupNode`）。
 * - 同じノードの同じプロセス名の行は合算する。
 * - 重要度：行に書かれていれば最大値（declared）。無ければ表全体の金額（無ければ件数）に占める割合から決める（derived）。
 *   割合 30% 以上＝High、10% 以上＝Medium、それ未満＝Low。
 * - 表に出てきたノードだけ置き換える。他のノードと、businessContext 以外の項目は触らない。
 */

export const DEFAULT_BUSINESS_CONTEXT_PRODUCT = 'business-context';
export const SHARE_HIGH = 0.3;
export const SHARE_MEDIUM = 0.1;
const MAX_PROCESSES = 100;

type Node = Omit<ImportNodeRef, 'layer'> & { businessContext?: NodeBusinessContext };
type Layer = { nodes: Node[] };

export interface AppliedNode {
  nodeId: string;
  layer: LayerKey;
  seq?: number;
  label?: string;
  type: ComponentTypeId;
  criticality: BusinessCriticality;
  criticalitySource: BusinessCriticalitySource;
  /** 表全体に占める割合（0〜1。割合の基準があるときだけ）。 */
  share?: number;
  processCount: number;
}

export interface SkippedNode {
  nodeId: string;
  layer: LayerKey;
  seq?: number;
  label?: string;
  /** 'noCriticality'：行に重要度が無く、金額・件数も表に無いため決められない。 */
  reason: 'noCriticality';
}

export interface ApplyBusinessContextSummary {
  applied: AppliedNode[];
  unknownRefs: string[];
  ambiguousRefs: string[];
  skipped: SkippedNode[];
  /** 割合の基準：金額・件数・なし。 */
  basis: 'value' | 'cases' | 'none';
  /** 合算・通貨・上限の注意（日本語）。 */
  notes: string[];
  rows: number;
}

export interface ApplyBusinessContextOptions {
  now: Date;
  source?: { product?: string; ref?: string };
}

export function applyBusinessContext<L extends Layer>(
  layers: Partial<Record<LayerKey, L>>,
  rows: readonly BusinessContextRow[],
  options: ApplyBusinessContextOptions,
): { layers: Partial<Record<LayerKey, L>>; summary: ApplyBusinessContextSummary } {
  const refs: ImportNodeRef[] = LAYER_KEYS.flatMap((layer) =>
    (layers[layer]?.nodes ?? []).map((n) => ({ id: n.id, layer, seq: n.seq, type: n.type, label: n.label })),
  );
  const notes: string[] = [];

  // 割合の基準（表全体＝図に無い行も含める）。通貨が混在するときは件数にする。
  const currencies = new Set(rows.filter((r) => r.value !== undefined && r.currency).map((r) => r.currency));
  const totalValue = rows.reduce((s, r) => s + (r.value ?? 0), 0);
  const totalCases = rows.reduce((s, r) => s + (r.cases ?? 0), 0);
  let basis: ApplyBusinessContextSummary['basis'] = 'none';
  if (totalValue > 0 && currencies.size <= 1) basis = 'value';
  else if (totalCases > 0) basis = 'cases';
  if (totalValue > 0 && currencies.size > 1) {
    notes.push(`通貨が混在しているため（${[...currencies].join('・')}）、金額は割合の基準にしていません。`);
  }
  const total = basis === 'value' ? totalValue : basis === 'cases' ? totalCases : 0;

  const unknown = new Set<string>();
  const ambiguous = new Set<string>();
  const byNode = new Map<string, { node: ImportNodeRef; rows: BusinessContextRow[] }>();
  for (const r of rows) {
    const found = lookupNode(refs, r.node);
    if (found.kind === 'unknown') unknown.add(r.node);
    else if (found.kind === 'ambiguous') ambiguous.add(r.node);
    else {
      const key = `${found.node.layer}:${found.node.id}`;
      const g = byNode.get(key) ?? { node: found.node, rows: [] };
      g.rows.push(r);
      byNode.set(key, g);
    }
  }

  const applied: AppliedNode[] = [];
  const skipped: SkippedNode[] = [];
  const next = new Map<string, NodeBusinessContext>();
  const retrievedAt = options.now.toISOString();

  for (const [key, g] of byNode) {
    const label = g.node.label?.trim() || undefined;
    const id = {
      nodeId: g.node.id,
      layer: g.node.layer,
      ...(g.node.seq !== undefined ? { seq: g.node.seq } : {}),
      ...(label ? { label } : {}),
    };
    const where = g.node.seq !== undefined ? `C${g.node.seq}` : g.node.id;
    const processes = mergeProcesses(g.rows, where, notes);
    const declared = g.rows
      .map((r) => r.criticality)
      .filter((c): c is BusinessCriticality => c !== undefined)
      .sort((a, b) => BUSINESS_CRITICALITIES.indexOf(a) - BUSINESS_CRITICALITIES.indexOf(b))[0];

    let criticality: BusinessCriticality;
    let source: BusinessCriticalitySource;
    let share: number | undefined;
    if (declared) {
      criticality = declared;
      source = 'declared';
    } else if (basis === 'none') {
      skipped.push({ ...id, reason: 'noCriticality' });
      continue;
    } else {
      const mine = g.rows.reduce((s, r) => s + ((basis === 'value' ? r.value : r.cases) ?? 0), 0);
      share = mine / total;
      criticality = share >= SHARE_HIGH ? 'High' : share >= SHARE_MEDIUM ? 'Medium' : 'Low';
      source = 'derived';
    }

    next.set(key, {
      criticality,
      criticalitySource: source,
      processes,
      source: {
        product: options.source?.product ?? DEFAULT_BUSINESS_CONTEXT_PRODUCT,
        retrievedAt,
        ...(options.source?.ref ? { ref: options.source.ref } : {}),
      },
    });
    applied.push({
      ...id,
      type: g.node.type,
      criticality,
      criticalitySource: source,
      ...(share !== undefined ? { share } : {}),
      processCount: processes.length,
    });
  }

  const out: Partial<Record<LayerKey, L>> = { ...layers };
  for (const layer of LAYER_KEYS) {
    const data = layers[layer];
    if (!data) continue;
    if (!data.nodes.some((n) => next.has(`${layer}:${n.id}`))) continue;
    out[layer] = {
      ...data,
      nodes: data.nodes.map((n) => {
        const bc = next.get(`${layer}:${n.id}`);
        return bc ? { ...n, businessContext: bc } : n;
      }),
    };
  }

  return {
    layers: out,
    summary: { applied, unknownRefs: [...unknown], ambiguousRefs: [...ambiguous], skipped, basis, notes, rows: rows.length },
  };
}

/** 同じプロセス名の行を合算する。通貨・期間が食い違えば落として注意に書く。金額の大きい順。 */
function mergeProcesses(rows: readonly BusinessContextRow[], where: string, notes: string[]): BusinessProcessRef[] {
  const groups = new Map<string, BusinessContextRow[]>();
  for (const r of rows) groups.set(r.process, [...(groups.get(r.process) ?? []), r]);
  const out: BusinessProcessRef[] = [];
  for (const [name, rs] of groups) {
    const p: BusinessProcessRef = { name };
    if (rs.some((r) => r.cases !== undefined)) p.cases = rs.reduce((s, r) => s + (r.cases ?? 0), 0);
    if (rs.some((r) => r.value !== undefined)) p.value = rs.reduce((s, r) => s + (r.value ?? 0), 0);
    const currencies = new Set(rs.map((r) => r.currency).filter((c): c is string => c !== undefined));
    if (currencies.size === 1) p.currency = [...currencies][0];
    else if (currencies.size > 1) notes.push(`${where} のプロセス「${name}」は通貨が食い違うため、通貨を記録していません。`);
    const periods = new Set(rs.map((r) => r.period).filter((c): c is string => c !== undefined));
    if (periods.size === 1) p.period = [...periods][0];
    else if (periods.size > 1) notes.push(`${where} のプロセス「${name}」は期間が食い違うため、期間を記録していません。`);
    out.push(p);
  }
  out.sort((a, b) => (b.value ?? 0) - (a.value ?? 0) || (b.cases ?? 0) - (a.cases ?? 0));
  if (out.length > MAX_PROCESSES) {
    notes.push(`${where} のプロセスが ${out.length} 件あり、上位 ${MAX_PROCESSES} 件だけ記録しました。`);
    out.length = MAX_PROCESSES;
  }
  return out;
}
