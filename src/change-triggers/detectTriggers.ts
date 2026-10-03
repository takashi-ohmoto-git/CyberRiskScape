import {
  LAYER_KEYS,
  type DiagramBoundary,
  type DiagramEdge,
  type DiagramNode,
  type ElementKind,
  type LayerData,
  type LayerKey,
} from '../core/model/types';
import { resolveNodeTrust } from '../core/threat-engine/resolveNodeTrust';
import { formatElementalId } from '../core/model/elementalId';
import { componentRegistry } from '../component-library/defaultRegistry';
import type { ChangeTrigger, TriggerDetector } from './schema/trigger';

/**
 * base/head 2 版のモデルを比べ、どの実行トリガーに当たる変更かを判定する純粋関数。
 *
 * マッチングは**レイヤー内で要素 id が同じもの**を同一要素とみなす（id は図の内部キーで
 * 不変。ElementalID の採番 `seq` は表示用で、ここでは照合に使わない）。
 */

/** 1 件の根拠。対象要素の表示ラベル（ElementalID ＋名前）は `threatReport.ts` / `sarif.ts` と同じ形。 */
export interface TriggerEvidence {
  layer: LayerKey;
  kind: TriggerDetector['kind'];
  element: { kind: ElementKind; id: string; label: string };
  /** `*-changed` 系検出器のみ：差があったフィールド名（カンマ区切り）、または信頼レベルの変化。 */
  detail?: string;
}

export interface TriggerHit {
  triggerId: string;
  title: string;
  checkpoint: string;
  evidence: TriggerEvidence[];
}

function nodeLabel(n: DiagramNode): string {
  const id = n.seq != null ? formatElementalId('node', n.seq) : n.id;
  return `${id} ${n.label?.trim() || n.type}`;
}

function edgeLabel(e: DiagramEdge): string {
  const id = e.seq != null ? formatElementalId('edge', e.seq) : e.id;
  const name = e.dataFlowName?.trim();
  return name ? `${id} ${name}` : id;
}

function boundaryLabel(b: DiagramBoundary): string {
  const id = b.seq != null ? formatElementalId('boundary', b.seq) : b.id;
  return `${id} ${b.vlanName?.trim() || b.blastRadiusLabel?.trim() || b.type}`;
}

/** 任意オブジェクトから `any` を使わずフィールド値を取り出す。 */
function fieldValue(obj: object, field: string): unknown {
  return (obj as Record<string, unknown>)[field];
}

/** 深い比較（構造が変われば異なるとみなす）。配列・オブジェクトの両方に対応する。 */
function fieldsDiffer(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) !== JSON.stringify(b);
}

/**
 * ノードが型／カテゴリフィルタに一致するか。`nodeTypes` と `categories` は OR
 * （どちらか一方に一致すれば成立）。両方未指定ならフィルタ無し＝常に成立。
 */
function nodeMatchesFilter(
  node: DiagramNode,
  nodeTypes: readonly string[] | undefined,
  categories: readonly string[] | undefined,
): boolean {
  if (!nodeTypes && !categories) return true;
  if (nodeTypes?.includes(node.type)) return true;
  if (categories) {
    const category = componentRegistry.get(node.type)?.category;
    if (category !== undefined && categories.includes(category)) return true;
  }
  return false;
}

function changedFieldNames(
  before: object,
  after: object,
  fields: readonly string[],
): string[] {
  return fields.filter((f) => fieldsDiffer(fieldValue(before, f), fieldValue(after, f)));
}

/**
 * レイヤー 1 枚分の base/head を 1 個の検出器に通し、根拠（evidence）を追記する。
 * 複数レイヤー・複数検出器をまとめて 1 つの evidence 配列へ積む呼び出し元から使う。
 */
function runDetector(
  layer: LayerKey,
  base: LayerData,
  head: LayerData,
  detector: TriggerDetector,
  out: TriggerEvidence[],
): void {
  switch (detector.kind) {
    case 'node-added': {
      const baseIds = new Set(base.nodes.map((n) => n.id));
      for (const n of head.nodes) {
        if (baseIds.has(n.id)) continue;
        if (!nodeMatchesFilter(n, detector.nodeTypes, detector.categories)) continue;
        out.push({
          layer,
          kind: detector.kind,
          element: { kind: 'node', id: n.id, label: nodeLabel(n) },
        });
      }
      break;
    }
    case 'node-changed': {
      const baseById = new Map(base.nodes.map((n) => [n.id, n] as const));
      for (const n of head.nodes) {
        const prev = baseById.get(n.id);
        if (!prev) continue;
        if (!nodeMatchesFilter(n, detector.nodeTypes, detector.categories)) continue;
        const changed = changedFieldNames(prev, n, detector.fields);
        if (changed.length === 0) continue;
        out.push({
          layer,
          kind: detector.kind,
          element: { kind: 'node', id: n.id, label: nodeLabel(n) },
          detail: changed.join(', '),
        });
      }
      break;
    }
    case 'edge-added': {
      const baseIds = new Set(base.edges.map((e) => e.id));
      // crossesTrust / peerTrust は head 時点の信頼レベルで判定する（新設エッジの評価対象は現状）。
      const trust = resolveNodeTrust(head.nodes, head.boundaries);
      for (const e of head.edges) {
        if (baseIds.has(e.id)) continue;
        const semantic = e.semantic ?? 'data_flow';
        if (detector.semantic && !detector.semantic.includes(semantic)) continue;
        const sourceTrust = trust.get(e.source);
        const targetTrust = trust.get(e.target);
        if (detector.crossesTrust && !(sourceTrust && targetTrust && sourceTrust !== targetTrust)) {
          continue;
        }
        if (detector.peerTrust) {
          const matches =
            (sourceTrust !== undefined && detector.peerTrust.includes(sourceTrust)) ||
            (targetTrust !== undefined && detector.peerTrust.includes(targetTrust));
          if (!matches) continue;
        }
        out.push({
          layer,
          kind: detector.kind,
          element: { kind: 'edge', id: e.id, label: edgeLabel(e) },
        });
      }
      break;
    }
    case 'edge-changed': {
      const baseById = new Map(base.edges.map((e) => [e.id, e] as const));
      for (const e of head.edges) {
        const prev = baseById.get(e.id);
        if (!prev) continue;
        const changed = changedFieldNames(prev, e, detector.fields);
        if (changed.length === 0) continue;
        out.push({
          layer,
          kind: detector.kind,
          element: { kind: 'edge', id: e.id, label: edgeLabel(e) },
          detail: changed.join(', '),
        });
      }
      break;
    }
    case 'node-trust-changed': {
      const baseTrust = resolveNodeTrust(base.nodes, base.boundaries);
      const headTrust = resolveNodeTrust(head.nodes, head.boundaries);
      for (const n of head.nodes) {
        const before = baseTrust.get(n.id);
        const after = headTrust.get(n.id);
        if (before === undefined || after === undefined || before === after) continue;
        out.push({
          layer,
          kind: detector.kind,
          element: { kind: 'node', id: n.id, label: nodeLabel(n) },
          detail: `${before} → ${after}`,
        });
      }
      break;
    }
    case 'boundary-added': {
      const baseIds = new Set(base.boundaries.map((b) => b.id));
      for (const b of head.boundaries) {
        if (baseIds.has(b.id)) continue;
        out.push({
          layer,
          kind: detector.kind,
          element: { kind: 'boundary', id: b.id, label: boundaryLabel(b) },
        });
      }
      break;
    }
    case 'boundary-changed': {
      const baseById = new Map(base.boundaries.map((b) => [b.id, b] as const));
      for (const b of head.boundaries) {
        const prev = baseById.get(b.id);
        if (!prev) continue;
        const changed = changedFieldNames(prev, b, detector.fields);
        if (changed.length === 0) continue;
        out.push({
          layer,
          kind: detector.kind,
          element: { kind: 'boundary', id: b.id, label: boundaryLabel(b) },
          detail: changed.join(', '),
        });
      }
      break;
    }
  }
}

/**
 * base/head（レイヤー別）を全トリガーの検出器に通し、根拠が 1 件以上あるトリガーだけを返す。
 */
export function detectTriggers(
  base: Record<LayerKey, LayerData>,
  head: Record<LayerKey, LayerData>,
  triggers: readonly ChangeTrigger[],
): TriggerHit[] {
  const hits: TriggerHit[] = [];
  for (const trigger of triggers) {
    const evidence: TriggerEvidence[] = [];
    for (const layer of LAYER_KEYS) {
      for (const detector of trigger.detect) {
        runDetector(layer, base[layer], head[layer], detector, evidence);
      }
    }
    if (evidence.length > 0) {
      hits.push({ triggerId: trigger.id, title: trigger.title, checkpoint: trigger.checkpoint, evidence });
    }
  }
  return hits;
}

/**
 * モデル差分だけでは自動判定できないトリガー（`detect: []`）。T4 が該当する。
 * これらは差分の有無に関わらず常に「PR レビューで確認」として提示する。
 */
export function manualCheckTriggers(triggers: readonly ChangeTrigger[]): ChangeTrigger[] {
  return triggers.filter((t) => t.detect.length === 0);
}
