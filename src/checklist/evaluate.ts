import { formatElementalId } from '../core/model/elementalId';
import { getNodeDisplayName } from '../core/model/nodeDisplay';
import type { DiagramNode, ThreatView } from '../core/model/types';
import type { Checklist, ChecklistGroup, ChecklistItem } from './schema';

/**
 * 注意喚起チェックリストの判定（純粋関数）。規則は docs/posture-checklist.md §6.2。
 * 判定は構成図と検出結果に基づく。実機の点検の代わりではない。
 */

export type ItemStatus = 'notApplicable' | 'action' | 'unfilled' | 'accepted' | 'ok';

/** 画面の並び順・集計の順序。 */
export const ITEM_STATUSES: readonly ItemStatus[] = ['action', 'unfilled', 'accepted', 'ok', 'notApplicable'];

export interface RelatedNode {
  /** `DiagramNode.id`（キャンバスの選択に使う）。 */
  id: string;
  /** `C3 名前`。採番が無ければ名前のみ。 */
  label: string;
}

/** 確認が必要な脅威（要対応か未入力の検出）。 */
export interface CheckThreat {
  /** `ThreatView.id`（脅威カードの特定に使う）。 */
  threatId: string;
  /** 脅威名（未設定ならカテゴリ）。 */
  name: string;
  node: RelatedNode;
  kind: 'action' | 'unfilled';
}

export interface ItemResult {
  item: ChecklistItem;
  status: ItemStatus;
  /** 関係ノード（検出の対象。重複なし）。 */
  nodes: RelatedNode[];
  /** 確認が必要なノード（要対応か未入力の検出があるノード。重複なし）。 */
  checkNodes: RelatedNode[];
  /** 確認が必要な脅威（検出順）。 */
  checkThreats: CheckThreat[];
  /** 図にある `targetTypes` のノード数。 */
  targetNodeCount: number;
  /** 検出件数の内訳（誤検知・対策不要は含めない）。 */
  counts: { action: number; unfilled: number; accepted: number; implemented: number };
}

export interface GroupResult {
  group: ChecklistGroup;
  items: ItemResult[];
}

export type StaleReason = 'unrecorded' | 'stale';

export interface StaleNode {
  node: RelatedNode;
  reason: StaleReason;
  /** 最終点検日（reason が stale のとき）。 */
  lastReviewedAt?: string;
  /** asOf からの経過日数（reason が stale のとき）。 */
  daysSince?: number;
}

export interface ChecklistResult {
  checklist: Checklist['checklist'];
  /** 基準日（YYYY-MM-DD）。 */
  asOf: string;
  groups: GroupResult[];
  summary: Record<ItemStatus, number>;
  staleNodes: StaleNode[];
}

export interface EvaluateChecklistInput {
  checklist: Checklist;
  /** 判定対象のレイヤーのノード。 */
  nodes: readonly DiagramNode[];
  /** 同じレイヤーの脅威ビュー（抑制・リスク受容の記録を含む）。 */
  threats: readonly ThreatView[];
  /** 点検が古いかの基準日。 */
  asOf: Date | string;
}

const DAY_MS = 86_400_000;
const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** `YYYY-MM-DD` を UTC 0 時の epoch ms にする。実在しない日付・形式違いは undefined。 */
function parseDay(value: string): number | undefined {
  const m = DATE_RE.exec(value);
  if (!m) return undefined;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const ms = Date.UTC(y, mo - 1, d);
  const back = new Date(ms);
  return back.getUTCFullYear() === y && back.getUTCMonth() === mo - 1 && back.getUTCDate() === d ? ms : undefined;
}

/** 基準日を `YYYY-MM-DD` にする。Date は UTC 日付で見る（`toISOString` と同じ）。 */
export function formatDay(asOf: Date | string): string {
  return typeof asOf === 'string' ? asOf : asOf.toISOString().slice(0, 10);
}

/** 脅威がルールに対応するか。畳み込み（canonicalId）された脅威は元の検出 id（`{ruleId}-{subjectId}`）でも照合する。 */
function matchesRule(t: ThreatView, ruleId: string): boolean {
  if (t.ruleId === ruleId) return true;
  return t.corroboration?.ruleIds.some((id) => id.startsWith(`${ruleId}-`)) ?? false;
}

function relatedNode(n: DiagramNode): RelatedNode {
  const name = getNodeDisplayName(n);
  return { id: n.id, label: n.seq !== undefined ? `${formatElementalId('node', n.seq)} ${name}` : name };
}

export function evaluateChecklist(input: EvaluateChecklistInput): ChecklistResult {
  const { checklist, nodes, threats } = input;
  const asOf = formatDay(input.asOf);
  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  const detected = threats.filter((t) => t.origin === 'detected');

  const evaluateItem = (item: ChecklistItem): ItemResult => {
    const types = new Set(item.targetTypes);
    const targetNodeCount = nodes.filter((n) => types.has(n.type)).length;
    const counts = { action: 0, unfilled: 0, accepted: 0, implemented: 0 };
    const nodeIds: string[] = [];
    const checkNodeIds: string[] = [];
    const checkThreats: CheckThreat[] = [];
    for (const t of detected) {
      if (!item.ruleIds.some((r) => matchesRule(t, r))) continue;
      if (t.suppression?.status === 'false-positive') continue; // 誤検知は除外
      if (t.controlStatus?.status === 'not-applicable') continue; // 対策不要も除外
      if (t.suppression?.status === 'accepted') counts.accepted++;
      else if (t.controlStatus?.status === 'implemented') counts.implemented++;
      else {
        const kind = t.assumptionFlags?.some((f) => f === 'attackSurface' || f === 'posture') ? 'unfilled' : 'action';
        counts[kind]++;
        if (!checkNodeIds.includes(t.nodeId)) checkNodeIds.push(t.nodeId);
        const n = nodeById.get(t.nodeId);
        if (n) checkThreats.push({ threatId: t.id, name: t.name ?? t.category, node: relatedNode(n), kind });
      }
      if (!nodeIds.includes(t.nodeId)) nodeIds.push(t.nodeId);
    }
    const toRelated = (ids: string[]) =>
      ids.flatMap((id) => {
        const n = nodeById.get(id);
        return n ? [relatedNode(n)] : [];
      });
    const related = toRelated(nodeIds);
    let status: ItemStatus;
    if (counts.action + counts.unfilled + counts.accepted + counts.implemented === 0 && targetNodeCount === 0) status = 'notApplicable';
    else if (counts.action > 0) status = 'action';
    else if (counts.unfilled > 0) status = 'unfilled';
    else if (counts.accepted > 0) status = 'accepted';
    else status = 'ok';
    return { item, status, nodes: related, checkNodes: toRelated(checkNodeIds), checkThreats, targetNodeCount, counts };
  };

  const groups: GroupResult[] = checklist.groups.map((group) => ({
    group,
    items: group.items.map(evaluateItem),
  }));

  const summary: Record<ItemStatus, number> = { action: 0, unfilled: 0, accepted: 0, ok: 0, notApplicable: 0 };
  for (const g of groups) for (const r of g.items) summary[r.status]++;

  // 点検が古い・未記録のノード：チェックリストの対象の型のノードのみ。
  const allTypes = new Set(checklist.groups.flatMap((g) => g.items.flatMap((i) => i.targetTypes)));
  const asOfMs = parseDay(asOf);
  const staleNodes: StaleNode[] = [];
  for (const n of nodes) {
    if (!allTypes.has(n.type)) continue;
    const last = n.posture?.lastReviewedAt;
    const lastMs = last ? parseDay(last) : undefined;
    if (last === undefined || lastMs === undefined) {
      staleNodes.push({ node: relatedNode(n), reason: 'unrecorded' });
      continue;
    }
    if (asOfMs === undefined) continue;
    const days = Math.floor((asOfMs - lastMs) / DAY_MS);
    if (days > checklist.checklist.staleDays) {
      staleNodes.push({ node: relatedNode(n), reason: 'stale', lastReviewedAt: last, daysSince: days });
    }
  }

  return { checklist: checklist.checklist, asOf, groups, summary, staleNodes };
}
