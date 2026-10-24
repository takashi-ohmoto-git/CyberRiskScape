import type {
  ComponentTypeId,
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  Severity,
  ThreatView,
} from '../../core/model/types';
import { ATTACK_OBJECTIVE_APPLICABLE, isSuppressed } from '../../core/model/types';
import { resolveNodeBoundaries } from '../../core/canvas/boundaryCrossing';

/**
 * 侵入ポイントの分析（Search Attack Graph）を使える攻撃者の型。
 * 「外から見える資産を起点に探索する」前提の判定なので、まず AI エージェント攻撃者に限る。
 * 脅威アクター・内部不正者は今後（docs/plan.md §2.92）。
 */
export const ENTRY_SEARCH_APPLICABLE: ReadonlySet<ComponentTypeId> = new Set(['AGENTIC_ATTACKER']);

/** 攻撃面属性（Global IP 等）で公開条件を表す型。NodePanel の攻撃面属性の表示対象と同じ（応答キャッシュのみの AI_GATEWAY を除く）。 */
const PUBLIC_SURFACE_TYPES: ReadonlySet<ComponentTypeId> = new Set([
  'FRONT_END_SERVER',
  'GATEWAY',
  'REVERSE_PROXY',
]);

/** 入口の候補にしない型（攻撃する側・利用者の端末・図の外の主体）。 */
const NON_ENTRY_TYPES: ReadonlySet<ComponentTypeId> = new Set([
  'USER',
  'PC',
  'SMARTPHONE',
  'EXTERNAL_ENTITY',
]);

/** 入口とみなした理由。 */
export type EntryReason =
  /** 公開サーバー型で Global IP あり（未入力は「あり」と仮定）。 */
  | 'publicSurface'
  /** インターネット経由のエッジで外から受ける。 */
  | 'internetEdge'
  /** インターネット境界の中にある。 */
  | 'internetZone'
  /** 攻撃者から線が引かれている。 */
  | 'attackerEdge';

/** 入口の弱点。順位付けと一覧の表示に使う。 */
export type EntryWeakness =
  | 'noUserAuth'
  | 'noSourceIpRestriction'
  | 'noRemoteAccessRestriction'
  | 'noWaf'
  | 'unauthenticatedEdge';

export interface EntryCandidate {
  nodeId: string;
  /** 1 始まりの順位。 */
  rank: number;
  reasons: EntryReason[];
  weaknesses: EntryWeakness[];
  /** 未入力の属性を悪い値として仮定した判定を含む。 */
  assumed: boolean;
  /** このノード（と内包するデータ資産）のアクティブな脅威の件数。 */
  threatCount: number;
  maxSeverity?: Severity;
}

const SEVERITY_ORDER: Record<Severity, number> = { Low: 1, Medium: 2, High: 3, Critical: 4 };

/** n がこのエッジで外から受ける側か（edge.dataFlow で判定。未設定は outbound）。 */
function receives(edge: DiagramEdge, nodeId: string): boolean {
  const flow = edge.dataFlow ?? 'outbound';
  if (edge.target === nodeId) return flow === 'outbound' || flow === 'bidirectional';
  if (edge.source === nodeId) return flow === 'inbound' || flow === 'bidirectional';
  return false;
}

/**
 * AI エージェント攻撃者から見た侵入ポイントの候補を、入りやすい順に返す純粋関数。
 *
 * 外から見える資産を探索の起点にする、というエージェント型の攻撃ツールの性質に合わせ、
 * 次のいずれかに当たるトップレベルのノードを候補にする（内包されたデータ資産は親で数える）。
 * - 公開サーバー型（FRONT_END_SERVER / GATEWAY / REVERSE_PROXY）で Global IP あり
 * - インターネット経由のエッジで外から受ける
 * - 宣言されたインターネット境界の中にある（どの境界にも属さない＝未宣言は対象外）
 * - 攻撃者から線が引かれている
 *
 * 未入力の攻撃面属性は悪い値（Global IP あり・防御策なし）として扱い、`assumed` を立てる。
 * 順位は弱点の数 → 脅威の最大重大度 → 脅威の件数 → 連番の順。
 * 攻撃者が見つからない、または対象外の型なら空配列。
 */
export function findEntryPoints(
  nodes: readonly DiagramNode[],
  edges: readonly DiagramEdge[],
  boundaries: readonly DiagramBoundary[],
  threats: readonly ThreatView[],
  attackerId: string,
): EntryCandidate[] {
  const attacker = nodes.find((n) => n.id === attackerId);
  if (!attacker || !ENTRY_SEARCH_APPLICABLE.has(attacker.type)) return [];

  const owning = resolveNodeBoundaries(nodes, boundaries);
  const ids = new Set(nodes.map((n) => n.id));
  const candidates: Omit<EntryCandidate, 'rank'>[] = [];

  for (const n of nodes) {
    if (n.parentId && ids.has(n.parentId)) continue;
    if (ATTACK_OBJECTIVE_APPLICABLE.has(n.type) || NON_ENTRY_TYPES.has(n.type)) continue;

    const reasons: EntryReason[] = [];
    const weaknesses: EntryWeakness[] = [];
    let assumed = false;

    if (PUBLIC_SURFACE_TYPES.has(n.type)) {
      const surface = n.attackSurface ?? {};
      if (surface.hasGlobalIp !== false) {
        reasons.push('publicSurface');
        if (surface.hasGlobalIp === undefined) assumed = true;
        const weak: [boolean | undefined, EntryWeakness][] = [
          [surface.hasUserAuthentication, 'noUserAuth'],
          [surface.hasSourceIpRestriction, 'noSourceIpRestriction'],
          [surface.hasRemoteAccessRestriction, 'noRemoteAccessRestriction'],
          [surface.hasWafProtection, 'noWaf'],
        ];
        for (const [value, weakness] of weak) {
          if (value === true) continue;
          weaknesses.push(weakness);
          if (value === undefined) assumed = true;
        }
      }
    }

    const internetIn = edges.filter((e) => e.network === 'Internet' && receives(e, n.id));
    if (internetIn.length > 0) {
      reasons.push('internetEdge');
      if (internetIn.some((e) => e.auth === 'None')) weaknesses.push('unauthenticatedEdge');
    }

    if (owning.get(n.id)?.[0]?.trustLevel === 'Internet') reasons.push('internetZone');

    if (edges.some((e) => (e.source === attackerId && e.target === n.id) || (e.target === attackerId && e.source === n.id))) {
      reasons.push('attackerEdge');
    }

    if (reasons.length === 0) continue;

    const childIds = new Set(nodes.filter((c) => c.parentId === n.id).map((c) => c.id));
    const active = threats.filter((t) => !isSuppressed(t) && (t.nodeId === n.id || childIds.has(t.nodeId)));
    const maxSeverity = active.reduce<Severity | undefined>(
      (max, t) => (!max || SEVERITY_ORDER[t.severity] > SEVERITY_ORDER[max] ? t.severity : max),
      undefined,
    );
    candidates.push({ nodeId: n.id, reasons, weaknesses, assumed, threatCount: active.length, maxSeverity });
  }

  const seqOf = new Map(nodes.map((n) => [n.id, n.seq ?? Number.MAX_SAFE_INTEGER]));
  candidates.sort(
    (a, b) =>
      b.weaknesses.length - a.weaknesses.length ||
      (b.maxSeverity ? SEVERITY_ORDER[b.maxSeverity] : 0) - (a.maxSeverity ? SEVERITY_ORDER[a.maxSeverity] : 0) ||
      b.threatCount - a.threatCount ||
      (seqOf.get(a.nodeId) ?? 0) - (seqOf.get(b.nodeId) ?? 0),
  );
  return candidates.map((c, i) => ({ ...c, rank: i + 1 }));
}
