import type {
  ComponentTypeId,
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  Severity,
  ThreatView,
} from '../../core/model/types';
import {
  ATTACK_OBJECTIVE_APPLICABLE,
  ATTACK_SURFACE_APPLICABLE,
  ATTACK_SURFACE_KEYS_BY_TYPE,
  isSuppressed,
  type AttackSurfaceKey,
} from '../../core/model/types';
import { resolveNodeBoundaries } from '../../core/canvas/boundaryCrossing';

/**
 * 侵入ポイントの分析（Search Attack Graph）を使える攻撃者の型。
 * 「外から見える資産を起点に探索する」前提の判定なので、まず AI エージェント攻撃者に限る。
 * 脅威アクター・内部不正者は今後（docs/plan.md §2.92）。
 */
export const ENTRY_SEARCH_APPLICABLE: ReadonlySet<ComponentTypeId> = new Set(['AGENTIC_ATTACKER']);

/** 型 type で攻撃面属性の項目 key を入力できるか（入力できない項目は弱点にも仮定にも数えない）。 */
function acceptsSurfaceKey(type: ComponentTypeId, key: AttackSurfaceKey): boolean {
  if (!ATTACK_SURFACE_APPLICABLE.has(type)) return false;
  const keys = ATTACK_SURFACE_KEYS_BY_TYPE[type];
  return !keys || keys.includes(key);
}

/** 入口の候補にしない型（攻撃する側・利用者の端末・図の外の主体）。端末は下の例外のときだけ候補にする。 */
const NON_ENTRY_TYPES: ReadonlySet<ComponentTypeId> = new Set([
  'USER',
  'PC',
  'SMARTPHONE',
  'EXTERNAL_ENTITY',
]);

/** 利用者の端末の型。侵害されて踏み台にされる外部の端末として、条件つきで候補にする。 */
const ENDPOINT_TYPES: ReadonlySet<ComponentTypeId> = new Set(['USER', 'PC', 'SMARTPHONE']);

/** 遠隔接続の装置の型。外部の端末からここへ線があれば、その端末の侵害（資格情報の窃取）が入口になる。 */
const REMOTE_ACCESS_TYPES: ReadonlySet<ComponentTypeId> = new Set(['VPN_GATEWAY', 'ZTNA_PROXY', 'BASTION', 'ADMIN_CONSOLE']);

/** 入口とみなした理由。 */
export type EntryReason =
  /** 公開サーバー型で Global IP あり（未入力は「あり」と仮定）。 */
  | 'publicSurface'
  /** インターネット経由のエッジで外から受ける。 */
  | 'internetEdge'
  /** インターネット境界の中にある。 */
  | 'internetZone'
  /** 攻撃者から線が引かれている。 */
  | 'attackerEdge'
  /** 外部の端末で、遠隔接続の装置へ線がある（端末の侵害で正規の接続を使われる）。 */
  | 'externalEndpoint';

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
 * - 攻撃面属性で Global IP を入力できる型（公開サーバー・バックエンド API・MCP サーバー等）で Global IP あり
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
  const threatSummary = (nodeId: string): Pick<EntryCandidate, 'threatCount' | 'maxSeverity'> => {
    const childIds = new Set(nodes.filter((c) => c.parentId === nodeId).map((c) => c.id));
    const active = threats.filter((t) => !isSuppressed(t) && (t.nodeId === nodeId || childIds.has(t.nodeId)));
    const maxSeverity = active.reduce<Severity | undefined>(
      (max, t) => (!max || SEVERITY_ORDER[t.severity] > SEVERITY_ORDER[max] ? t.severity : max),
      undefined,
    );
    return { threatCount: active.length, maxSeverity };
  };

  const typeOf = new Map(nodes.map((x) => [x.id, x.type] as const));
  for (const n of nodes) {
    if (n.parentId && ids.has(n.parentId)) continue;
    if (ATTACK_OBJECTIVE_APPLICABLE.has(n.type)) continue;

    const attackerEdge = edges.some(
      (e) => (e.source === attackerId && e.target === n.id) || (e.target === attackerId && e.source === n.id),
    );
    if (NON_ENTRY_TYPES.has(n.type)) {
      // 端末は、攻撃者から線が引かれている（利用者アカウントの乗っ取り等を利用者が描いた）か、
      // インターネット側にあって遠隔接続の装置へ線がある（外部の端末の侵害）ときだけ候補にする。
      if (!ENDPOINT_TYPES.has(n.type)) continue;
      const toRemote = edges.some((e) => {
        const peer = e.source === n.id ? e.target : e.target === n.id ? e.source : undefined;
        return peer !== undefined && REMOTE_ACCESS_TYPES.has(typeOf.get(peer) as ComponentTypeId);
      });
      const external = toRemote && owning.get(n.id)?.[0]?.trustLevel === 'Internet';
      if (!attackerEdge && !external) continue;
      const reasons: EntryReason[] = [];
      if (external) reasons.push('externalEndpoint');
      if (attackerEdge) reasons.push('attackerEdge');
      candidates.push({ nodeId: n.id, reasons, weaknesses: [], assumed: false, ...threatSummary(n.id) });
      continue;
    }

    const reasons: EntryReason[] = [];
    const weaknesses: EntryWeakness[] = [];
    let assumed = false;

    if (acceptsSurfaceKey(n.type, 'hasGlobalIp')) {
      const surface = n.attackSurface ?? {};
      if (surface.hasGlobalIp !== false) {
        reasons.push('publicSurface');
        if (surface.hasGlobalIp === undefined) assumed = true;
        const weak: [AttackSurfaceKey, EntryWeakness][] = [
          ['hasUserAuthentication', 'noUserAuth'],
          ['hasSourceIpRestriction', 'noSourceIpRestriction'],
          ['hasRemoteAccessRestriction', 'noRemoteAccessRestriction'],
          ['hasWafProtection', 'noWaf'],
        ];
        for (const [key, weakness] of weak) {
          if (!acceptsSurfaceKey(n.type, key)) continue;
          const value = surface[key];
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

    if (attackerEdge) reasons.push('attackerEdge');

    if (reasons.length === 0) continue;

    candidates.push({ nodeId: n.id, reasons, weaknesses, assumed, ...threatSummary(n.id) });
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

/** 侵入候補の仮想の線の id 接頭辞。図のエッジ id とは衝突しない。 */
const ENTRY_EDGE_PREFIX = 'entry:';

export function isEntryEdgeId(edgeId: string): boolean {
  return edgeId.startsWith(ENTRY_EDGE_PREFIX);
}

/**
 * 侵入候補を、攻撃者 → 入口の仮想の線（攻撃経路分析の入力用）にする。保存はしない。
 * 攻撃者から線が引かれている入口は、図の線をそのまま使うので作らない。
 * 線そのものに脅威は無いため、経路のコストでは中立の重みになり、入口のノードの脅威で重みが付く。
 */
export function buildEntryEdges(attackerId: string, candidates: readonly EntryCandidate[]): DiagramEdge[] {
  return candidates
    .filter((c) => !c.reasons.includes('attackerEdge'))
    .map((c) => ({
      id: `${ENTRY_EDGE_PREFIX}${c.nodeId}`,
      source: attackerId,
      target: c.nodeId,
      auth: 'None',
      network: 'Internet',
      encryption: 'Plain',
    }));
}

/**
 * 侵入候補の仮想の線に、入口がインターネットから受ける線（図の線）の脅威を引き継がせる。
 * 攻撃者が入口を外から直接攻めるとき、その入口が外から受けている線の弱点（露出した境界機器の脆弱性・
 * 単独のパスワード等）を使えるため、入口の段の重み付けに使う。返すのは複製を足した一覧で、
 * `buildHopEvidence` に渡す用途に限る（脅威の件数や一覧の表示に使うと二重に数える）。
 */
export function withEntryEdgeThreats(
  threats: readonly ThreatView[],
  edges: readonly DiagramEdge[],
  entryEdges: readonly DiagramEdge[],
): ThreatView[] {
  const out = [...threats];
  for (const entry of entryEdges) {
    const inbound = new Set(
      edges.filter((e) => !isEntryEdgeId(e.id) && e.network === 'Internet' && receives(e, entry.target)).map((e) => e.id),
    );
    if (inbound.size === 0) continue;
    for (const t of threats) {
      if (t.subject?.kind === 'edge' && inbound.has(t.subject.id)) out.push({ ...t, subject: { kind: 'edge', id: entry.id } });
    }
  }
  return out;
}
