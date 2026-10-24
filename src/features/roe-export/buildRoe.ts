import {
  ATTACK_OBJECTIVE_APPLICABLE,
  type DiagramBoundary,
  type DiagramEdge,
  type DiagramNode,
  type LayerKey,
  type ProjectMeta,
  type ThreatView,
  type TrustLevel,
} from '../../core/model/types';
import { TRUST_BEARING_BOUNDARY_TYPES } from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import { resolveDrawableAncestor } from '../../core/model/parentChain';
import { getNodeCenter } from '../../core/canvas/nodeGeometry';
import { BRANDING } from '../../core/branding';
import { getLocale, type Locale } from '../../i18n';

/**
 * 脅威モデルから、交戦規定（RoE）／スコープ宣言の構造を作る純粋関数。
 *
 * 用途：エージェント型ペネトレーションツールを自社で運用する際、「診断してよい対象・スコープ外の対象・
 * 承認方針」を脅威モデルから書き出し、運用者がツールの遮断ルールと送信元のファイアウォール／プロキシへ
 * 写して突き合わせるための監査エビデンス。機械取り込み用の allowlist ではない（宛先は図から機械的には
 * 確定できないため、人が確認して確定する）。
 *
 * in-scope の決め方（2026-10-24 ユーザー決定・案 A）：外部・第三者を除く図内の全ノード。
 *   - 攻撃者系ノード（攻撃者・内部犯・攻撃エージェント）は対象でも対象外でもなく、どちらにも載せない。
 *   - **明示的に外部**（Internet / Partner の信頼境界に置いた、または ThirdParty 所有）→ out-of-scope。
 *   - それ以外（Internal 境界、またはどの境界にも属さない「未宣言」）→ in-scope。
 *     未宣言のノードは「ゾーン未宣言・要確認」の印を付ける（境界に入れていないだけで外部扱いにしない）。
 *   注：脅威エンジンの resolveNodeTrust は「未所属＝Internet」とするが、RoE では未所属を外部に倒さない。
 *   運用者が自社資産を診断対象から誤って外すのを防ぐため。所属は中心点包含・最内側で判定（同関数と同じ規則）。
 */

/** ゾーン表示。未宣言（どの境界にも属さない）を区別する。 */
export type RoeZone = TrustLevel | 'Undeclared';

/** buildThreatReport と同じ入力の部分集合。 */
export interface RoeInput {
  threats: ThreatView[];
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  boundaries: DiagramBoundary[];
  projectMeta: ProjectMeta;
  layer: LayerKey;
}

export interface RoeScopeEntry {
  /** 表示 ID（`C{seq}`）。seq が無ければノード id。 */
  id: string;
  /** コンポーネント型 id（JSON 消費者向け）。 */
  type: string;
  /** 表示名（label、無ければ型名）。 */
  name: string;
  /** 所属ゾーンの信頼区分（未宣言を含む）。 */
  zone: RoeZone;
  /** label / description から拾ったアドレスの手がかり（FQDN・IP・URL）。空なら手がかり無し。 */
  addressHint: string;
  /** out-of-scope の理由（ThirdParty 所有 / 外部ゾーン）。in-scope では空。 */
  reason: string;
}

export interface RoeApprovalItem {
  /** 承認方針の一文。 */
  text: string;
  /** この項目が、現在の図で発火している脅威に裏づけられているか。 */
  backed: boolean;
}

export interface RoeDocument {
  locale: Locale;
  product: string;
  system: string;
  layer: LayerKey;
  generatedAt: string;
  inScope: RoeScopeEntry[];
  outOfScope: RoeScopeEntry[];
  approvalPolicy: RoeApprovalItem[];
}

/** label + description から最初に見つかったアドレスらしき文字列を 1 つ返す（確認は人に委ねる）。 */
function addressHintOf(node: DiagramNode): string {
  const text = `${node.label ?? ''} ${node.description ?? ''}`;
  const url = text.match(/https?:\/\/[^\s)]+/i);
  if (url) return url[0];
  const ipv4 = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b/);
  if (ipv4) return ipv4[0];
  const host = text.match(/\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b/i);
  if (host) return host[0];
  return '';
}

/** ruleId の接頭辞で、承認・スコープ・自己拡張の脅威が発火しているかを判定する。 */
function hasRule(threats: ThreatView[], needle: string): boolean {
  return threats.some((t) => (t.ruleId ?? t.id).includes(needle));
}

/**
 * ノードの所属境界（信頼を担う境界のうち、中心点を含む最内側）の trustLevel を返す。
 * どの境界にも属さなければ null（＝未宣言。resolveNodeTrust と違い Internet に倒さない）。
 */
function innermostZone(node: DiagramNode, nodes: DiagramNode[], boundaries: DiagramBoundary[]): TrustLevel | null {
  const anchor = getNodeCenter(resolveDrawableAncestor(node, nodes));
  let zone: TrustLevel | null = null;
  let innerArea = Infinity;
  for (const b of boundaries) {
    if (!TRUST_BEARING_BOUNDARY_TYPES.has(b.type)) continue;
    if (anchor.x >= b.x && anchor.x <= b.x + b.width && anchor.y >= b.y && anchor.y <= b.y + b.height) {
      const area = b.width * b.height;
      if (area < innerArea) {
        zone = b.trustLevel;
        innerArea = area;
      }
    }
  }
  return zone;
}

export function buildRoe(input: RoeInput, now: Date, locale: Locale = getLocale()): RoeDocument {
  const isAttacker = (n: DiagramNode) => ATTACK_OBJECTIVE_APPLICABLE.has(n.type);

  const entry = (n: DiagramNode, zone: RoeZone, reason: string): RoeScopeEntry => ({
    id: n.seq != null ? formatElementalId('node', n.seq) : n.id,
    type: n.type,
    name: getNodeDisplayName(n),
    zone,
    addressHint: addressHintOf(n),
    reason,
  });

  const inScope: RoeScopeEntry[] = [];
  const outOfScope: RoeScopeEntry[] = [];
  for (const n of input.nodes) {
    if (isAttacker(n)) continue; // 攻撃者はスコープの対象ではない
    const declared = innermostZone(n, input.nodes, input.boundaries);
    if (n.cloudOwnership === 'ThirdParty') {
      outOfScope.push(entry(n, declared ?? 'Undeclared', 'thirdParty'));
    } else if (declared === 'Internet') {
      outOfScope.push(entry(n, 'Internet', 'internetZone'));
    } else if (declared === 'Partner') {
      outOfScope.push(entry(n, 'Partner', 'partnerZone'));
    } else if (declared === 'Internal') {
      inScope.push(entry(n, 'Internal', ''));
    } else {
      // どの境界にも属さない＝未宣言。外部に倒さず in-scope に入れ、要確認の印を付ける。
      inScope.push(entry(n, 'Undeclared', 'undeclared'));
    }
  }

  const sortByIdNum = (a: RoeScopeEntry, b: RoeScopeEntry) =>
    a.id.localeCompare(b.id, undefined, { numeric: true });
  inScope.sort(sortByIdNum);
  outOfScope.sort(sortByIdNum);

  const approvalPolicy: RoeApprovalItem[] = [
    { text: 'approval.defaultDeny', backed: hasRule(input.threats, 'tool-approval-gate-gap') },
    { text: 'approval.reviewAllTools', backed: hasRule(input.threats, 'tool-approval-gate-gap') },
    { text: 'approval.enforceScopeAtSource', backed: hasRule(input.threats, 'tool-action-scope-escape') },
    { text: 'approval.gateSelfExtension', backed: hasRule(input.threats, 'self-capability-expansion') },
    { text: 'approval.humanApprovalHighImpact', backed: hasRule(input.threats, 'tool-approval-gate-gap') },
    { text: 'approval.rulesNotDisableable', backed: hasRule(input.threats, 'tool-approval-gate-gap') },
  ];

  return {
    locale,
    product: BRANDING.name,
    system: input.projectMeta.systemName.trim() || input.projectMeta.name.trim() || BRANDING.name,
    layer: input.layer,
    generatedAt: `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`,
    inScope,
    outOfScope,
    approvalPolicy,
  };
}
