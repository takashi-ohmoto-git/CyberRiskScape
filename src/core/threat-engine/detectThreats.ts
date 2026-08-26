import type {
  AttackSurfaceAttribute,
  DetectedThreat,
  DetectionAssumptionFlag,
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  FrameworkView,
  Severity,
  TrustLevel,
} from '../model/types';
import type { ThreatRule } from '../../threat-library/schema/threatRule';
import { renderEdgeTemplate, renderNodeTemplate } from './renderTemplate';
import { resolveNodeTrust } from './resolveNodeTrust';

/**
 * 脅威検出エンジン。
 *
 * 設計原則（[[architecture]] §5）：
 * - 個別の脅威知識を一切持たず、ローダーが返した `ThreatRule[]` を解釈するだけ。
 * - 評価は `appliesTo.kind` による分岐のみ（'node' / 'edge'）。コンポーネント型や
 *   エッジ属性ごとの if 文をエンジンに書かないこと。新しい条件軸が必要になった場合は
 *   スキーマ（`ThreatRuleSchema.appliesTo`）側を拡張する。
 * - severity / description の段階分けは edge ルールの `conditions`（first-match-wins）
 *   で表現する。動的説明文は `{{sourceName}}` 等のテンプレで展開する。
 */
export interface DetectThreatsInput {
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  /** アクティブなフレームワークビュー。`'ALL'` のとき framework フィルタを行わない。 */
  framework: FrameworkView;
  /** ロード済み脅威ライブラリ。App 起動時に YAML から構築する。 */
  rules: ThreatRule[];
  /**
   * 描画中の境界（任意）。指定された場合、各ノードの所属境界から trustLevel を解決し、
   * edge ルールの `sourceTrust` / `targetTrust` 軸で参照できるようにする。
   * 未指定または空配列のとき、全ノードは `'Internet'` 扱い（未所属 = Untrust）。
   */
  boundaries?: DiagramBoundary[];
}

type EdgeAppliesTo = Extract<ThreatRule['appliesTo'], { kind: 'edge' }>;
type EdgeWhenLeaf = NonNullable<EdgeAppliesTo['when']>;
type NodeAppliesTo = Extract<ThreatRule['appliesTo'], { kind: 'node' }>;
type ConnectionRequirement = NonNullable<NodeAppliesTo['connection']>;
type AttackSurfaceMatch = NonNullable<NodeAppliesTo['attackSurface']>;
type AgentAttributesMatch = NonNullable<NodeAppliesTo['agentAttributes']>;

/**
 * `agentAttributes` 未指定ノードのベースライン値（[[plan]] §2.22 1.6c）。
 * 「最悪を仮定」評価：未指定 = 最大リスク値とみなしてマッチさせる。
 * 設計者に明示宣言を促す圧力として機能する（脅威モデリングの定石）。
 */
const AGENT_ATTRIBUTES_BASELINE = {
  agency: 'Autonomous' as const,
  blastRadius: 'Admin' as const,
  identityTier: 'LabelOnly' as const,
};

/**
 * 未設定ノード用のデフォルト Attack Surface（insecure baseline）。
 * NodePanel UI の `ATTACK_SURFACE_DEFAULTS` と必ず一致させること。
 */
const ATTACK_SURFACE_DEFAULTS: Required<AttackSurfaceAttribute> = {
  hasGlobalIp: true,
  hasSourceIpRestriction: false,
  hasRemoteAccessRestriction: false,
  hasUserAuthentication: false,
  hasAccessLog: false,
  hasWafProtection: false,
  hasDdosProtection: false,
};

function resolveAttackSurface(node: DiagramNode): Required<AttackSurfaceAttribute> {
  return { ...ATTACK_SURFACE_DEFAULTS, ...node.attackSurface };
}

function matchAttackSurface(node: DiagramNode, match: AttackSurfaceMatch): boolean {
  const surface = resolveAttackSurface(node);
  for (const k of Object.keys(match) as (keyof AttackSurfaceMatch)[]) {
    const expected = match[k];
    if (expected === undefined) continue;
    if (surface[k] !== expected) return false;
  }
  return true;
}

/**
 * 攻撃面条件の評価で、ノード側の未設定フィールドを insecure baseline で埋めたか。
 * マッチ成立時のみ意味がある（不成立なら検出自体が起きない）。
 */
function usedAttackSurfaceBaseline(node: DiagramNode, match: AttackSurfaceMatch): boolean {
  const declared = node.attackSurface ?? {};
  for (const k of Object.keys(match) as (keyof AttackSurfaceMatch)[]) {
    if (match[k] === undefined) continue;
    if (declared[k] === undefined) return true;
  }
  return false;
}

/**
 * `agentAttributes` 条件のマッチ判定（[[plan]] §2.22 1.6c）。
 *
 * - 各条件フィールドは配列で OR、フィールド間は AND。
 * - ノード側で未指定の属性は `AGENT_ATTRIBUTES_BASELINE`（最悪を仮定）で評価する。
 *   これにより既存ルール（属性条件なし）の挙動は不変、明示宣言したノードはルール対象から外せる。
 */
function matchAgentAttributes(node: DiagramNode, match: AgentAttributesMatch): boolean {
  const attrs = node.agentAttributes ?? {};
  if (match.agency) {
    const value = attrs.agency ?? AGENT_ATTRIBUTES_BASELINE.agency;
    if (!match.agency.includes(value)) return false;
  }
  if (match.blastRadius) {
    const value = attrs.blastRadius ?? AGENT_ATTRIBUTES_BASELINE.blastRadius;
    if (!match.blastRadius.includes(value)) return false;
  }
  if (match.identityTier) {
    const value = attrs.identityTier ?? AGENT_ATTRIBUTES_BASELINE.identityTier;
    if (!match.identityTier.includes(value)) return false;
  }
  return true;
}

/**
 * agentAttributes 条件の評価で、ノード側の未設定属性を最悪 baseline で埋めたか。
 */
function usedAgentAttributesBaseline(node: DiagramNode, match: AgentAttributesMatch): boolean {
  const attrs = node.agentAttributes ?? {};
  if (match.agency && attrs.agency === undefined) return true;
  if (match.blastRadius && attrs.blastRadius === undefined) return true;
  if (match.identityTier && attrs.identityTier === undefined) return true;
  return false;
}

/** ノードルール評価で使われた最悪仮定フラグを収集する（マッチ成立時のみ呼ぶ）。 */
function collectNodeAssumptionFlags(
  node: DiagramNode,
  nodeApplies: NodeAppliesTo,
): DetectionAssumptionFlag[] | undefined {
  const flags: DetectionAssumptionFlag[] = [];
  if (nodeApplies.attackSurface && usedAttackSurfaceBaseline(node, nodeApplies.attackSurface)) {
    flags.push('attackSurface');
  }
  if (nodeApplies.agentAttributes && usedAgentAttributesBaseline(node, nodeApplies.agentAttributes)) {
    flags.push('agentAttributes');
  }
  return flags.length > 0 ? flags : undefined;
}

function matchEdgeWhen(
  when: EdgeWhenLeaf,
  edge: DiagramEdge,
  source: DiagramNode,
  target: DiagramNode,
  sourceTrust: TrustLevel,
  targetTrust: TrustLevel,
): boolean {
  if (when.auth && !when.auth.includes(edge.auth)) return false;
  if (when.network && !when.network.includes(edge.network)) return false;
  if (when.encryption && !when.encryption.includes(edge.encryption)) return false;
  if (when.sourceType && !when.sourceType.includes(source.type)) return false;
  if (when.targetType && !when.targetType.includes(target.type)) return false;
  if (when.sourceTrust && !when.sourceTrust.includes(sourceTrust)) return false;
  if (when.targetTrust && !when.targetTrust.includes(targetTrust)) return false;
  if (when.sourceManagedState) {
    if (!source.managedState) return false;
    if (!when.sourceManagedState.includes(source.managedState)) return false;
  }
  if (when.targetManagedState) {
    if (!target.managedState) return false;
    if (!when.targetManagedState.includes(target.managedState)) return false;
  }
  if (when.sourceUserTrust) {
    // managedState と同じ「明示宣言時のみ発火」方式。USER 以外や未宣言ノードは不成立。
    if (!source.userTrustAttribute) return false;
    if (!when.sourceUserTrust.includes(source.userTrustAttribute)) return false;
  }
  if (when.targetUserTrust) {
    if (!target.userTrustAttribute) return false;
    if (!when.targetUserTrust.includes(target.userTrustAttribute)) return false;
  }
  if (when.semantic) {
    // 未指定エッジは 'data_flow' を既定とする（§2.22 1.6d）。
    // agentAttributes のような「最悪を仮定」ではないため、`semantic: [tool_invocation]`
    // のような特化条件は明示マーク済みエッジでのみ発火する。既存ルール（semantic 条件なし）
    // の挙動は完全に保持される。
    const value = edge.semantic ?? 'data_flow';
    if (!when.semantic.includes(value)) return false;
  }
  return true;
}

/**
 * Edge ルールの `appliesTo` を評価する。`when` / `allOf` / `anyOf` のうち
 * 1 つだけが必ず設定されている（スキーマで保証）ため、それを分岐する。
 */
function matchEdgeApplies(
  applies: EdgeAppliesTo,
  edge: DiagramEdge,
  source: DiagramNode,
  target: DiagramNode,
  sourceTrust: TrustLevel,
  targetTrust: TrustLevel,
): boolean {
  if (applies.when)
    return matchEdgeWhen(applies.when, edge, source, target, sourceTrust, targetTrust);
  if (applies.allOf)
    return applies.allOf.every((w) =>
      matchEdgeWhen(w, edge, source, target, sourceTrust, targetTrust),
    );
  if (applies.anyOf)
    return applies.anyOf.some((w) =>
      matchEdgeWhen(w, edge, source, target, sourceTrust, targetTrust),
    );
  return false;
}

/**
 * Node ルールの `appliesTo` を評価する。`nodeType` 単一 or `anyOf` 複数リーフ。
 */
function matchNodeApplies(applies: NodeAppliesTo, node: DiagramNode): boolean {
  if (applies.nodeType) return node.type === applies.nodeType;
  if (applies.anyOf) return applies.anyOf.some((leaf) => leaf.nodeType === node.type);
  return false;
}

/**
 * Node ルールの接続要件を評価する。`connection` 省略時は
 * `{ required: true, direction: 'any' }` と等価。
 *
 * - `required: false`：常に成立（内在的脅威）。
 * - それ以外：`direction` / `peerType` / `peerAttackSurface` をすべて満たすエッジが
 *   少なくとも 1 本必要（同一エッジで AND 評価）。
 */
function matchNodeConnection(
  node: DiagramNode,
  edges: DiagramEdge[],
  nodeById: Map<string, DiagramNode>,
  conn: ConnectionRequirement | undefined,
): boolean {
  if (conn?.required === false) return true;
  const direction = conn?.direction ?? 'any';
  const peerType = conn?.peerType;
  const peerAttackSurface = conn?.peerAttackSurface;
  for (const edge of edges) {
    const isSource = edge.source === node.id;
    const isTarget = edge.target === node.id;
    if (!isSource && !isTarget) continue;
    if (direction === 'inbound' && !isTarget) continue;
    if (direction === 'outbound' && !isSource) continue;
    if (peerType || peerAttackSurface) {
      const peerId = isSource ? edge.target : edge.source;
      const peer = nodeById.get(peerId);
      if (!peer) continue;
      if (peerType && !peerType.includes(peer.type)) continue;
      if (peerAttackSurface && !matchAttackSurface(peer, peerAttackSurface)) continue;
    }
    return true;
  }
  return false;
}

export function detectThreats({
  nodes,
  edges,
  framework,
  rules,
  boundaries,
}: DetectThreatsInput): DetectedThreat[] {
  const threats: DetectedThreat[] = [];
  const nodeById = new Map(nodes.map((n) => [n.id, n] as const));
  const trustByNodeId = resolveNodeTrust(nodes, boundaries ?? []);

  for (const rule of rules) {
    if (framework !== 'ALL' && rule.framework !== framework) continue;

    if (rule.appliesTo.kind === 'node') {
      const nodeApplies = rule.appliesTo;
      for (const node of nodes) {
        if (!matchNodeApplies(nodeApplies, node)) continue;
        if (!matchNodeConnection(node, edges, nodeById, nodeApplies.connection)) continue;
        if (nodeApplies.attackSurface && !matchAttackSurface(node, nodeApplies.attackSurface))
          continue;
        if (nodeApplies.agentAttributes && !matchAgentAttributes(node, nodeApplies.agentAttributes))
          continue;
        threats.push({
          id: `${rule.id}-${node.id}`,
          ruleId: rule.id,
          canonicalId: rule.canonicalId,
          subject: { kind: 'node', id: node.id },
          nodeId: node.id,
          framework: rule.framework,
          category: rule.category,
          name: rule.name,
          severity: rule.severity,
          description: renderNodeTemplate(rule.description, node),
          mitigation: rule.mitigation,
          mitigationTiers: rule.mitigationTiers,
          complianceRefs: rule.complianceRefs,
          references: rule.references,
          assumptionFlags: collectNodeAssumptionFlags(node, nodeApplies),
        });
      }
      continue;
    }

    // kind === 'edge'
    const edgeApplies = rule.appliesTo;
    const { conditions } = edgeApplies;
    for (const edge of edges) {
      const sourceNode = nodeById.get(edge.source);
      const targetNode = nodeById.get(edge.target);
      if (!sourceNode || !targetNode) continue;
      const sourceTrust = trustByNodeId.get(sourceNode.id) ?? 'Internet';
      const targetTrust = trustByNodeId.get(targetNode.id) ?? 'Internet';
      if (!matchEdgeApplies(edgeApplies, edge, sourceNode, targetNode, sourceTrust, targetTrust))
        continue;

      let severity: Severity = rule.severity;
      let description: string = rule.description;
      if (conditions) {
        for (const cond of conditions) {
          if (!matchEdgeWhen(cond.when, edge, sourceNode, targetNode, sourceTrust, targetTrust))
            continue;
          if (cond.severity !== undefined) severity = cond.severity;
          if (cond.description !== undefined) description = cond.description;
          break;
        }
      }

      threats.push({
        id: `${rule.id}-${edge.id}`,
        ruleId: rule.id,
        canonicalId: rule.canonicalId,
        // 対象要素はエッジ自身（Analytics の要素単位集約用）。nodeId は
        // 既存 UI 互換のため引き続きターゲットノードを指す（[[plan]] §2.26 Step 4）。
        subject: { kind: 'edge', id: edge.id },
        nodeId: targetNode.id,
        framework: rule.framework,
        category: rule.category,
        name: rule.name,
        severity,
        description: renderEdgeTemplate(description, sourceNode, targetNode),
        mitigation: rule.mitigation,
        mitigationTiers: rule.mitigationTiers,
        complianceRefs: rule.complianceRefs,
        references: rule.references,
        isDynamic: true,
      });
    }
  }

  return threats;
}
