import {
  ATTACK_SURFACE_KEYS_BY_TYPE,
  type DiagramEdge,
  type DiagramNode,
  type Finding,
  type FindingConditionKind,
  type LayerData,
} from '../../core/model/types';
import { resolveNodeTrust } from '../../core/threat-engine/resolveNodeTrust';

/**
 * 指摘の前提（conditions）・未解決の事実（openQuestions）を、図の事実と並べるための純粋関数（docs/architecture.md §8.9）。
 * 保存しない（表示・報告のたびに導く。取り込んだ事実と利用者の入力を混ぜない）。
 * 出すのは中立な事実（i18n キー＋パラメータ）だけで、「成立する／しない」の判定はしない。
 *
 * 事実のキー（表示側は `findings.securityAudit.fact.<key>` のように文言へ引く）：
 * - node.unlinked            指摘がノードに結びついていない
 * - node.notFound            結びついたノードが図に無い
 * - reachability.nodeTrust   {trust} ノードが属する信頼境界
 * - reachability.peerTrust   {trust, count} ノードへデータが入る接続の相手が属する信頼境界ごとの本数
 * - reachability.edgeNetwork {network, count} 同じ接続の経路（Internet / VPN / VPC）ごとの本数
 * - reachability.attackSurface      {name, value} 攻撃面属性（入力済み）
 * - reachability.attackSurfaceUnset {name} 攻撃面属性（未入力。脅威エンジンは悪い値として扱う）
 * - authentication.edgeAuth  {auth, count} ノードへデータが入る接続の認証ごとの本数
 * - edge.noIncoming          ノードへデータが入る接続が無い
 * - posture.value            {name, value} 運用状況（入力済み）
 * - posture.none             運用状況が 1 件も入力されていない（未入力は悪い値と同じ扱い）
 */

export type DiagramFactKey =
  | 'node.unlinked'
  | 'node.notFound'
  | 'reachability.nodeTrust'
  | 'reachability.peerTrust'
  | 'reachability.edgeNetwork'
  | 'reachability.attackSurface'
  | 'reachability.attackSurfaceUnset'
  | 'authentication.edgeAuth'
  | 'edge.noIncoming'
  | 'posture.value'
  | 'posture.none';

export interface DiagramFact {
  key: DiagramFactKey;
  params?: Record<string, string | number | boolean>;
}

export interface ConditionComparison {
  kind: FindingConditionKind;
  text: string;
  diagramFacts: DiagramFact[];
}

export interface ConditionComparisonResult {
  conditions: ConditionComparison[];
  /** 未解決の事実（出し手の文）。分類できないので図の事実は付けない（表示側で conditions の事実の横に出す）。 */
  openQuestions: ConditionComparison[];
}

/** 「到達できるか」に関わる攻撃面属性。 */
const REACHABILITY_SURFACE_KEYS = [
  'hasGlobalIp',
  'hasSourceIpRestriction',
  'hasRemoteAccessRestriction',
  'hasUserAuthentication',
  'hasWafProtection',
] as const;

/** ノードへデータが入る接続か（dataFlow：未指定は outbound＝source → target）。 */
function incomingPeer(e: DiagramEdge, nodeId: string): string | undefined {
  const flow = e.dataFlow ?? 'outbound';
  if (e.target === nodeId && flow !== 'inbound') return e.source;
  if (e.source === nodeId && flow !== 'outbound') return e.target;
  return undefined;
}

function countBy<T>(values: readonly T[]): [T, number][] {
  const m = new Map<T, number>();
  for (const v of values) m.set(v, (m.get(v) ?? 0) + 1);
  return [...m.entries()];
}

function factsFor(kind: FindingConditionKind, node: DiagramNode, layer: LayerData): DiagramFact[] {
  const incoming = layer.edges.flatMap((e) => {
    const peer = incomingPeer(e, node.id);
    return peer === undefined ? [] : [{ edge: e, peer }];
  });

  if (kind === 'reachability') {
    const trust = resolveNodeTrust(layer.nodes, layer.boundaries);
    const facts: DiagramFact[] = [{ key: 'reachability.nodeTrust', params: { trust: trust.get(node.id) ?? 'Internet' } }];
    if (incoming.length === 0) facts.push({ key: 'edge.noIncoming' });
    for (const [t, count] of countBy(incoming.map((i) => trust.get(i.peer) ?? 'Internet'))) {
      facts.push({ key: 'reachability.peerTrust', params: { trust: t, count } });
    }
    for (const [network, count] of countBy(incoming.map((i) => i.edge.network))) {
      facts.push({ key: 'reachability.edgeNetwork', params: { network, count } });
    }
    const applicable = ATTACK_SURFACE_KEYS_BY_TYPE[node.type] ?? [];
    for (const name of REACHABILITY_SURFACE_KEYS) {
      if (!(applicable as readonly string[]).includes(name)) continue;
      const value = node.attackSurface?.[name];
      facts.push(
        value === undefined
          ? { key: 'reachability.attackSurfaceUnset', params: { name } }
          : { key: 'reachability.attackSurface', params: { name, value } },
      );
    }
    return facts;
  }

  if (kind === 'authentication') {
    if (incoming.length === 0) return [{ key: 'edge.noIncoming' }];
    return countBy(incoming.map((i) => i.edge.auth)).map(([auth, count]) => ({ key: 'authentication.edgeAuth', params: { auth, count } }));
  }

  if (kind === 'authorization' || kind === 'configuration') {
    const entries = Object.entries(node.posture ?? {}).filter(([, v]) => v !== undefined);
    if (entries.length === 0) return [{ key: 'posture.none' }];
    return entries.map(([name, value]) => ({ key: 'posture.value', params: { name, value: String(value) } }));
  }

  return [];
}

export function compareConditions(finding: Finding, layer: LayerData | undefined): ConditionComparisonResult {
  const subject = finding.subject;
  const node = subject && layer ? layer.nodes.find((n) => n.id === subject.nodeId) : undefined;
  const noNode: DiagramFact[] = [{ key: subject ? 'node.notFound' : 'node.unlinked' }];
  return {
    conditions: (finding.conditions ?? []).map((c) => ({
      kind: c.kind,
      text: c.text,
      diagramFacts:
        c.kind === 'user-interaction' || c.kind === 'other' ? [] : node && layer ? factsFor(c.kind, node, layer) : noNode,
    })),
    openQuestions: (finding.openQuestions ?? []).map((text) => ({ kind: 'other', text, diagramFacts: [] })),
  };
}
