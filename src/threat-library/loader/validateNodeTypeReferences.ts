import type { ThreatRule } from '../schema/threatRule';

export interface NodeTypeReference {
  ruleId: string;
  nodeType: string;
}

/**
 * 脅威ルール群が `appliesTo` で参照する全ノード型 ID を収集する。
 *
 * 対象：
 * - `appliesTo.kind === 'node'` の `nodeType` / `anyOf[].nodeType` / `connection.peerType[]`
 * - `appliesTo.kind === 'edge'` の `when` / `allOf[]` / `anyOf[]` 内の `sourceType` / `targetType`
 * - edge `conditions[].when` の `sourceType` / `targetType`
 *
 * 出力は (ruleId, nodeType) のフラットなリスト。重複は除去しない（呼び出し側の用途次第）。
 */
export function collectReferencedNodeTypes(
  rules: readonly ThreatRule[],
): NodeTypeReference[] {
  const refs: NodeTypeReference[] = [];
  for (const rule of rules) {
    const applies = rule.appliesTo;
    if (applies.kind === 'node') {
      if (applies.nodeType) refs.push({ ruleId: rule.id, nodeType: applies.nodeType });
      if (applies.anyOf) {
        for (const leaf of applies.anyOf) {
          refs.push({ ruleId: rule.id, nodeType: leaf.nodeType });
        }
      }
      if (applies.connection?.peerType) {
        for (const t of applies.connection.peerType) {
          refs.push({ ruleId: rule.id, nodeType: t });
        }
      }
    } else {
      const leaves: Array<{ sourceType?: readonly string[]; targetType?: readonly string[] }> = [];
      if (applies.when) leaves.push(applies.when);
      if (applies.allOf) leaves.push(...applies.allOf);
      if (applies.anyOf) leaves.push(...applies.anyOf);
      if (applies.conditions) {
        for (const c of applies.conditions) leaves.push(c.when);
      }
      for (const leaf of leaves) {
        if (leaf.sourceType) {
          for (const t of leaf.sourceType) refs.push({ ruleId: rule.id, nodeType: t });
        }
        if (leaf.targetType) {
          for (const t of leaf.targetType) refs.push({ ruleId: rule.id, nodeType: t });
        }
      }
    }
  }
  return refs;
}
