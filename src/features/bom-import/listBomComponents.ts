import { toIsoTimestamp } from '../../core/model/assetIdentity';
import { identifierValues, normalizeIdentifierValue } from '../../core/model/identifierSchemes';
import { isExactVersion, purlOf } from '../../core/model/purl';
import type { BomComponent, DiagramNode, LayerKey } from '../../core/model/types';

/**
 * 取り込んだ部品に、ノードの依存パッケージのインベントリを同じ形で合わせて返す（docs/architecture.md §8.8）。
 * インベントリは移行しない（環境変数など BOM でないものも入っており、同じ事実を 2 か所に保存すると食い違うため）。
 * 同じノードに同じ purl があれば、取り込んだ部品を優先する。純粋関数。
 */
export function listBomComponents(
  imported: readonly BomComponent[],
  nodes: readonly { node: Pick<DiagramNode, 'id' | 'inventory'>; layer: LayerKey }[],
): BomComponent[] {
  // purl は表記をそろえてから比べる（修飾子の有無・`pkg:type` の大文字小文字で二重に出さない）
  const key = (nodeId: string | undefined, rawPurl: string, purl = normalizeIdentifierValue('purl', rawPurl)) => `${nodeId ?? ''}\u0000${purl}`;
  const seen = new Set(
    imported.flatMap((c) => identifierValues(c.identifiers, 'purl').map((purl) => key(c.subject?.nodeId, purl))),
  );
  const derived: BomComponent[] = [];
  for (const { node, layer } of nodes) {
    const inv = node.inventory;
    if (!inv || (inv.kind !== 'npm' && inv.kind !== 'pypi')) continue;
    const observedAt = toIsoTimestamp(inv.collectedAt);
    for (const item of inv.items) {
      const exact = !!item.version && isExactVersion(item.version, item.pinned);
      const purl = purlOf(inv.kind, item.name, exact ? item.version : undefined);
      if (seen.has(key(node.id, purl))) continue;
      seen.add(key(node.id, purl));
      const externalId = `${node.id}:${purl}`;
      derived.push({
        id: `inventory:${externalId}`,
        source: { format: 'inventory', product: inv.source, importedAt: inv.collectedAt },
        externalId,
        identifiers: [{ scheme: 'purl', value: purl }],
        kind: 'software',
        sourceType: 'library',
        name: item.name,
        ...(item.version ? { version: item.version } : {}),
        subject: { layer, nodeId: node.id },
        ...(observedAt ? { observedAt } : {}),
      });
    }
  }
  return [...imported, ...derived];
}
