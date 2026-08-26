import type { DiagramNode } from './types';
import { componentRegistry } from '../../component-library/defaultRegistry';

/**
 * ノードの表示名を取得する。
 * カスタムラベルがあればそれを優先し、無ければ型 ID 由来のラベルにフォールバックする。
 * 型が未登録（ライブラリ削除後の旧ダイアグラム等）の場合は型 ID をそのまま表示する。
 */
export function getNodeDisplayName(node: DiagramNode): string {
  const trimmed = node.label?.trim();
  if (trimmed && trimmed.length > 0) return trimmed;
  return componentRegistry.get(node.type)?.label ?? node.type;
}
