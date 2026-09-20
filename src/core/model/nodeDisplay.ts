import type { DiagramNode } from './types';
import { getComponentRegistry } from '../../component-library/defaultRegistry';
import { getLocale } from '../../i18n';

/**
 * ノードの表示名を取得する。
 * カスタムラベルがあればそれを優先し、無ければ型 ID 由来のラベルにフォールバックする。
 * 型が未登録（ライブラリ削除後の旧ダイアグラム等）の場合は型 ID をそのまま表示する。
 *
 * 型ラベルは現在の locale で解決する。引数で locale を受け取らないのは、この関数が
 * 描画・脅威エンジン・エクスポートから広く呼ばれ、公開シグネチャを変えると波及が
 * 大きいため（i18n 非対応の純関数に `getLocale()` を使う既存方針と同じ）。
 * 呼び出し側の React コンポーネントは `useT` / `useLocale` 経由で locale を購読済みで、
 * 言語切替時に再レンダーされる。
 */
export function getNodeDisplayName(node: DiagramNode): string {
  const trimmed = node.label?.trim();
  if (trimmed && trimmed.length > 0) return trimmed;
  return getComponentRegistry(getLocale()).get(node.type)?.label ?? node.type;
}
