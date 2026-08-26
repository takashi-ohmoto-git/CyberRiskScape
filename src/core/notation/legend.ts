import type { BoundaryTypeId, ComponentTypeId, DiagramBoundary, DiagramEdge, DiagramNode } from '../model/types';
import { EDGE_NOTATION_LEGEND, type EdgeNotationLegendEntry } from './edgeNotation';

/**
 * 凡例モデルの組み立て（純関数）。描画から切り離してテスト可能にする。
 *
 * 方針：**そのキャンバスで実際に使われている記号だけ**を凡例化する。
 * 未使用のコンポーネント型・線記法・境界型は出さないことで、図ごとに過不足ない凡例にする
 * （engineering / compliance 双方の「レビューが速くなる」便益に直結）。
 */

/** 図中に存在する線記法エントリ（出現順は EDGE_NOTATION_LEGEND の宣言順）。 */
export function presentEdgeNotations(edges: readonly DiagramEdge[]): EdgeNotationLegendEntry[] {
  return EDGE_NOTATION_LEGEND.filter((entry) => edges.some((e) => entry.appliesTo(e)));
}

/**
 * 図中に存在するコンポーネント型を distinct 抽出する（初出順を保つ）。
 * ラベル・アイコン・カテゴリ順の解決は描画側でレジストリを引いて行う。
 */
export function presentComponentTypes(nodes: readonly DiagramNode[]): ComponentTypeId[] {
  const seen = new Set<ComponentTypeId>();
  const result: ComponentTypeId[] = [];
  for (const n of nodes) {
    if (!seen.has(n.type)) {
      seen.add(n.type);
      result.push(n.type);
    }
  }
  return result;
}

/** 図中に存在する境界型を distinct 抽出する（初出順を保つ）。 */
export function presentBoundaryTypes(boundaries: readonly DiagramBoundary[]): BoundaryTypeId[] {
  const seen = new Set<BoundaryTypeId>();
  const result: BoundaryTypeId[] = [];
  for (const b of boundaries) {
    if (!seen.has(b.type)) {
      seen.add(b.type);
      result.push(b.type);
    }
  }
  return result;
}
