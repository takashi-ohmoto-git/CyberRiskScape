import { EMPTY_LAYER, type LayerData } from '../../core/model/types';
import { serializeProject } from '../persistence/serialize';
import type { PersistedProject } from '../persistence/schema';

/**
 * 取り込んだ 1 レイヤー分の図を、L1 に置いたプロジェクト（保存形式）にする。CLI 用。
 * ElementalID の連番（`seq`）はここで 1 から振る（UI ではテンプレート取り込みが振る）。
 */
export function layerToProject(layer: LayerData): PersistedProject {
  const number = <T extends object>(items: T[]) => items.map((item, i) => ({ ...item, seq: i + 1 }));
  return serializeProject({
    layers: {
      L0: EMPTY_LAYER,
      L1: {
        nodes: number(layer.nodes),
        edges: number(layer.edges),
        boundaries: number(layer.boundaries),
        annotations: [],
      },
      L2: EMPTY_LAYER,
      L3: EMPTY_LAYER,
      PQC: EMPTY_LAYER,
    },
    activeLayer: 'L1',
    activeFramework: 'ALL',
    idCounters: {
      L0: { node: 0, edge: 0, boundary: 0 },
      L1: { node: layer.nodes.length, edge: layer.edges.length, boundary: layer.boundaries.length },
      L2: { node: 0, edge: 0, boundary: 0 },
      L3: { node: 0, edge: 0, boundary: 0 },
      PQC: { node: 0, edge: 0, boundary: 0 },
    },
  });
}
