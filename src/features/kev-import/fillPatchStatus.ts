import type { Finding, LayerKey } from '../../core/model/types';
import { LAYER_KEYS } from '../../core/model/types';
import { componentRegistry } from '../../component-library/defaultRegistry';
import type { PersistedProject } from '../persistence/schema';

/**
 * 保存済みの指摘（CVE 付き）から、運用状況 `patchStatus` の未入力を 'Missing' で埋める。
 * - 人の入力は上書きしない。'UpToDate' は書かない（指摘が無いことは更新済みの証明にならない）。
 * - 型が運用状況のグループ 'patch' を宣言していないノードには書かない。
 * - 試行のみ（outcome: 'attempted'）の指摘は根拠にしない。
 * 置き場所は KEV 照合（kev-import）と同じ「保存済みの指摘 → プロジェクト JSON」の後処理だから。
 */

export interface FilledPatchNode {
  layer: LayerKey;
  nodeId: string;
  type: string;
  label: string;
  /** 根拠にした CVE（大文字・重複なし）。 */
  cves: string[];
}

export interface FillPatchStatusResult {
  project: PersistedProject;
  filled: FilledPatchNode[];
  skipped: {
    /** patchStatus が既に入力されているノード（根拠となる指摘がある場合のみ数える）。 */
    alreadySet: number;
    /** 型が patch グループを持たないノード（根拠となる指摘がある場合のみ数える）。 */
    noPatchGroup: number;
    /** ノードに結びつかない、または存在しないノードを指す CVE 付き指摘。 */
    unboundFindings: number;
  };
}

export function fillPatchStatus(project: PersistedProject): FillPatchStatusResult {
  const findings: readonly Finding[] = project.findings ?? [];
  const cvesByNode = new Map<string, Set<string>>();
  let unboundFindings = 0;
  const existingNodeKeys = new Set<string>();
  for (const layer of LAYER_KEYS) for (const n of project.layers?.[layer]?.nodes ?? []) existingNodeKeys.add(`${layer}:${n.id}`);

  for (const f of findings) {
    if (f.outcome === 'attempted') continue;
    const cves = f.identifiers.filter((i) => i.scheme.toLowerCase() === 'cve').map((i) => i.value.trim().toUpperCase());
    if (cves.length === 0) continue;
    const key = f.subject ? `${f.subject.layer}:${f.subject.nodeId}` : null;
    if (!key || !existingNodeKeys.has(key)) {
      unboundFindings++;
      continue;
    }
    const set = cvesByNode.get(key) ?? new Set<string>();
    for (const c of cves) set.add(c);
    cvesByNode.set(key, set);
  }

  const filled: FilledPatchNode[] = [];
  const skipped = { alreadySet: 0, noPatchGroup: 0, unboundFindings };
  const layers = project.layers;
  if (!layers) return { project, filled, skipped };

  const nextLayers = { ...layers } as NonNullable<PersistedProject['layers']>;
  for (const layer of LAYER_KEYS) {
    const data = layers[layer];
    if (!data) continue;
    const nodes = data.nodes.map((n) => {
      const cves = cvesByNode.get(`${layer}:${n.id}`);
      if (!cves) return n;
      if (!componentRegistry.getPostureGroups(n.type).includes('patch')) {
        skipped.noPatchGroup++;
        return n;
      }
      if (n.posture?.patchStatus !== undefined) {
        skipped.alreadySet++;
        return n;
      }
      filled.push({ layer, nodeId: n.id, type: n.type, label: n.label?.trim() || n.type, cves: [...cves].sort() });
      return { ...n, posture: { ...n.posture, patchStatus: 'Missing' as const } };
    });
    nextLayers[layer] = { ...data, nodes };
  }
  return { project: { ...project, layers: nextLayers }, filled, skipped };
}
