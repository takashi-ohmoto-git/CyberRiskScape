/**
 * どの脅威にも結びついていない人の判断（リスク対応方針・リスク評価・対策実装状況）を拾う。
 *
 * 判断は脅威カードの id をキーに、プロジェクト全体で 1 つの記録として保存している。脅威は図と
 * ルールから毎回導出するので、部品を消した・属性を入力して脅威が出なくなった・ルールが無くなった
 * ときに、判断だけが保存データに残る。ここではそれを拾って理由を付ける（消しはしない。人の判断を
 * 機械が捨てない）。設計は docs/common-data-model.md §7.2 B、id の形は docs/identifiers.md。
 *
 * 表示中のレイヤー・フレームワークに左右されないよう、全レイヤー・全フレームワークで脅威を
 * 導出して突き合わせる。
 */
import { buildThreatViews } from './buildThreatViews';
import { detectThreats } from './detectThreats';
import type {
  ControlStatusState,
  LayerData,
  ManualThreat,
  RiskScore,
  SuppressionState,
} from '../model/types';
import type { ThreatRule } from '../../threat-library/schema/threatRule';

/**
 * 外れた理由。
 * - `element-removed`：部品（ノード・線・境界）がどのレイヤーにも無い
 * - `source-removed`：元のルール・分類・手動脅威が見つからない（無効にしたカスタムルールを含む）
 * - `not-detected`：部品もルールもあるが、今の図では脅威として出ていない（属性の入力で条件から外れた等）
 */
export type OrphanReason = 'element-removed' | 'source-removed' | 'not-detected';

export interface OrphanedJudgement {
  /** 保存データ上のキー（脅威カードの id。旧形式を含む）。 */
  key: string;
  reason: OrphanReason;
  suppression?: SuppressionState;
  risk?: RiskScore;
  controlStatus?: ControlStatusState;
}

export interface FindOrphanedJudgementsInput {
  /** 全レイヤー。 */
  layers: readonly Pick<LayerData, 'nodes' | 'edges' | 'boundaries'>[];
  /** 全レイヤーの手動脅威（`layers` と同じ並び）。 */
  manualThreats: readonly (readonly ManualThreat[])[];
  /** 評価に使うルール（同梱＋有効なカスタムルール）。 */
  rules: ThreatRule[];
  suppressions?: Record<string, SuppressionState>;
  riskScores?: Record<string, RiskScore>;
  controlStatuses?: Record<string, ControlStatusState>;
}

/** `分類 ID::kind:部品 ID` の形なら、元（分類 ID）と部品 ID に分ける。 */
function splitCanonicalKey(key: string): { source: string; elementId: string } | undefined {
  const sep = key.indexOf('::');
  if (sep < 0) return undefined;
  const kindEnd = key.indexOf(':', sep + 2);
  if (kindEnd < 0) return undefined;
  return { source: key.slice(0, sep), elementId: key.slice(kindEnd + 1) };
}

function reasonOf(
  key: string,
  elementIds: ReadonlySet<string>,
  sourceIds: ReadonlySet<string>,
): OrphanReason {
  const canonical = splitCanonicalKey(key);
  if (canonical) {
    if (!elementIds.has(canonical.elementId)) return 'element-removed';
    return sourceIds.has(canonical.source) ? 'not-detected' : 'source-removed';
  }
  // `元の id-部品 ID`（旧形式・カスタムルール・型指定の手動脅威）か、`元の id` だけ（手動脅威）。
  // どちらの id もハイフンを含み得るので、いま在る部品 ID・元の id との前後一致で分ける。
  if (sourceIds.has(key)) return 'not-detected';
  for (const elementId of elementIds) {
    if (!key.endsWith(`-${elementId}`)) continue;
    const source = key.slice(0, key.length - elementId.length - 1);
    return sourceIds.has(source) ? 'not-detected' : 'source-removed';
  }
  for (const source of sourceIds) {
    if (key.startsWith(`${source}-`)) return 'element-removed';
  }
  return 'source-removed';
}

export function findOrphanedJudgements({
  layers,
  manualThreats,
  rules,
  suppressions = {},
  riskScores = {},
  controlStatuses = {},
}: FindOrphanedJudgementsInput): OrphanedJudgement[] {
  const keys = new Set([
    ...Object.keys(suppressions),
    ...Object.keys(riskScores),
    ...Object.keys(controlStatuses),
  ]);
  if (keys.size === 0) return [];

  const attached = new Set<string>();
  const elementIds = new Set<string>();
  const sourceIds = new Set<string>();
  for (const r of rules) {
    sourceIds.add(r.id);
    if (r.canonicalId) sourceIds.add(r.canonicalId);
  }
  layers.forEach((layer, i) => {
    const manual = manualThreats[i] ?? [];
    for (const m of manual) sourceIds.add(m.id);
    for (const e of [...layer.nodes, ...layer.edges, ...layer.boundaries]) elementIds.add(e.id);
    const views = buildThreatViews({
      detected: detectThreats({
        nodes: layer.nodes,
        edges: layer.edges,
        framework: 'ALL',
        rules,
        boundaries: layer.boundaries,
      }),
      manualThreats: [...manual],
      nodes: layer.nodes,
      framework: 'ALL',
      suppressions: {},
    });
    for (const v of views) {
      attached.add(v.id);
      for (const id of v.legacyIds ?? []) attached.add(id);
    }
  });

  const out: OrphanedJudgement[] = [];
  for (const key of keys) {
    if (attached.has(key)) continue;
    out.push({
      key,
      reason: reasonOf(key, elementIds, sourceIds),
      ...(key in suppressions ? { suppression: suppressions[key] } : {}),
      ...(key in riskScores ? { risk: riskScores[key] } : {}),
      ...(key in controlStatuses ? { controlStatus: controlStatuses[key] } : {}),
    });
  }
  return out;
}
