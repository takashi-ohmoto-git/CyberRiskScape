import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import type { DiagramNode, ThreatView } from '../../core/model/types';
import { isSuppressed, POSTURE_GROUP_FIELDS } from '../../core/model/types';

/**
 * 入口の高価値の面と届き得る先（docs/attack-tree-analysis.md §14）。
 *
 * 入口が受け付け・処理する「リモートコード実行・権限の上昇・データの持ち出しに届き得る」面を、
 * 脅威の canonicalId から判定する。「届き得る」にとどめ、悪用できるとは言わない。
 * どの脅威がどの面かは知識なので `data/attack-chain/entry-surfaces.yaml` に置く。
 */

/** 届き得る先。recon は次の段の材料になる情報。 */
export const ENTRY_OUTCOMES = ['rce', 'privesc', 'exfil', 'recon'] as const;
export type EntryOutcome = (typeof ENTRY_OUTCOMES)[number];

/** 運用状況の inputFeatures グループのフィールド（declaredBy に書けるもの）。 */
type InputFeatureField = (typeof POSTURE_GROUP_FIELDS.inputFeatures)[number];
const INPUT_FEATURE_FIELDS = POSTURE_GROUP_FIELDS.inputFeatures;

const EntrySurfaceFileSchema = z.object({
  schemaVersion: z.literal(1),
  surfaces: z.array(
    z.object({
      id: z.string().min(1),
      outcomes: z.array(z.enum(ENTRY_OUTCOMES)).nonempty(),
      canonicalIds: z.array(z.string().min(1)).nonempty(),
      declaredBy: z.string().min(1).optional(),
    }),
  ),
});

export interface EntrySurfaceDef {
  id: string;
  outcomes: readonly EntryOutcome[];
  canonicalIds: readonly string[];
  /** 明示が要る面：運用状況のこのフィールドが Yes のときだけ数える。 */
  declaredBy?: InputFeatureField;
}

export type EntrySurfaceTable = readonly EntrySurfaceDef[];

export function loadEntrySurfaces(text: string): EntrySurfaceTable {
  const file = EntrySurfaceFileSchema.parse(parseYaml(text));
  const seen = new Set<string>();
  return file.surfaces.map((s) => {
    if (seen.has(s.id)) throw new Error(`[entry-surfaces] 面 ${s.id} が複数回載っています`);
    seen.add(s.id);
    const dup = s.canonicalIds.find((c, i) => s.canonicalIds.indexOf(c) !== i);
    if (dup) throw new Error(`[entry-surfaces] 面 ${s.id} に ${dup} が複数回載っています`);
    if (s.declaredBy !== undefined && !(INPUT_FEATURE_FIELDS as readonly string[]).includes(s.declaredBy)) {
      throw new Error(`[entry-surfaces] 面 ${s.id} の declaredBy ${s.declaredBy} は inputFeatures のフィールドではありません`);
    }
    return {
      id: s.id,
      outcomes: s.outcomes,
      canonicalIds: s.canonicalIds,
      declaredBy: s.declaredBy as InputFeatureField | undefined,
    };
  });
}

const sources = import.meta.glob<string>('../../../data/attack-chain/entry-surfaces.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const BUNDLED_ENTRY_SURFACES: EntrySurfaceTable = loadEntrySurfaces(
  Object.values(sources)[0] ?? 'schemaVersion: 1\nsurfaces: []\n',
);

/** 入口に見つかった面と、その根拠になった脅威。 */
export interface EntrySurfaceHit {
  id: string;
  /** 根拠になった脅威の id（抑制されていないもの）。 */
  threatIds: string[];
  canonicalIds: string[];
}

export interface EntrySurfaceEvaluation {
  surfaces: EntrySurfaceHit[];
  /** 届き得る先（rce・privesc・exfil・recon の順。重複なし）。 */
  outcomes: EntryOutcome[];
}

/**
 * 入口ノード（と内包する子ノード）の、抑制されていない脅威から面を判定する純粋関数。
 * 明示が要る面は、ノードの運用状況が Yes のときだけ数える（未入力・No は数えない）。
 */
export function evaluateEntrySurfaces(
  node: DiagramNode,
  nodes: readonly DiagramNode[],
  threats: readonly ThreatView[],
  table: EntrySurfaceTable = BUNDLED_ENTRY_SURFACES,
): EntrySurfaceEvaluation {
  const childIds = new Set(nodes.filter((c) => c.parentId === node.id).map((c) => c.id));
  const active = threats.filter((t) => !isSuppressed(t) && (t.nodeId === node.id || childIds.has(t.nodeId)));
  const surfaces: EntrySurfaceHit[] = [];
  const outcomes = new Set<EntryOutcome>();
  for (const s of table) {
    if (s.declaredBy && node.posture?.[s.declaredBy] !== 'Yes') continue;
    const hits = active.filter((t) => t.canonicalId !== undefined && s.canonicalIds.includes(t.canonicalId));
    if (hits.length === 0) continue;
    surfaces.push({
      id: s.id,
      threatIds: hits.map((t) => t.id),
      canonicalIds: [...new Set(hits.map((t) => t.canonicalId as string))],
    });
    for (const o of s.outcomes) outcomes.add(o);
  }
  return { surfaces, outcomes: ENTRY_OUTCOMES.filter((o) => outcomes.has(o)) };
}
