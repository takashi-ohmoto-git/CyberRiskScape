import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { EDGE_PROTOCOLS } from '../../core/model/types';

/**
 * TMT の型 → CyberRiskScape の型の対応表（`data/import-maps/tm7.yaml`）を読む。
 * 型の知識はコードに置かず YAML に置く。
 */

const NodeTarget = z.string().regex(/^[A-Z][A-Za-z0-9_]*$/);
const EdgeTarget = z.object({
  protocol: z.enum(EDGE_PROTOCOLS).optional(),
  encryption: z.enum(['Plain', 'TLS', 'E2EE']).optional(),
});
const BoundaryTarget = z.object({
  type: z.enum(['RECT', 'RECT_DASHED', 'ROUNDED', 'ROUNDED_DASHED']),
  trustLevel: z.enum(['Internal', 'Partner', 'Internet']).optional(),
  macroTrust: z.enum(['Public Area', 'Office Area', 'Security Zone']).optional(),
});

const TargetSchema = z.object({
  node: NodeTarget.optional(),
  edge: EdgeTarget.optional(),
  boundary: BoundaryTarget.optional(),
  lineBoundary: z.literal(true).optional(),
});

const Tm7MapSchema = z.object({
  schemaVersion: z.literal(1),
  generic: z.record(z.string().min(1), TargetSchema),
  types: z.array(TargetSchema.extend({ typeId: z.string().min(1), note: z.string().optional() })),
});

export type Tm7Target = z.infer<typeof TargetSchema>;

export interface Tm7Map {
  generic: Record<string, Tm7Target>;
  types: Map<string, Tm7Target>;
}

export function loadTm7Map(text: string): Tm7Map {
  const parsed = Tm7MapSchema.parse(parseYaml(text));
  const types = new Map<string, Tm7Target>();
  for (const t of parsed.types) {
    if (types.has(t.typeId)) throw new Error(`[tm7-map] typeId ${t.typeId} が重複しています`);
    types.set(t.typeId, t);
  }
  return { generic: parsed.generic, types };
}

/**
 * 型を引く。TypeId が表にあればそれ、無ければ親の汎用型（GenericTypeId）。
 * `exact` は TypeId で一致したか（汎用型に落ちたら「型を確認」の印を付ける）。
 */
export function resolveTm7Target(
  map: Tm7Map,
  typeId: string,
  genericTypeId: string,
): { target: Tm7Target; exact: boolean } | undefined {
  const t = map.types.get(typeId);
  if (t) return { target: t, exact: true };
  const g = map.generic[genericTypeId];
  return g ? { target: g, exact: false } : undefined;
}

// ── 同梱データ（Vite の import.meta.glob で raw 文字列として取り込む。CLI ビルド・Vitest でも動く）──

const sources = import.meta.glob<string>('../../../data/import-maps/tm7.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const BUNDLED_TM7_MAP: Tm7Map = loadTm7Map(
  Object.values(sources)[0] ?? 'schemaVersion: 1\ngeneric: {}\ntypes: []\n',
);
