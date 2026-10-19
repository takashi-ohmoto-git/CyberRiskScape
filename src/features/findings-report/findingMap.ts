import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

/**
 * 指摘の CWE → 脅威ライブラリの canonicalId の対応表（`data/finding-maps/cwe.yaml`）。
 * 脅威知識はコードに置かず YAML に置く。
 */

const FindingMapSchema = z.object({
  schemaVersion: z.literal(1),
  mappings: z.array(
    z.object({
      cwe: z.array(z.number().int().positive()).nonempty(),
      canonicalIds: z.array(z.string().min(1)).nonempty(),
      note: z.string().optional(),
    }),
  ),
});

export type FindingMapping = z.infer<typeof FindingMapSchema>['mappings'][number];

export function loadFindingMap(text: string): FindingMapping[] {
  const mappings = FindingMapSchema.parse(parseYaml(text)).mappings;
  const seen = new Set<number>();
  for (const m of mappings) {
    for (const c of m.cwe) {
      if (seen.has(c)) throw new Error(`[finding-map] CWE-${c} が複数の mapping に載っています`);
      seen.add(c);
    }
  }
  return mappings;
}

/** CWE 番号 → canonicalId 一覧。載っていない CWE は undefined。 */
export function cweToCanonicalIds(mappings: readonly FindingMapping[], cwe: number): readonly string[] | undefined {
  return mappings.find((m) => m.cwe.includes(cwe))?.canonicalIds;
}

// ── 同梱データ（Vite の import.meta.glob で raw 文字列として取り込む。CLI ビルド・Vitest でも動く）──

const sources = import.meta.glob<string>('../../../data/finding-maps/cwe.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const BUNDLED_FINDING_MAP: FindingMapping[] = loadFindingMap(
  Object.values(sources)[0] ?? 'schemaVersion: 1\nmappings: []\n',
);
