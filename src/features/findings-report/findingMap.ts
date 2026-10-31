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

// ── AITech 対応表（`data/finding-maps/aitech.yaml`。Cisco AI Defense 系スキャナーの分類コード用）──

const AitechCode = z.string().regex(/^AITech-\d+\.\d+$/);
const AisubtechCode = z.string().regex(/^AISubtech-\d+\.\d+\.\d+$/);

const AitechMapSchema = z.object({
  schemaVersion: z.literal(1),
  mappings: z.array(
    z
      .object({
        aitech: z.array(AitechCode).nonempty().optional(),
        aisubtech: z.array(AisubtechCode).nonempty().optional(),
        canonicalIds: z.array(z.string().min(1)).nonempty(),
        note: z.string().optional(),
      })
      .refine((m) => (m.aitech === undefined) !== (m.aisubtech === undefined), {
        message: 'aitech と aisubtech はどちらか一方だけを書いてください',
      }),
  ),
});

export type AitechMapping = z.infer<typeof AitechMapSchema>['mappings'][number];

export function loadAitechMap(text: string): AitechMapping[] {
  const mappings = AitechMapSchema.parse(parseYaml(text)).mappings;
  const seen = new Set<string>();
  for (const m of mappings) {
    for (const c of [...(m.aitech ?? []), ...(m.aisubtech ?? [])]) {
      if (seen.has(c)) throw new Error(`[finding-map] ${c} が複数の mapping に載っています`);
      seen.add(c);
    }
  }
  return mappings;
}

/**
 * AISubtech の行 → 無ければ親の AITech の行。指摘に aisubtech が無い・載っていないときは aitech で引く。
 * aitech が無く aisubtech だけのときは、AISubtech-12.1.5 → AITech-12.1 のように親を導く。
 * スキャナーによってサブ技術の番号が分類の版とずれるため、AITech 単位の行で受け止める。
 */
export function aitechToCanonicalIds(
  mappings: readonly AitechMapping[],
  aitech: string | undefined,
  aisubtech: string | undefined,
): readonly string[] | undefined {
  if (aisubtech) {
    const hit = mappings.find((m) => m.aisubtech?.includes(aisubtech));
    if (hit) return hit.canonicalIds;
  }
  const parent = aitech ?? aisubtech?.replace(/^AISubtech-(\d+\.\d+)\.\d+$/, 'AITech-$1');
  return parent ? mappings.find((m) => m.aitech?.includes(parent))?.canonicalIds : undefined;
}

const aitechSources = import.meta.glob<string>('../../../data/finding-maps/aitech.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const BUNDLED_AITECH_MAP: AitechMapping[] = loadAitechMap(
  Object.values(aitechSources)[0] ?? 'schemaVersion: 1\nmappings: []\n',
);
