import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { BUNDLED_PROWLER_MAP, findProwlerMapping, type ProwlerMapping } from '../prowler-import/prowlerMap';

/**
 * OCSF の製品ごとの検査 ID → canonicalId の対応表（`data/finding-maps/ocsf.yaml`）。
 * Prowler は既存の `prowler.yaml` を使う。脅威知識はコードに置かない。
 */

const OcsfMapSchema = z.object({
  schemaVersion: z.literal(1),
  products: z.array(
    z.object({
      product: z.string().min(1),
      mappings: z.array(z.object({ checks: z.array(z.string().min(1)).nonempty(), canonicalIds: z.array(z.string().min(1)).nonempty() })),
    }),
  ),
});

export type OcsfProductMap = z.infer<typeof OcsfMapSchema>['products'][number];

export function loadOcsfMap(text: string): OcsfProductMap[] {
  const products = OcsfMapSchema.parse(parseYaml(text)).products;
  const seenProducts = new Set<string>();
  for (const p of products) {
    const key = p.product.toLowerCase();
    if (seenProducts.has(key)) throw new Error(`[ocsf-map] 製品 ${p.product} が複数あります`);
    seenProducts.add(key);
    const seen = new Set<string>();
    for (const m of p.mappings) {
      for (const c of m.checks) {
        if (seen.has(c)) throw new Error(`[ocsf-map] ${p.product}: 検査 ${c} が複数のエントリに載っています`);
        seen.add(c);
      }
    }
  }
  return products;
}

/** 製品と検査 ID から canonicalId を引く。載っていなければ空。 */
export function ocsfCanonicalIds(
  product: string,
  checkId: string,
  map: readonly OcsfProductMap[],
  prowlerMap: readonly ProwlerMapping[] = BUNDLED_PROWLER_MAP,
): readonly string[] {
  if (product.toLowerCase() === 'prowler') return findProwlerMapping(prowlerMap, checkId)?.canonicalIds ?? [];
  const p = map.find((x) => x.product.toLowerCase() === product.toLowerCase());
  return p?.mappings.find((m) => m.checks.includes(checkId))?.canonicalIds ?? [];
}

const sources = import.meta.glob<string>('../../../data/finding-maps/ocsf.yaml', { query: '?raw', import: 'default', eager: true });

export const BUNDLED_OCSF_MAP: OcsfProductMap[] = loadOcsfMap(Object.values(sources)[0] ?? 'schemaVersion: 1\nproducts: []\n');
