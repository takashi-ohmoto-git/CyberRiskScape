import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { SeveritySchema } from '../../threat-library/schema/threatRule';

/**
 * SARIF の取り込みの分類（`data/finding-maps/sarif-categories.yaml`）のスキーマとローダー。
 * 利用者が `--category` で指定した分類の結果を、すべて同じ脅威に結ぶ（製品の名前で見分けない）。
 * DOM にも Node にも依存しない。
 */

const CategorySchema = z.object({
  id: z.string().regex(/^[a-z][a-z0-9-]*$/),
  title: z.string().min(1),
  canonicalIds: z.array(z.string().min(1)).nonempty(),
  /** その脅威が出る図のノードの型（指摘を結ぶ先の目安）。 */
  nodeTypes: z.array(z.string().regex(/^[A-Z][A-Za-z0-9_]*$/)).nonempty(),
  defaultSeverity: SeveritySchema,
  useMessageAsTitle: z.boolean(),
  /** `--show-secrets` で取り込みの報告に生の情報を出せるか。 */
  allowRawReport: z.boolean().default(false),
});

const FileSchema = z.object({ schemaVersion: z.literal(1), categories: z.array(CategorySchema) });

export type SarifCategory = z.infer<typeof CategorySchema>;

export function loadSarifCategories(text: string): SarifCategory[] {
  const parsed = FileSchema.parse(parseYaml(text));
  const ids = new Set<string>();
  for (const c of parsed.categories) {
    if (ids.has(c.id)) throw new Error(`分類の id が重複しています: ${c.id}`);
    ids.add(c.id);
  }
  return parsed.categories;
}

const sources = import.meta.glob<string>('../../../data/finding-maps/sarif-categories.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const BUNDLED_SARIF_CATEGORIES: SarifCategory[] = loadSarifCategories(
  Object.values(sources)[0] ?? 'schemaVersion: 1\ncategories: []\n',
);
