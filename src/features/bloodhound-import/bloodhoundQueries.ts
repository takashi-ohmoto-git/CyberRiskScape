import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { SeveritySchema } from '../../threat-library/schema/threatRule';

/**
 * BloodHound CE に送る問い合わせ（Cypher）と canonicalId の対応表（`data/finding-maps/bloodhound.yaml`）の
 * スキーマとローダー。問い合わせは読み取りだけに限る（書き込みの句を含むものは読み込み時にエラー）。
 * DOM にも Node にも依存しない。
 */

/** 書き込み・手続き呼び出しの句。問い合わせに含めない。 */
const WRITE_CLAUSE_RE = /\b(CREATE|MERGE|SET|DELETE|REMOVE|DETACH|DROP|CALL|LOAD|FOREACH)\b/i;

export function isReadOnlyCypher(cypher: string): boolean {
  return /^\s*MATCH\b/i.test(cypher) && /\bRETURN\b/i.test(cypher) && !WRITE_CLAUSE_RE.test(cypher);
}

const QuerySchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  title: z.string().min(1).max(150),
  cypher: z.string().min(1).max(2000).refine(isReadOnlyCypher, '読み取りだけの問い合わせ（MATCH … RETURN）にしてください'),
  canonicalIds: z.array(z.string().min(1)).nonempty(),
  severity: SeveritySchema,
  /** 指摘を載せる図のノードの種類。 */
  subject: z.enum(['directory', 'ca']),
  /** Tier Zero のノード（応答の isTierZero）を数えない。 */
  excludeTierZero: z.boolean(),
});

const QueriesFileSchema = z.object({
  schemaVersion: z.literal(1),
  queries: z.array(QuerySchema),
});

export type BloodhoundQuery = z.infer<typeof QuerySchema>;

export function loadBloodhoundQueries(text: string): BloodhoundQuery[] {
  const parsed = QueriesFileSchema.parse(parseYaml(text));
  const ids = new Set<string>();
  for (const q of parsed.queries) {
    if (ids.has(q.id)) throw new Error(`問い合わせの id が重複しています: ${q.id}`);
    ids.add(q.id);
  }
  return parsed.queries;
}

const sources = import.meta.glob<string>('../../../data/finding-maps/bloodhound.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const BUNDLED_BLOODHOUND_QUERIES: BloodhoundQuery[] = loadBloodhoundQueries(
  Object.values(sources)[0] ?? 'schemaVersion: 1\nqueries: []\n',
);
