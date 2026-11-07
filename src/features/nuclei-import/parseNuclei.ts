import { z } from 'zod';
import { MAX_FINDINGS } from '../../core/model/types';

/**
 * Nuclei（projectdiscovery/nuclei v3）の結果を読む（docs/architecture.md §8.6）。
 * JSONL（-j / -jle）と JSON 配列（-je）の両方を受ける。許可リストの Zod で検証し、未知のキーは捨てる。
 * request / response / curl-command / extracted-results / interaction / meta / template-encoded / description / ip は
 * 秘密情報を含み得るため読まない（スキーマに載せない）。
 */

/** 読む結果の上限。info・不一致で捨てる分を見込んで保存上限の 4 倍とする。 */
export const MAX_NUCLEI_RECORDS = MAX_FINDINGS * 4;

const Str = z.string().optional().catch(undefined);
const StrList = z.array(z.string()).optional().catch(undefined);
const Num = z.number().optional().catch(undefined);

const NucleiResultSchema = z.object({
  'template-id': z.string().min(1),
  info: z
    .object({
      name: Str,
      severity: Str,
      classification: z
        .object({ 'cve-id': StrList, 'cwe-id': StrList, 'cvss-score': Num, 'epss-score': Num })
        .optional()
        .catch(undefined),
    })
    .optional()
    .catch(undefined),
  type: Str,
  host: Str,
  scheme: Str,
  port: z.union([z.string(), z.number()]).optional().catch(undefined),
  'matched-at': Str,
  'matcher-name': Str,
  timestamp: Str,
  'matcher-status': z.boolean().optional().catch(undefined),
});

export type NucleiResult = z.infer<typeof NucleiResultSchema>;

export type ParseNucleiResult =
  | {
      ok: true;
      results: NucleiResult[];
      /** 読めなかった行・要素の数。 */
      invalid: number;
      /** 上限で読まなかった数。 */
      overLimit: number;
    }
  | { ok: false; error: string };

export function parseNuclei(text: string): ParseNucleiResult {
  const trimmed = text.trim();
  if (trimmed === '') return { ok: false, error: 'Nuclei の結果が空です。' };
  let records: unknown[];
  let invalid = 0;
  if (trimmed.startsWith('[')) {
    try {
      const arr: unknown = JSON.parse(trimmed);
      if (!Array.isArray(arr)) return { ok: false, error: 'Nuclei の JSON 配列として読めません。' };
      records = arr;
    } catch {
      return { ok: false, error: 'Nuclei の JSON 配列として読めません。' };
    }
  } else {
    records = [];
    for (const line of trimmed.split(/\r?\n/)) {
      if (line.trim() === '') continue;
      try {
        records.push(JSON.parse(line));
      } catch {
        invalid++;
      }
    }
  }
  const overLimit = Math.max(0, records.length - MAX_NUCLEI_RECORDS);
  const results: NucleiResult[] = [];
  for (const r of records.slice(0, MAX_NUCLEI_RECORDS)) {
    const p = NucleiResultSchema.safeParse(r);
    if (p.success) results.push(p.data);
    else invalid++;
  }
  if (results.length === 0) {
    return { ok: false, error: 'Nuclei の結果として読める行がありません（template-id を持つ JSONL または JSON 配列が必要です）。' };
  }
  return { ok: true, results, invalid, overLimit };
}
