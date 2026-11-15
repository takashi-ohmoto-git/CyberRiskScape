import { z } from 'zod';
import { scrubUri } from './sarifToFindings';

/**
 * 秘密の走査の SARIF から、調査のための生の情報（場所・コミットの情報・秘密の値）を取り出す。
 * `import-sarif --category secrets --show-secrets` のときだけ呼ぶ。結果は取り込みの報告にだけ出し、
 * プロジェクト JSON・SARIF の書き出し・画面には入れない（parseSarif は秘密の値を読まない作りのまま）。
 * DOM にも Node にも依存しない。
 */

const Str = z.string().optional().catch(undefined);

const ResultSchema = z.object({
  ruleId: Str,
  rule: z.object({ id: Str }).optional().catch(undefined),
  locations: z
    .array(
      z.object({
        physicalLocation: z
          .object({
            artifactLocation: z.object({ uri: Str }).optional().catch(undefined),
            region: z
              .object({ startLine: z.number().int().optional().catch(undefined), snippet: z.object({ text: Str }).optional().catch(undefined) })
              .optional()
              .catch(undefined),
          })
          .optional()
          .catch(undefined),
      }),
    )
    .optional()
    .catch(undefined),
  partialFingerprints: z.record(z.string(), z.string()).optional().catch(undefined),
});

const SarifSchema = z.object({ runs: z.array(z.object({ results: z.array(ResultSchema).optional().catch(undefined) })) });

export interface SecretDetail {
  rule: string;
  /** ファイルと行（相対的な表記）。 */
  location?: string;
  /** 走査の製品が付けた付随情報（コミット・作者・メールアドレス・日時等）。項目名はそのまま。 */
  context: Record<string, string>;
  /** 見つかった秘密の値（SARIF のコード片）。 */
  secret?: string;
}

const MAX_DETAILS = 5000;
const VALUE_MAX = 500;

export function extractSecretDetails(raw: unknown): SecretDetail[] {
  const r = SarifSchema.safeParse(raw);
  if (!r.success) return [];
  const out: SecretDetail[] = [];
  for (const run of r.data.runs) {
    for (const res of run.results ?? []) {
      if (out.length >= MAX_DETAILS) return out;
      const phys = res.locations?.[0]?.physicalLocation;
      const uri = phys?.artifactLocation?.uri ? scrubUri(phys.artifactLocation.uri) : undefined;
      const line = phys?.region?.startLine;
      const context: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.partialFingerprints ?? {})) context[k.slice(0, 50)] = v.slice(0, VALUE_MAX);
      const secret = phys?.region?.snippet?.text;
      out.push({
        rule: (res.ruleId ?? res.rule?.id ?? 'unknown').slice(0, 200),
        ...(uri ? { location: `${uri}${line !== undefined ? `:${line}` : ''}` } : {}),
        context,
        ...(secret !== undefined ? { secret: secret.slice(0, VALUE_MAX) } : {}),
      });
    }
  }
  return out;
}
