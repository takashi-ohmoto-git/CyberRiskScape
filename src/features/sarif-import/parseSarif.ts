import { z } from 'zod';

/**
 * 汎用の SARIF 2.1.0 を読む（docs/architecture.md §8.6）。許可リストの Zod で検証し、未知のキーは捨てる。
 * 持つのは指摘の識別・深刻度・場所だけ。message の本文・コード片（snippet）・codeFlows は読まない。
 */

const Str = z.string().optional().catch(undefined);
const Tags = z.array(z.string()).optional().catch(undefined);
const Score = z.union([z.string(), z.number()]).optional().catch(undefined);

const DescriptorRefSchema = z.object({
  id: Str,
  toolComponent: z.object({ name: Str }).optional().catch(undefined),
});

const RuleSchema = z.object({
  id: Str,
  shortDescription: z.object({ text: Str }).optional().catch(undefined),
  defaultConfiguration: z.object({ level: Str }).optional().catch(undefined),
  properties: z.object({ tags: Tags, 'security-severity': Score }).optional().catch(undefined),
  relationships: z.array(z.object({ target: DescriptorRefSchema.optional().catch(undefined) })).optional().catch(undefined),
});

const LocationSchema = z.object({
  physicalLocation: z
    .object({
      artifactLocation: z.object({ uri: Str }).optional().catch(undefined),
      region: z.object({ startLine: z.number().int().optional().catch(undefined) }).optional().catch(undefined),
    })
    .optional()
    .catch(undefined),
});

const ResultSchema = z.object({
  ruleId: Str,
  ruleIndex: z.number().int().optional().catch(undefined),
  rule: z.object({ id: Str }).optional().catch(undefined),
  level: Str,
  kind: Str,
  baselineState: Str,
  message: z.object({ text: Str }).optional().catch(undefined),
  locations: z.array(LocationSchema).optional().catch(undefined),
  partialFingerprints: z.record(z.string(), z.string()).optional().catch(undefined),
  suppressions: z.array(z.object({ status: Str })).optional().catch(undefined),
  taxa: z.array(DescriptorRefSchema).optional().catch(undefined),
  properties: z.object({ tags: Tags, 'security-severity': Score }).optional().catch(undefined),
});

const RunSchema = z.object({
  tool: z.object({
    driver: z.object({
      name: z.string().min(1),
      semanticVersion: Str,
      version: Str,
      rules: z.array(RuleSchema).optional().catch(undefined),
    }),
  }),
  results: z.array(ResultSchema).optional().catch(undefined),
});

const SarifSchema = z.object({ version: Str, runs: z.array(RunSchema) });

export type SarifRule = z.infer<typeof RuleSchema>;
export type SarifResult = z.infer<typeof ResultSchema>;
export type SarifRun = z.infer<typeof RunSchema>;

export type ParsedSarif = { ok: true; runs: SarifRun[] } | { ok: false; error: string };

export function parseSarif(raw: unknown): ParsedSarif {
  const r = SarifSchema.safeParse(raw);
  if (!r.success) return { ok: false, error: 'SARIF 2.1.0 の形式ではありません（runs[] と tool.driver.name が必要）。' };
  if (r.data.version !== undefined && !r.data.version.startsWith('2.1')) {
    return { ok: false, error: `SARIF 2.1.0 のみ対応しています（version: ${r.data.version.slice(0, 20)}）。` };
  }
  return { ok: true, runs: r.data.runs };
}
