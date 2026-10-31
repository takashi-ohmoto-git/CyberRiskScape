import { z } from 'zod';
import { ciscoSeverityScore, type CiscoParseResult } from './parseSkillScanner';
import { stripSecrets, type NormalizedFinding } from './parseVeracode';

/**
 * Cisco AI Defense の mcp-scanner の結果を共通の形（`NormalizedFinding`）に直す。
 * 入力は次の 3 形式を自動判別する（未知のキーは無視）。
 *   - `--format raw`: `{ server_url, scan_results: [...] }`
 *   - `--raw`: 結果の配列
 *   - `known-configs --raw`: `{ "<設定ファイルのパス>": [...], ... }`（パスは使わない）
 * 指摘ごとの重大度は無く解析器ごとの集約だけなので、1 指摘 = (項目, 解析器, mcp_taxonomies の 1 要素) とし、
 * 重大度はその解析器の severity を使う。`server_url`（stdio ではコマンドと引数）・`tool_description`・
 * `server_source`・`mcp_taxonomies[].description` は秘密を含みうるので読まない。
 */

const Str = z.string().nullish();

const TaxonomySchema = z.object({
  aitech: Str,
  aitech_name: Str,
  aisubtech: Str,
  aisubtech_name: Str,
});
type Taxonomy = z.infer<typeof TaxonomySchema>;

const AnalyzerSchema = z.object({
  severity: Str,
  total_findings: z.number().nullish(),
  mcp_taxonomies: z.array(TaxonomySchema).nullish(),
});
const ResultSchema = z.object({
  status: Str,
  item_type: Str,
  tool_name: Str,
  prompt_name: Str,
  resource_name: Str,
  resource_uri: Str,
  server_name: Str,
  findings: z.record(z.string(), AnalyzerSchema).nullish(),
});
type McpResult = z.infer<typeof ResultSchema>;

const EnvelopeSchema = z.object({ scan_results: z.array(ResultSchema) });
const ArraySchema = z.array(ResultSchema);
const KnownConfigsSchema = z.record(z.string(), z.array(ResultSchema));

const SHAPE_ERROR =
  'mcp-scanner の結果ファイルの形式を認識できません。`--format raw`（"scan_results" 配列）、`--raw`（結果の配列）、`known-configs --raw`（設定ファイルのパス → 結果の配列）のいずれかの出力を指定してください。';

const clean = (v: string | null | undefined): string | undefined => v?.trim() || undefined;

function itemName(r: McpResult): string {
  return (
    clean(r.tool_name) ??
    clean(r.prompt_name) ??
    clean(r.resource_name) ??
    stripSecrets(clean(r.resource_uri)) ??
    'unknown'
  );
}

function resultFindings(r: McpResult): NormalizedFinding[] {
  const name = itemName(r);
  const server = clean(r.server_name) ?? '';
  const type = clean(r.item_type) ?? 'item';
  const out = new Map<string, NormalizedFinding>();
  for (const [analyzer, a] of Object.entries(r.findings ?? {})) {
    const taxa: Taxonomy[] = a.mcp_taxonomies ?? [];
    // SAFE / UNKNOWN で指摘 0 件（分類も無い）の解析器は指摘なし
    if ((a.total_findings ?? 0) === 0 && taxa.length === 0) continue;
    const severity = ciscoSeverityScore(a.severity ?? undefined);
    for (const t of taxa.length > 0 ? taxa : [{} as Taxonomy]) {
      const aitech = clean(t.aitech);
      const aisubtech = clean(t.aisubtech);
      const id = `${server}/${name}/${analyzer}/${aisubtech ?? aitech ?? 'unclassified'}`;
      if (out.has(id)) continue;
      out.set(id, {
        id,
        scanType: 'STATIC',
        severity,
        title: `${analyzer}: ${clean(t.aisubtech_name) ?? clean(t.aitech_name) ?? aisubtech ?? aitech ?? 'Unclassified'}`,
        location: `${server ? `${server}/` : ''}${type}:${name}`,
        status: 'open',
        origin: 'mcp-scanner',
        aitech,
        aitechName: clean(t.aitech_name),
        aisubtech,
        aisubtechName: clean(t.aisubtech_name),
      });
    }
  }
  return [...out.values()];
}

export function parseMcpScannerFindings(raw: unknown): CiscoParseResult {
  const env = EnvelopeSchema.safeParse(raw);
  const arr = env.success ? undefined : ArraySchema.safeParse(raw);
  const known = env.success || arr?.success ? undefined : KnownConfigsSchema.safeParse(raw);
  const results = env.success
    ? env.data.scan_results
    : arr?.success
      ? arr.data
      : known?.success
        ? Object.values(known.data).flat()
        : undefined;
  if (!results) return { ok: false, error: SHAPE_ERROR };
  const findings = results.flatMap(resultFindings);
  const incompleteItems = results.filter((r) => (clean(r.status) ?? 'completed') !== 'completed').length;
  return { ok: true, findings, excluded: { sca: 0, closed: 0 }, incompleteItems };
}
