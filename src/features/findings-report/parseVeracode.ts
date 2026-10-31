import { z } from 'zod';

/**
 * Veracode のスキャン結果ファイルを共通の形（`NormalizedFinding`）に直す。
 * 入力は次の 2 形式を自動判別する（未知のキーは無視）。
 *   - Pipeline Scan の `results.json`（`{ findings: [...] }`。すべて STATIC・未解決として扱う）
 *   - Findings API v2 の応答 1 ページ（`{ _embedded: { findings: [...] } }`）
 * 説明文などの自由記述は取り込まない（タイトル・場所・分類だけ）。
 */

export type ScanType = 'STATIC' | 'DYNAMIC' | 'MANUAL' | 'SCA';

export interface NormalizedFinding {
  id: string;
  scanType: ScanType;
  cwe?: number;
  cweName?: string;
  /** Veracode の重大度（0〜5）。 */
  severity: number;
  title: string;
  /** file:line / URL / 入力ベクタ など。 */
  location?: string;
  /** MANUAL の攻撃カテゴリ（値はそのまま。対応づけはしない）。 */
  capec?: string;
  status: 'open' | 'closed';
  /** Cisco AI Defense 系スキャナーの指摘のとき、その種別（Veracode では付かない）。 */
  origin?: 'skill-scanner' | 'mcp-scanner';
  /** Cisco 系の AITech / AISubtech コードと名前（コードと名前だけ。説明文は取り込まない）。 */
  aitech?: string;
  aitechName?: string;
  aisubtech?: string;
  aisubtechName?: string;
}

export interface ParsedFindings {
  source: 'pipeline' | 'findings-api';
  /** 対象（STATIC / DYNAMIC / MANUAL かつ未解決）。 */
  findings: NormalizedFinding[];
  excluded: { sca: number; closed: number };
}

export type ParseResult = ({ ok: true } & ParsedFindings) | { ok: false; error: string };

const PipelineIssueSchema = z.object({
  title: z.string().optional(),
  issue_id: z.number().optional(),
  severity: z.number().optional(),
  cwe_id: z.union([z.string(), z.number()]).optional(),
  files: z
    .object({
      source_file: z.object({ file: z.string().optional(), line: z.number().optional() }).optional(),
    })
    .optional(),
});
const PipelineSchema = z.object({ findings: z.array(PipelineIssueSchema) });

const NameOrString = z.union([z.string(), z.object({ name: z.string().optional() })]);
const FindingSchema = z.object({
  issue_id: z.union([z.number(), z.string()]).optional(),
  scan_type: z.enum(['STATIC', 'DYNAMIC', 'MANUAL', 'SCA']),
  finding_status: z.object({ status: z.string().optional() }).optional(),
  finding_details: z
    .object({
      cwe: z.union([z.number(), z.object({ id: z.number().optional(), name: z.string().optional() })]).optional(),
      severity: z.number().optional(),
      finding_category: NameOrString.optional(),
      file_path: z.string().optional(),
      file_name: z.string().optional(),
      file_line_number: z.number().optional(),
      URL: z.string().optional(),
      path: z.string().optional(),
      capec_id: z.union([z.string(), z.number()]).optional(),
      input_vector: z.string().optional(),
      location: z.string().optional(),
    })
    .passthrough(),
});
const FindingsApiSchema = z.object({ _embedded: z.object({ findings: z.array(FindingSchema) }) });

const SHAPE_ERROR =
  'Veracode の結果ファイルの形式を認識できません。Pipeline Scan の results.json（"findings" 配列）か、Findings API v2 の応答（"_embedded.findings" 配列）を指定してください。';

function toCwe(v: string | number | undefined): number | undefined {
  if (v === undefined) return undefined;
  const n = typeof v === 'number' ? v : Number.parseInt(v, 10);
  return Number.isInteger(n) && n > 0 ? n : undefined;
}

/** URL の userinfo・クエリ・フラグメントを捨てる（トークン等が載りうるため取り込まない）。URL でなければ `?` 以降を捨てる。 */
export function stripSecrets(v: string | undefined): string | undefined {
  if (!v) return undefined;
  try {
    const u = new URL(v);
    return `${u.protocol}//${u.host}${u.pathname}`;
  } catch {
    return v.split(/[?#]/)[0] || undefined;
  }
}

function nameOf(v: z.infer<typeof NameOrString> | undefined): string | undefined {
  const s = typeof v === 'string' ? v : v?.name;
  return s?.trim() || undefined;
}

function pipelineFindings(p: z.infer<typeof PipelineSchema>): ParsedFindings {
  const findings = p.findings.map((f, i): NormalizedFinding => {
    const cwe = toCwe(f.cwe_id);
    const src = f.files?.source_file;
    return {
      id: f.issue_id !== undefined ? String(f.issue_id) : `P-${i + 1}`,
      scanType: 'STATIC',
      cwe,
      severity: f.severity ?? 0,
      title: f.title?.trim() || (cwe ? `CWE-${cwe}` : 'Unknown'),
      location: src?.file ? (src.line !== undefined ? `${src.file}:${src.line}` : src.file) : undefined,
      status: 'open',
    };
  });
  return { source: 'pipeline', findings, excluded: { sca: 0, closed: 0 } };
}

function apiFindings(p: z.infer<typeof FindingsApiSchema>): ParsedFindings {
  const excluded = { sca: 0, closed: 0 };
  const findings: NormalizedFinding[] = [];
  p._embedded.findings.forEach((f, i) => {
    if (f.scan_type === 'SCA') {
      excluded.sca += 1;
      return;
    }
    if (f.finding_status?.status?.toUpperCase() === 'CLOSED') {
      excluded.closed += 1;
      return;
    }
    const d = f.finding_details;
    const cwe = typeof d.cwe === 'object' ? toCwe(d.cwe.id) : toCwe(d.cwe);
    const cweName = typeof d.cwe === 'object' ? nameOf(d.cwe) : undefined;
    let location: string | undefined;
    if (f.scan_type === 'STATIC') {
      const file = d.file_path || d.file_name;
      location = file ? (d.file_line_number !== undefined ? `${file}:${d.file_line_number}` : file) : undefined;
    } else if (f.scan_type === 'DYNAMIC') {
      location = stripSecrets(d.URL || d.path);
    } else {
      location = stripSecrets(d.input_vector || d.location);
    }
    findings.push({
      id: f.issue_id !== undefined ? String(f.issue_id) : `F-${i + 1}`,
      scanType: f.scan_type,
      cwe,
      cweName,
      severity: d.severity ?? 0,
      title: cweName ?? nameOf(d.finding_category) ?? (cwe ? `CWE-${cwe}` : 'Unknown'),
      location,
      capec: f.scan_type === 'MANUAL' && d.capec_id !== undefined ? String(d.capec_id) : undefined,
      status: 'open',
    });
  });
  return { source: 'findings-api', findings, excluded };
}

export function parseVeracodeFindings(raw: unknown): ParseResult {
  const api = FindingsApiSchema.safeParse(raw);
  if (api.success) return { ok: true, ...apiFindings(api.data) };
  const pipe = PipelineSchema.safeParse(raw);
  if (pipe.success) return { ok: true, ...pipelineFindings(pipe.data) };
  return { ok: false, error: SHAPE_ERROR };
}
