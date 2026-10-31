import { z } from 'zod';
import type { NormalizedFinding } from './parseVeracode';

/**
 * Cisco AI Defense の skill-scanner（`--format json`）の結果を共通の形（`NormalizedFinding`）に直す。
 * 入力は次の 2 形式を自動判別する（未知のキーは無視）。
 *   - 単体: `{ skill_name, findings: [...] }`
 *   - 複数スキル（scan-all）: `{ results: [単体...] }`
 * 取り込むのはタイトル・場所・重大度・分類コードだけ。`snippet`・`description`・`remediation`・
 * `skill_path`（絶対パス）・`framework_mappings` は秘密や環境情報を含みうるので読まない。
 */

export interface ParsedCiscoFindings {
  findings: NormalizedFinding[];
  excluded: { sca: number; closed: number };
  /** status が completed 以外の項目数（mcp-scanner のみ。検査できていない＝安全ではない）。 */
  incompleteItems?: number;
}

export type CiscoParseResult = ({ ok: true } & ParsedCiscoFindings) | { ok: false; error: string };

const SEVERITY_SCORE: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 0 };

/** Cisco 系の重大度ラベル → 既存の 0〜5 スケール。不明なラベルは 0。 */
export function ciscoSeverityScore(label: string | undefined): number {
  return SEVERITY_SCORE[(label ?? '').toUpperCase()] ?? 0;
}

/** 0〜5 のスケール → Cisco 系の重大度ラベル（表示用）。 */
export function ciscoSeverityLabel(score: number): string {
  if (score >= 5) return 'CRITICAL';
  if (score >= 4) return 'HIGH';
  if (score >= 3) return 'MEDIUM';
  if (score >= 2) return 'LOW';
  return 'INFO';
}

const Str = z.string().nullish();

const FindingSchema = z.object({
  id: z.union([z.string(), z.number()]).optional(),
  rule_id: Str,
  title: Str,
  severity: Str,
  file_path: Str,
  line_number: z.number().nullish(),
  metadata: z
    .object({
      aitech: Str,
      aitech_name: Str,
      aisubtech: Str,
      aisubtech_name: Str,
    })
    .nullish(),
});
const SkillSchema = z.object({ skill_name: Str, findings: z.array(FindingSchema) });
const MultiSchema = z.object({ results: z.array(SkillSchema) });

const SHAPE_ERROR =
  'skill-scanner の結果ファイルの形式を認識できません。`skill-scanner scan ... --format json` の出力（"findings" 配列）か、scan-all の出力（"results" 配列）を指定してください。';

const clean = (v: string | null | undefined): string | undefined => v?.trim() || undefined;

function skillFindings(skill: z.infer<typeof SkillSchema>, offset: number): NormalizedFinding[] {
  const name = clean(skill.skill_name) ?? 'skill';
  return skill.findings.map((f, i): NormalizedFinding => {
    const file = clean(f.file_path);
    const where = file ? (f.line_number != null ? `${file}:${f.line_number}` : file) : '';
    const m = f.metadata;
    return {
      id: f.id !== undefined ? String(f.id) : `S-${offset + i + 1}`,
      scanType: 'STATIC',
      severity: ciscoSeverityScore(f.severity ?? undefined),
      title: clean(f.title) ?? clean(f.rule_id) ?? 'Unknown',
      location: where ? `${name}/${where}` : name,
      status: 'open',
      origin: 'skill-scanner',
      aitech: clean(m?.aitech),
      aitechName: clean(m?.aitech_name),
      aisubtech: clean(m?.aisubtech),
      aisubtechName: clean(m?.aisubtech_name),
    };
  });
}

export function parseSkillScannerFindings(raw: unknown): CiscoParseResult {
  const multi = MultiSchema.safeParse(raw);
  const list = multi.success ? multi.data.results : undefined;
  const single = list ? undefined : SkillSchema.safeParse(raw);
  const skills = list ?? (single?.success ? [single.data] : undefined);
  if (!skills) return { ok: false, error: SHAPE_ERROR };
  const findings: NormalizedFinding[] = [];
  for (const s of skills) findings.push(...skillFindings(s, findings.length));
  return { ok: true, findings, excluded: { sca: 0, closed: 0 } };
}
