import { z } from 'zod';

/**
 * AI によるソース監査（Cloudflare security-audit スキル）の `findings.json` と `coverage-ledger.json` を読む
 * （docs/architecture.md §8.9）。許可リストの Zod で緩く検証し、未知のキーは捨てる。
 * 持つのは指摘の識別・判定・重大度・場所・前提・要確認の事実だけ。execution（payloads を含む）・remediation（修正コード）・
 * evidence・root_cause・intended_behavior の本文は読まない。入力のサイズ上限（16 MB）は呼び出し側で確かめる。
 */

export const SECURITY_AUDIT_MAX_BYTES = 16 * 1024 * 1024;

const Fingerprint = z
  .string()
  .min(1)
  .max(200)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/);

const TraceSchema = z.object({
  kind: z.string().optional().catch(undefined),
  file: z.string().min(1),
  line: z.number().int().positive().optional().catch(undefined),
});

const ConditionSchema = z.object({ kind: z.string(), description: z.string() });

const ConfirmedSchema = z.object({
  verdict: z.literal('confirmed'),
  fingerprint: Fingerprint,
  title: z.string().min(1),
  trace: z.array(TraceSchema).catch([]),
  conditions: z.array(ConditionSchema).catch([]),
  severity: z.object({ overall_severity: z.string() }).optional().catch(undefined),
});

const NeedsValidationSchema = z.object({
  verdict: z.literal('needs_validation'),
  fingerprint: Fingerprint,
  title: z.string().min(1),
  trace: z.array(TraceSchema).catch([]),
  blockers: z.array(z.string()).catch([]),
  validation_plan: z.object({ deployment: z.string().optional().catch(undefined) }).optional().catch(undefined),
});

const RejectedSchema = z.object({ verdict: z.literal('rejected'), fingerprint: Fingerprint });

const ItemSchema = z.discriminatedUnion('verdict', [ConfirmedSchema, NeedsValidationSchema, RejectedSchema]);

export type AuditItem = z.infer<typeof ItemSchema>;

export type ParsedSecurityAudit =
  | { ok: true; items: AuditItem[]; /** 形が合わず読めなかった要素の数。 */ invalid: number }
  | { ok: false; error: string };

export function parseSecurityAudit(raw: unknown): ParsedSecurityAudit {
  if (!Array.isArray(raw)) return { ok: false, error: 'findings.json の形式が不正です（最上位が配列ではありません）。' };
  const items: AuditItem[] = [];
  let invalid = 0;
  for (const el of raw) {
    const r = ItemSchema.safeParse(el);
    if (r.success) items.push(r.data);
    else invalid += 1;
  }
  return { ok: true, items, invalid };
}

/** 台帳の単位 1 件分（攻撃クラスの参照と、その単位が出した指摘の指紋）。 */
export interface LedgerUnit {
  /** `FILE.md#型名`。無ければ undefined。 */
  attackClass?: string;
  fingerprints: string[];
}

const LedgerUnitSchema = z.object({
  canonical_refs: z.object({ attack_class: z.string().optional().catch(undefined) }).optional().catch(undefined),
  result_fingerprints: z.array(z.string()).catch([]),
});

export type ParsedLedger = { ok: true; units: LedgerUnit[] } | { ok: false; error: string };

export function parseCoverageLedger(raw: unknown): ParsedLedger {
  if (!Array.isArray(raw)) return { ok: false, error: 'coverage-ledger.json の形式が不正です（最上位が配列ではありません）。' };
  const units: LedgerUnit[] = [];
  for (const el of raw) {
    const r = LedgerUnitSchema.safeParse(el);
    if (!r.success) continue;
    const attackClass = r.data.canonical_refs?.attack_class;
    units.push({ ...(attackClass ? { attackClass } : {}), fingerprints: r.data.result_fingerprints });
  }
  return { ok: true, units };
}
