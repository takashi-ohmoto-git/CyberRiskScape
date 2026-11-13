import { z } from 'zod';
import { BUSINESS_CRITICALITIES, type BusinessCriticality } from '../../core/model/types';

/**
 * 業務の文脈の表（ベンダー非依存）の読み取り。CSV と JSON の 2 形式（docs/architecture.md §8 の翻訳ハブ）。
 * プロセスマイニング等の集計を「ノード × 業務プロセス」の表にしたものを受け取り、検証済みの行にする。
 * 外部入力なので Zod で検証し、サイズ・行数に上限を置く。ネットワークにも出ない。
 */

export const BUSINESS_CONTEXT_KIND = 'cyberriskscape-business-context';
export const BUSINESS_CONTEXT_MAX_BYTES = 5 * 1024 * 1024;
export const BUSINESS_CONTEXT_MAX_ROWS = 10_000;

export interface BusinessContextRow {
  /** ノード ID または C 番号。 */
  node: string;
  process: string;
  cases?: number;
  value?: number;
  currency?: string;
  period?: string;
  criticality?: BusinessCriticality;
}

export interface BusinessContextTable {
  rows: BusinessContextRow[];
  /** JSON の最上位に書かれた出どころ（製品名・参照）。 */
  source?: { product: string; ref?: string };
}

export type ParseBusinessContextResult = ({ ok: true } & BusinessContextTable) | { ok: false; error: string };

const num = z.number().finite().nonnegative();
const RowSchema = z.object({
  node: z.string().trim().min(1).max(200),
  process: z.string().trim().min(1).max(200),
  cases: num.optional(),
  value: num.optional(),
  currency: z.string().trim().min(1).max(16).optional(),
  period: z.string().trim().min(1).max(64).optional(),
  criticality: z
    .string()
    .trim()
    .transform((s) => BUSINESS_CRITICALITIES.find((c) => c.toLowerCase() === s.toLowerCase()))
    .refine((c): c is BusinessCriticality => c !== undefined, { message: 'criticality は High / Medium / Low のいずれか' })
    .optional(),
});

const SourceSchema = z.object({
  product: z.string().trim().min(1).max(64),
  ref: z.string().trim().min(1).max(200).optional(),
});

const COLUMNS = ['node', 'process', 'cases', 'value', 'currency', 'period', 'criticality'] as const;

/** RFC 4180 の範囲の CSV 解析（引用符・引用符内の改行と "" を扱う）。空行は捨てる。 */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  let i = 0;
  const endField = () => {
    row.push(field);
    field = '';
  };
  const endRow = () => {
    endField();
    if (row.some((c) => c.trim() !== '')) rows.push(row);
    row = [];
  };
  while (i < text.length) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        quoted = false;
      } else field += c;
    } else if (c === '"' && field === '') quoted = true;
    else if (c === ',') endField();
    else if (c === '\n') endRow();
    else if (c !== '\r') field += c;
    i += 1;
  }
  if (field !== '' || row.length > 0) endRow();
  return rows;
}

function issueText(e: z.ZodError): string {
  const i = e.issues[0];
  return `${i.path.join('.') || '値'}: ${i.message}`;
}

/** 表（CSV か JSON）を読む。拡張子が .json か、先頭が `{` なら JSON として扱う。 */
export function parseBusinessContextTable(text: string, fileName?: string): ParseBusinessContextResult {
  if (text.length > BUSINESS_CONTEXT_MAX_BYTES) {
    return { ok: false, error: `表が大きすぎます（上限 ${BUSINESS_CONTEXT_MAX_BYTES / 1024 / 1024} MB）。` };
  }
  const body = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const isJson = /\.json$/i.test(fileName ?? '') || (!/\.csv$/i.test(fileName ?? '') && body.trimStart().startsWith('{'));
  return isJson ? parseJson(body) : parseCsvTable(body);
}

function parseJson(text: string): ParseBusinessContextResult {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { ok: false, error: 'JSON として読めません。' };
  }
  const head = z
    .object({ kind: z.literal(BUSINESS_CONTEXT_KIND), schemaVersion: z.literal(1), rows: z.array(z.unknown()), source: SourceSchema.optional() })
    .safeParse(raw);
  if (!head.success) {
    return { ok: false, error: `形式が合いません（kind: "${BUSINESS_CONTEXT_KIND}"・schemaVersion: 1・rows の配列が必要）: ${issueText(head.error)}` };
  }
  if (head.data.rows.length > BUSINESS_CONTEXT_MAX_ROWS) {
    return { ok: false, error: `行が多すぎます（上限 ${BUSINESS_CONTEXT_MAX_ROWS} 行）。` };
  }
  const rows: BusinessContextRow[] = [];
  for (const [i, r] of head.data.rows.entries()) {
    const p = RowSchema.safeParse(r);
    if (!p.success) return { ok: false, error: `${i + 1} 行目: ${issueText(p.error)}` };
    rows.push(clean(p.data));
  }
  return { ok: true, rows, ...(head.data.source ? { source: head.data.source } : {}) };
}

function parseCsvTable(text: string): ParseBusinessContextResult {
  const grid = parseCsv(text);
  if (grid.length === 0) return { ok: false, error: '表が空です。' };
  const header = grid[0].map((h) => h.trim().toLowerCase());
  for (const need of ['node', 'process']) {
    if (!header.includes(need)) return { ok: false, error: `ヘッダに ${need} の列がありません（${COLUMNS.join(',')}）。` };
  }
  const body = grid.slice(1);
  if (body.length > BUSINESS_CONTEXT_MAX_ROWS) {
    return { ok: false, error: `行が多すぎます（上限 ${BUSINESS_CONTEXT_MAX_ROWS} 行）。` };
  }
  const rows: BusinessContextRow[] = [];
  for (const [i, cells] of body.entries()) {
    const obj: Record<string, unknown> = {};
    for (const col of COLUMNS) {
      const idx = header.indexOf(col);
      const cell = idx >= 0 ? (cells[idx] ?? '').trim() : '';
      if (cell === '') continue;
      if (col === 'cases' || col === 'value') {
        // 空でない数値欄が数として読めなければエラー（黙って捨てない）。
        const n = /^[+-]?(\d+\.?\d*|\.\d+)(e[+-]?\d+)?$/i.test(cell) ? Number(cell) : Number.NaN;
        if (!Number.isFinite(n)) return { ok: false, error: `${i + 2} 行目: ${col} が数値ではありません。` };
        obj[col] = n;
      } else obj[col] = cell;
    }
    const p = RowSchema.safeParse(obj);
    if (!p.success) return { ok: false, error: `${i + 2} 行目: ${issueText(p.error)}` };
    rows.push(clean(p.data));
  }
  return { ok: true, rows };
}

/** undefined のキーを落とす。 */
function clean(r: z.infer<typeof RowSchema>): BusinessContextRow {
  const out: BusinessContextRow = { node: r.node, process: r.process };
  if (r.cases !== undefined) out.cases = r.cases;
  if (r.value !== undefined) out.value = r.value;
  if (r.currency !== undefined) out.currency = r.currency;
  if (r.period !== undefined) out.period = r.period;
  if (r.criticality !== undefined) out.criticality = r.criticality;
  return out;
}
