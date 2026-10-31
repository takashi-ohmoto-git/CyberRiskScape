import { z } from 'zod';

/**
 * Prowler の OCSF 出力（`*.ocsf.json`。Detection Finding の配列）を、取り込みに必要な項目だけに正規化する。
 * Zod は緩く（未知のキーは通すが読まない）。ファイル I/O はしない。
 *
 * 捨てるもの：`resources[].data`（資源の設定全体）・`cloud.account`・`cloud.org`・`risk_details` 等の長文・
 * URL の userinfo とクエリ。資源の ARN はノードとの対応付け（`uid`）にだけ使い、報告には `resourceLabel` を使う。
 */

export type ProwlerStatus = 'PASS' | 'FAIL' | 'MANUAL';

export interface ProwlerResource {
  uid?: string;
  name?: string;
  type?: string;
  /** サービス名（`group.name`）。 */
  service?: string;
  region?: string;
  /** タグ `crs-node` の値（図のノード ID または C 番号）。 */
  nodeTag?: string;
}

export interface NormalizedProwlerFinding {
  /** 検査 ID（`metadata.event_code`）。 */
  checkId: string;
  status: ProwlerStatus;
  severity?: string;
  title?: string;
  /** 製品側の指摘 ID（`finding_info.uid`。12 桁のアカウント ID は伏せ字）。 */
  uid?: string;
  /** 観測時刻（`time_dt`。ISO 8601）。 */
  observedAt?: string;
  resources: ProwlerResource[];
  categories: string[];
}

export interface ParsedProwler {
  findings: NormalizedProwlerFinding[];
  /** Prowler のバージョン（`metadata.product.version`。最初に見つかったもの）。 */
  productVersion?: string;
  skipped: {
    /** 形が読めなかった、または PASS/FAIL/MANUAL 以外の項目。 */
    invalid: number;
    /** ミュート済み（`status` が Suppressed）。 */
    muted: number;
  };
}

export type ParseProwlerResult = ({ ok: true } & ParsedProwler) | { ok: false; error: string };

export const NODE_TAG_KEY = 'crs-node';

const str = z.string().optional().catch(undefined);

const ResourceSchema = z
  .object({
    uid: str,
    name: str,
    type: str,
    region: str,
    group: z.object({ name: str }).optional().catch(undefined),
    labels: z.array(z.string()).optional().catch(undefined),
  })
  .passthrough();

const FindingSchema = z
  .object({
    metadata: z
      .object({
        event_code: z.string().min(1),
        product: z.object({ version: str }).passthrough().optional().catch(undefined),
      })
      .passthrough(),
    time_dt: str,
    status_code: z.string(),
    status: str,
    severity: str,
    finding_info: z.object({ title: str, uid: str }).passthrough().optional().catch(undefined),
    resources: z.array(ResourceSchema).optional().catch(undefined),
    unmapped: z
      .object({ categories: z.array(z.string()).optional().catch(undefined) })
      .passthrough()
      .optional()
      .catch(undefined),
  })
  .passthrough();

const TEXT_LIMIT = 200;

/** URL の userinfo とクエリ・フラグメントを捨てる。URL でなければそのまま。 */
export function stripUrlSecrets(value: string): string {
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return value;
  try {
    const u = new URL(value);
    u.username = '';
    u.password = '';
    u.search = '';
    u.hash = '';
    return u.toString();
  } catch {
    return value.replace(/\/\/[^/@]*@/, '//').replace(/[?#].*$/, '');
  }
}

function clean(value: string | undefined): string | undefined {
  if (value === undefined || value === '') return undefined;
  return stripUrlSecrets(value).slice(0, TEXT_LIMIT);
}

/** `["key:value", ...]` から crs-node の値を取り出す（Prowler の `unroll_dict_to_list` の形）。 */
function nodeTagOf(labels: readonly string[] | undefined): string | undefined {
  for (const l of labels ?? []) {
    const i = l.indexOf(':');
    if (i < 0) continue;
    if (l.slice(0, i).trim() === NODE_TAG_KEY) {
      const v = l.slice(i + 1).trim();
      return v === '' ? undefined : v.slice(0, TEXT_LIMIT);
    }
  }
  return undefined;
}

/** 報告に出す資源の表示名。名前があれば名前、無ければ uid（12 桁のアカウント ID は伏せる）。 */
export function resourceLabel(r: ProwlerResource): string {
  return (r.name ?? r.uid ?? '(名前なし)').replace(/\b\d{12}\b/g, '*');
}

export function parseProwlerOcsf(raw: unknown): ParseProwlerResult {
  const items = Array.isArray(raw) ? raw : raw && typeof raw === 'object' ? [raw] : undefined;
  if (!items) return { ok: false, error: 'Prowler の OCSF（*.ocsf.json）の形式ではありません（配列を期待）。' };

  const findings: NormalizedProwlerFinding[] = [];
  const skipped = { invalid: 0, muted: 0 };
  let productVersion: string | undefined;
  for (const item of items) {
    const p = FindingSchema.safeParse(item);
    if (!p.success) {
      skipped.invalid += 1;
      continue;
    }
    const f = p.data;
    const status = f.status_code.toUpperCase();
    if (status !== 'PASS' && status !== 'FAIL' && status !== 'MANUAL') {
      skipped.invalid += 1;
      continue;
    }
    if (f.status === 'Suppressed') {
      skipped.muted += 1;
      continue;
    }
    productVersion ??= clean(f.metadata.product?.version);
    findings.push({
      uid: clean(f.finding_info?.uid)?.replace(/\b\d{12}\b/g, '*'),
      observedAt: clean(f.time_dt),
      checkId: f.metadata.event_code,
      status,
      severity: f.severity,
      title: f.finding_info?.title?.slice(0, TEXT_LIMIT),
      resources: (f.resources ?? []).map((r) => ({
        uid: clean(r.uid),
        name: clean(r.name),
        type: r.type,
        service: r.group?.name,
        region: r.region,
        nodeTag: nodeTagOf(r.labels),
      })),
      categories: f.unmapped?.categories ?? [],
    });
  }
  if (findings.length === 0 && skipped.invalid === items.length && items.length > 0) {
    return { ok: false, error: 'Prowler の OCSF の検査結果として読める項目がありませんでした。' };
  }
  return { ok: true, findings, productVersion, skipped };
}
