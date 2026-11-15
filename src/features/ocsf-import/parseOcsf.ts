import { z } from 'zod';
import { NODE_TAG_KEY, stripUrlSecrets } from '../prowler-import/parseProwlerOcsf';

/**
 * OCSF（Open Cybersecurity Schema Framework）の検査結果を、製品に依らず正規化する（plan §2.149）。
 * 対象のクラス：Detection Finding（2004）・Compliance Finding（2003）。それ以外のクラスは数えて読まない。
 *
 * 状態の判定（FAIL だけを指摘にする。PASS・MANUAL は数えるだけ）
 * - `status_code` が PASS・FAIL・MANUAL ならそれ（Prowler 等）
 * - Compliance Finding は `compliance.status_id`（1 Pass・2 Warning・3 Fail）、無ければ `compliance.status`
 * - Detection Finding は検知そのものなので FAIL
 * - `status_id` が 3 Suppressed・4 Resolved・5 Archived のものは読まない
 *
 * 検査 ID：`metadata.event_code` → `finding_info.analytic.uid` → `analytic.name` → `compliance.control` → `finding_info.title`
 * 読まないもの：`resources[].data`（設定全体）・`owner`・説明文・修正手順・`unmapped`。リソースの ID は完全な形で持つ。
 * ファイル I/O はしない。
 */

export const OCSF_CLASS = { complianceFinding: 2003, detectionFinding: 2004 } as const;

export type OcsfStatus = 'PASS' | 'FAIL' | 'MANUAL';

export interface OcsfResource {
  uid?: string;
  name?: string;
  type?: string;
  region?: string;
  service?: string;
  provider?: string;
  account?: string;
  /** タグ・ラベル `crs-node` の値（図のノード ID または C 番号）。 */
  nodeTag?: string;
}

export interface OcsfFinding {
  product: string;
  productVersion?: string;
  classUid: number;
  checkId: string;
  status: OcsfStatus;
  severity?: string;
  title?: string;
  uid?: string;
  observedAt?: string;
  resources: OcsfResource[];
}

export interface ParsedOcsf {
  findings: OcsfFinding[];
  skipped: {
    /** 形が読めない・検査 ID が無い・状態が分からないもの。 */
    invalid: number;
    /** 対象外のクラス。 */
    otherClass: number;
    /** 抑止・解決済み・保管済み。 */
    closed: number;
  };
}

export type ParseOcsfResult = ({ ok: true } & ParsedOcsf) | { ok: false; error: string };

const TEXT_LIMIT = 200;
const str = z.string().optional().catch(undefined);
const num = z.number().optional().catch(undefined);

const ResourceSchema = z
  .object({
    uid: str,
    name: str,
    type: str,
    region: str,
    group: z.object({ name: str }).optional().catch(undefined),
    labels: z.array(z.string()).optional().catch(undefined),
    tags: z.array(z.object({ name: str, value: str })).optional().catch(undefined),
  })
  .passthrough();

const FindingSchema = z
  .object({
    class_uid: z.number(),
    metadata: z
      .object({
        event_code: str,
        product: z.object({ name: str, vendor_name: str, version: str }).passthrough().optional().catch(undefined),
      })
      .passthrough(),
    time_dt: str,
    status_code: str,
    status_id: num,
    severity: str,
    finding_info: z
      .object({ uid: str, title: str, analytic: z.object({ uid: str, name: str }).passthrough().optional().catch(undefined) })
      .passthrough()
      .optional()
      .catch(undefined),
    compliance: z.object({ status: str, status_id: num, control: str }).passthrough().optional().catch(undefined),
    cloud: z
      .object({ provider: str, region: str, account: z.object({ uid: str }).passthrough().optional().catch(undefined) })
      .passthrough()
      .optional()
      .catch(undefined),
    resources: z.array(ResourceSchema).optional().catch(undefined),
  })
  .passthrough();

function clean(value: string | undefined, limit = TEXT_LIMIT): string | undefined {
  if (value === undefined || value.trim() === '') return undefined;
  return stripUrlSecrets(value.trim()).slice(0, limit);
}

function nodeTagOf(r: z.infer<typeof ResourceSchema>): string | undefined {
  for (const t of r.tags ?? []) if (t.name?.trim() === NODE_TAG_KEY && t.value?.trim()) return t.value.trim().slice(0, TEXT_LIMIT);
  for (const l of r.labels ?? []) {
    const i = l.indexOf(':');
    if (i > 0 && l.slice(0, i).trim() === NODE_TAG_KEY && l.slice(i + 1).trim()) return l.slice(i + 1).trim().slice(0, TEXT_LIMIT);
  }
  return undefined;
}

function statusOf(f: z.infer<typeof FindingSchema>): OcsfStatus | undefined {
  const code = f.status_code?.toUpperCase();
  if (code === 'PASS' || code === 'FAIL' || code === 'MANUAL') return code;
  if (f.class_uid === OCSF_CLASS.detectionFinding) return 'FAIL';
  const c = f.compliance;
  const id = c?.status_id ?? { pass: 1, warning: 2, fail: 3 }[c?.status?.toLowerCase() ?? ''];
  return id === 1 ? 'PASS' : id === 2 ? 'MANUAL' : id === 3 ? 'FAIL' : undefined;
}

export function parseOcsf(raw: unknown): ParseOcsfResult {
  const items = Array.isArray(raw) ? raw : raw && typeof raw === 'object' ? [raw] : undefined;
  if (!items) return { ok: false, error: 'OCSF の検査結果（JSON の配列）の形式ではありません。' };

  const findings: OcsfFinding[] = [];
  const skipped = { invalid: 0, otherClass: 0, closed: 0 };
  for (const item of items) {
    const p = FindingSchema.safeParse(item);
    if (!p.success) {
      skipped.invalid += 1;
      continue;
    }
    const f = p.data;
    if (f.class_uid !== OCSF_CLASS.complianceFinding && f.class_uid !== OCSF_CLASS.detectionFinding) {
      skipped.otherClass += 1;
      continue;
    }
    if (f.status_id === 3 || f.status_id === 4 || f.status_id === 5) {
      skipped.closed += 1;
      continue;
    }
    const checkId = clean(
      f.metadata.event_code ?? f.finding_info?.analytic?.uid ?? f.finding_info?.analytic?.name ?? f.compliance?.control ?? f.finding_info?.title,
    );
    const status = statusOf(f);
    if (!checkId || !status) {
      skipped.invalid += 1;
      continue;
    }
    const provider = clean(f.cloud?.provider, 50);
    const account = clean(f.cloud?.account?.uid);
    findings.push({
      product: clean(f.metadata.product?.name, 100) ?? clean(f.metadata.product?.vendor_name, 100) ?? 'OCSF',
      ...(clean(f.metadata.product?.version, 50) ? { productVersion: clean(f.metadata.product?.version, 50) } : {}),
      classUid: f.class_uid,
      checkId,
      status,
      ...(f.severity ? { severity: f.severity.slice(0, 50) } : {}),
      ...(clean(f.finding_info?.title) ? { title: clean(f.finding_info?.title) } : {}),
      ...(clean(f.finding_info?.uid, 500) ? { uid: clean(f.finding_info?.uid, 500) } : {}),
      ...(clean(f.time_dt, 40) ? { observedAt: clean(f.time_dt, 40) } : {}),
      resources: (f.resources ?? []).map((r) => {
        const out: OcsfResource = {
          uid: clean(r.uid, 1000),
          name: clean(r.name),
          type: clean(r.type),
          region: clean(r.region ?? f.cloud?.region, 100),
          service: clean(r.group?.name, 100),
          provider,
          account,
          nodeTag: nodeTagOf(r),
        };
        return Object.fromEntries(Object.entries(out).filter(([, v]) => v !== undefined)) as OcsfResource;
      }),
    });
  }
  if (findings.length === 0 && items.length > 0 && skipped.invalid + skipped.otherClass + skipped.closed === items.length && skipped.invalid > 0) {
    return { ok: false, error: 'OCSF の検査結果（Detection Finding・Compliance Finding）として読める項目がありませんでした。' };
  }
  return { ok: true, findings, skipped };
}
