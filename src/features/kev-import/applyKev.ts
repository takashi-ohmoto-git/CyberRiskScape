import { z } from 'zod';
import type { Finding, FindingKev } from '../../core/model/types';

/**
 * CISA KEV（Known Exploited Vulnerabilities）カタログの照合（docs/attack-tree-analysis.md §12）。
 * 利用者が渡したカタログ JSON を読み、指摘の CVE 識別子（scheme 'cve'）と突き合わせて `kev` の印を付け外しする。
 * カタログは同梱せず、ネットワークにも出ない。KEV に載っている＝CISA が悪用を確認した事実。
 */

const KevEntrySchema = z.object({
  cveID: z.string().min(1).max(50),
  dateAdded: z.string().max(40).optional(),
  dueDate: z.string().max(40).optional(),
  knownRansomwareCampaignUse: z.string().max(40).optional(),
});

const KevCatalogSchema = z.object({
  catalogVersion: z.string().max(50).optional(),
  vulnerabilities: z.array(KevEntrySchema).max(100_000),
});

export interface KevCatalog {
  catalogVersion?: string;
  entries: Map<string, FindingKev>;
}

export type ParseKevResult = { ok: true; catalog: KevCatalog } | { ok: false; error: string };

/** KEV カタログ JSON を検証して CVE ID（大文字）→ 事実の表にする。 */
export function parseKevCatalog(raw: unknown): ParseKevResult {
  const parsed = KevCatalogSchema.safeParse(raw);
  if (!parsed.success) {
    return { ok: false, error: 'KEV カタログの形式が不正です（vulnerabilities[] の cveID が必要です）。' };
  }
  const { catalogVersion, vulnerabilities } = parsed.data;
  const entries = new Map<string, FindingKev>();
  for (const v of vulnerabilities) {
    entries.set(v.cveID.trim().toUpperCase(), {
      ...(v.dateAdded ? { dateAdded: v.dateAdded } : {}),
      ...(v.dueDate ? { dueDate: v.dueDate } : {}),
      ...(v.knownRansomwareCampaignUse !== undefined
        ? { ransomware: v.knownRansomwareCampaignUse.toLowerCase() === 'known' }
        : {}),
      ...(catalogVersion ? { catalogVersion } : {}),
    });
  }
  return { ok: true, catalog: { ...(catalogVersion ? { catalogVersion } : {}), entries } };
}

export interface KevApplyResult {
  findings: Finding[];
  /** CVE の識別子を持つ指摘の数（照合の対象）。 */
  checked: number;
  /** 今回 kev の印が付いている指摘の数。 */
  marked: number;
  /** 印を外した指摘の数（前回は載っていたが、今回のカタログに無い）。 */
  cleared: number;
}

/** 指摘に kev を付け外しした一覧を返す純粋関数。CVE を持たない指摘は触らない。 */
export function applyKev(findings: readonly Finding[], catalog: KevCatalog): KevApplyResult {
  let checked = 0;
  let marked = 0;
  let cleared = 0;
  const out = findings.map((f) => {
    const cves = f.identifiers.filter((i) => i.scheme.toLowerCase() === 'cve');
    if (cves.length === 0) return f;
    checked++;
    const hit = cves.map((i) => catalog.entries.get(i.value.trim().toUpperCase())).find((e) => e !== undefined);
    if (hit) {
      marked++;
      return { ...f, kev: hit };
    }
    if (f.kev) {
      cleared++;
      const { kev: _kev, ...rest } = f;
      return rest;
    }
    return f;
  });
  return { findings: out, checked, marked, cleared };
}
