import { z } from 'zod';
import type { LayerData } from '../../core/model/types';
import { getLocale, translate, type TranslationKey } from '../../i18n';
import { asmToLayer, type ExposedService } from '../asm-import/asmToLayer';

/**
 * Shodan の書き出し（`shodan download` / `host --save` の JSON Lines、JSON 配列、ホスト API の `data` 配列）から、
 * インターネットに露出したサービスの構成図の下書きを作る。
 *
 * 方針（`kong-import` / `conjur-import` と同じ）：
 * - **本文を読まない。** `data`（バナー本文）・`http.html` / `headers` / `title`・`ssl` の中身・`opts`・`location`・`org`・`asn` は
 *   読まない（Zod の object は未知キーを捨てるので、スキーマに書いたものしか手元に残らない）。
 *   使うのは ip_str・port・transport・hostnames・product・version・tags・vulns のキー・http/ssl の有無・http.waf・
 *   timestamp・_shodan.module だけ。
 * - **脅威の知識を持たない。** サービスをノード型・攻撃面属性・線の属性に置き換えるだけで、判定は既存のルールに任せる。
 *   外から確かめられない値（認証）は保守的な既定にし、利用者が直す前提。
 *
 * 対応：
 * - 1 サービス（ip:port/transport）＝ 1 ノード。同じサービスが複数あれば timestamp が最新のバナーを採る
 * - ics タグ → IOT（OT/ICS 用のステンシルが無い旨を説明欄に書く）／ ai タグ・Ollama 等 → LLM ／ database タグ・DB ポート → DATA_STORE ／
 *   vpn タグ・リモートアクセス用ポート → GATEWAY ／ HTTP → FRONT_END_SERVER ／ それ以外 → PROCESS
 * - 攻撃者 → 各サービスの線（Internet・TLS の有無はバナーの ssl で判定）。WAF が報告されていれば hasWafProtection
 * - vulns は CVE ID だけを「Shodan が報告した CVE（未検証）」として説明欄に書く（CVSS・詳細は載せない）
 */

export interface ShodanImportSummary {
  banners: number;
  services: number;
  hosts: number;
  cves: number;
  skipped: number;
  truncated: number;
}

export type ShodanImportResult =
  | { ok: true; name: string; layer: LayerData; summary: ShodanImportSummary }
  | { ok: false; error: string };

const str = z.string().optional().catch(undefined);
const BannerSchema = z.object({
  ip_str: z.string(),
  port: z.number().int(),
  transport: str,
  hostnames: z.array(z.string()).optional().catch(undefined),
  product: str,
  version: str,
  tags: z.array(z.string()).optional().catch(undefined),
  vulns: z.union([z.record(z.string(), z.unknown()), z.array(z.string())]).optional().catch(undefined),
  http: z.object({ waf: str }).optional().catch(undefined),
  ssl: z.object({}).optional().catch(undefined),
  timestamp: str,
  _shodan: z.object({ module: str }).optional().catch(undefined),
});
type Banner = z.infer<typeof BannerSchema>;

const cveIds = (b: Banner) =>
  (Array.isArray(b.vulns) ? b.vulns : Object.keys(b.vulns ?? {})).map((id) => id.replace(/^!/, '')).filter(Boolean);

/** 入力テキストから、バナー候補（未検証の値）の配列を取り出す。JSON 配列・ホストの data 配列・JSON Lines に対応。 */
function candidates(text: string): unknown[] {
  try {
    const whole: unknown = JSON.parse(text);
    if (Array.isArray(whole)) return whole;
    if (whole && typeof whole === 'object' && Array.isArray((whole as { data?: unknown }).data)) {
      return (whole as { data: unknown[] }).data;
    }
  } catch {
    // 全体が 1 つの JSON でなければ JSON Lines として読む
  }
  return text
    .split(/\r?\n/)
    .filter((line) => line.trim() !== '')
    .map((line) => {
      try {
        return JSON.parse(line) as unknown;
      } catch {
        return undefined;
      }
    });
}

/** バナーを共通の `ExposedService` に読み替える。 */
function toService(b: Banner): ExposedService {
  return {
    ip: b.ip_str,
    port: b.port,
    transport: b.transport,
    hostnames: b.hostnames,
    product: b.product,
    version: b.version,
    tags: b.tags,
    cves: cveIds(b),
    isHttp: !!b.http || !!b._shodan?.module?.startsWith('http'),
    hasTls: !!b.ssl,
    hasWaf: !!b.http?.waf,
    observedAt: b.timestamp,
    serviceHint: b._shodan?.module,
  };
}

export function shodanToLayer(text: string): ShodanImportResult {
  const locale = getLocale();
  const t = (key: TranslationKey, params?: Record<string, string | number>) => translate(key, locale, params);

  let banners = 0;
  let skipped = 0;
  const services: ExposedService[] = [];
  for (const raw of candidates(text)) {
    const parsed = BannerSchema.safeParse(raw);
    if (!parsed.success) {
      skipped++;
      continue;
    }
    banners++;
    services.push(toService(parsed.data));
  }
  if (services.length === 0) return { ok: false, error: t('shodan.error.noBanners') };

  const { layer, summary } = asmToLayer(services, { prefix: 'shodan' });
  return {
    ok: true,
    name: t('shodan.templateName'),
    layer,
    summary: { banners, ...summary, skipped },
  };
}
