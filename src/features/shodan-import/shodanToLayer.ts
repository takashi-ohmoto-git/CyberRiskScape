import { z } from 'zod';
import type { DiagramBoundary, DiagramEdge, DiagramNode, LayerData } from '../../core/model/types';
import { getLocale, translate, type TranslationKey } from '../../i18n';

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

const MAX_SERVICES = 300;
const MAX_CVES = 10;
const PER_COLUMN = 4;

const ICS_TAG = 'ics';
const LLM_PRODUCT = /ollama|vllm|llama\.cpp|text-generation|localai/i;
const LLM_PORTS = new Set([11434]);
const DATA_STORE_PORTS = new Set([1433, 1521, 3306, 5432, 5984, 6379, 7474, 9042, 9200, 9300, 11211, 27017]);
const REMOTE_ACCESS_PORTS = new Set([22, 23, 445, 3389, 5900, 5901, 5902, 5903, 5938, 5985, 5986]);
const HTTP_PORTS = new Set([80, 443, 8080, 8443]);
/** 線のラベルに使う、リモートアクセス用ポートの通称。 */
const PORT_NAMES: Record<number, string> = {
  22: 'SSH',
  23: 'Telnet',
  445: 'SMB',
  3389: 'RDP',
  5900: 'VNC',
  5901: 'VNC',
  5902: 'VNC',
  5903: 'VNC',
  5938: 'TeamViewer',
  5985: 'WinRM',
  5986: 'WinRM',
};

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

const safeId = (s: string) => s.replace(/[^\w-]/g, '_');
const transportOf = (b: Banner) => b.transport || 'tcp';
const keyOf = (b: Banner) => `${b.ip_str}:${b.port}/${transportOf(b)}`;
const cveIds = (b: Banner) =>
  (Array.isArray(b.vulns) ? b.vulns : Object.keys(b.vulns ?? {})).map((id) => id.replace(/^!/, '')).filter(Boolean);

/** IPv4 は数値順、それ以外は文字列順（IPv4 が先）。 */
function compareIp(a: string, b: string): number {
  const v4 = (s: string) => (/^\d{1,3}(\.\d{1,3}){3}$/.test(s) ? s.split('.').map(Number) : null);
  const pa = v4(a);
  const pb = v4(b);
  if (pa && pb) return pa[0] - pb[0] || pa[1] - pb[1] || pa[2] - pb[2] || pa[3] - pb[3];
  if (pa) return -1;
  if (pb) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

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

function classify(b: Banner): DiagramNode['type'] {
  const tags = b.tags ?? [];
  const product = b.product ?? '';
  if (tags.includes(ICS_TAG)) return 'IOT';
  if (tags.includes('ai') || LLM_PRODUCT.test(product) || LLM_PORTS.has(b.port)) return 'LLM';
  if (tags.includes('database') || DATA_STORE_PORTS.has(b.port)) return 'DATA_STORE';
  if (tags.includes('vpn')) return 'GATEWAY';
  if (REMOTE_ACCESS_PORTS.has(b.port)) return 'GATEWAY';
  if (b.http || b._shodan?.module?.startsWith('http') || HTTP_PORTS.has(b.port)) return 'FRONT_END_SERVER';
  return 'PROCESS';
}

export function shodanToLayer(text: string): ShodanImportResult {
  const locale = getLocale();
  const t = (key: TranslationKey, params?: Record<string, string | number>) => translate(key, locale, params);

  let banners = 0;
  let skipped = 0;
  const latest = new Map<string, Banner>();
  for (const raw of candidates(text)) {
    const parsed = BannerSchema.safeParse(raw);
    if (!parsed.success) {
      skipped++;
      continue;
    }
    banners++;
    const b = parsed.data;
    const prev = latest.get(keyOf(b));
    if (!prev || (b.timestamp ?? '') >= (prev.timestamp ?? '')) latest.set(keyOf(b), b);
  }
  if (latest.size === 0) return { ok: false, error: t('shodan.error.noBanners') };

  const sorted = [...latest.values()].sort((a, b) => compareIp(a.ip_str, b.ip_str) || a.port - b.port || (transportOf(a) < transportOf(b) ? -1 : 1));
  const services = sorted.slice(0, MAX_SERVICES);
  const truncated = sorted.length - services.length;

  const nodes: DiagramNode[] = [];
  const edges: DiagramEdge[] = [];
  const ROW = 180;
  const COLW = 260;
  const TOP = 120;
  const SERVICE_X = 400;

  // 配置：ホスト順・ポート順に上から PER_COLUMN 個ずつ縦に並べて右の列へ折り返す。攻撃者（左）からの線が手前の列の
  // ノードを貫かないよう、奇数列は半段ずらす。
  let row = 0;
  let col = 0;
  const allCves = new Set<string>();
  services.forEach((b) => {
    if (row === PER_COLUMN) {
      col++;
      row = 0;
    }

    const type = classify(b);
    const transport = transportOf(b);
    const suffix = `${safeId(b.ip_str)}-${b.port}-${transport}`;
    const product = b.product?.trim();
    const cves = [...new Set(cveIds(b))].sort();
    cves.forEach((c) => allCves.add(c));
    const shown = cves.slice(0, MAX_CVES).join(', ');
    const date = b.timestamp?.match(/^\d{4}-\d{2}-\d{2}/)?.[0];
    const description = [
      type === 'IOT' && (b.tags ?? []).includes(ICS_TAG) ? t('shodan.desc.ics') : '',
      t('shodan.desc.ip', { ip: b.ip_str }),
      t('shodan.desc.port', { port: b.port, transport }),
      product ? t('shodan.desc.product', { product: [product, b.version].filter(Boolean).join(' ') }) : '',
      b.tags?.length ? t('shodan.desc.tags', { tags: b.tags.join(', ') }) : '',
      date ? t('shodan.desc.observed', { date }) : '',
      cves.length
        ? t('shodan.desc.cves', {
            ids: cves.length > MAX_CVES ? `${shown} ${t('shodan.desc.more', { n: cves.length - MAX_CVES })}` : shown,
          })
        : '',
    ]
      .filter(Boolean)
      .join(' ／ ');

    const exposes = type === 'FRONT_END_SERVER' || type === 'GATEWAY';
    const id = `shodan-${suffix}`;
    nodes.push({
      id,
      type,
      x: SERVICE_X + col * COLW,
      y: TOP + row * ROW + (col % 2) * (ROW / 2),
      label: `${b.hostnames?.[0] ?? b.ip_str}:${b.port}${product ? ` ${product}` : ''}`,
      description,
      ...(exposes
        ? { attackSurface: { hasGlobalIp: true, ...(b.http?.waf ? { hasWafProtection: true } : {}) } }
        : {}),
    });
    row++;

    const serviceName = `${PORT_NAMES[b.port] ?? product ?? b._shodan?.module ?? transport} ${b.port}/${transport}`;
    edges.push({
      id: `shodan-e-${suffix}`,
      source: 'shodan-actor',
      target: id,
      network: 'Internet',
      encryption: b.ssl ? 'TLS' : 'Plain',
      // 外から認証の有無は確かめられないため保守的に Password とする（利用者が実態に合わせて直す）。
      auth: 'Password',
      dataFlow: 'bidirectional',
      dataFlowName: serviceName.slice(0, 80),
    });
  });

  const ys = nodes.map((n) => n.y);
  nodes.unshift({
    id: 'shodan-actor',
    type: 'THREAT_ACTOR',
    x: 60,
    y: (Math.min(...ys) + Math.max(...ys)) / 2,
    label: t('shodan.node.actor'),
    threatActorType: 'CyberCriminals',
  });

  // 境界：攻撃者を Internet（RECT）で、露出サービス全体を Public Area（ROUNDED・Internet）で囲む。
  const PAD = 40;
  const box = (id: string, members: DiagramNode[], type: DiagramBoundary['type'], extra: Partial<DiagramBoundary> = {}): DiagramBoundary => {
    const x = Math.min(...members.map((n) => n.x)) - PAD;
    const y = Math.min(...members.map((n) => n.y)) - PAD - 30;
    return {
      id,
      type,
      x,
      y,
      width: Math.max(...members.map((n) => n.x + 128)) + PAD - x,
      height: Math.max(...members.map((n) => n.y + 96)) + PAD - y,
      trustLevel: 'Internet',
      ...extra,
    };
  };
  const boundaries = [
    box('shodan-b-internet', nodes.slice(0, 1), 'RECT'),
    box('shodan-b-exposed', nodes.slice(1), 'ROUNDED', { macroTrust: 'Public Area' }),
  ];

  return {
    ok: true,
    name: t('shodan.templateName'),
    layer: { nodes, edges, boundaries, annotations: [] },
    summary: {
      banners,
      services: services.length,
      hosts: new Set(services.map((b) => b.ip_str)).size,
      cves: allCves.size,
      skipped,
      truncated,
    },
  };
}
