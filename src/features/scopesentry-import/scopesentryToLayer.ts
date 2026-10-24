import { z } from 'zod';
import type { LayerData } from '../../core/model/types';
import { getLocale, translate, type TranslationKey } from '../../i18n';
import { asmToLayer, LLM_PRODUCT, type ExposedService, type ExtraNode } from '../asm-import/asmToLayer';

/**
 * ScopeSentry（自前ホストの OSS ASM）の書き出し・API/MCP の応答から、インターネットに露出したサービスの
 * 構成図の下書きを作る。共通部分は `asmToLayer`（Shodan と共用）。ここは入力の読み替えだけを担う。
 *
 * 入力（`scopesentryToLayer` はテキスト、`scopesentryRecordsToLayer` は取り出し済みのレコード。CLI の MCP 取得も後者を使う）：
 * - 画面の Export の JSON（`json.Encoder` の JSON Lines。1 行 1 件）、JSON 配列、API/MCP の `{ "list": [...] }`
 * - レコードは混在してよく、キーで種類を判定する（vulnerability → 乗っ取り → asset の順）
 *   - vulnerability：vulnid / vulname / vulnerability のいずれかを持つ
 *   - 乗っ取り（SubdomainTakerResult）：cname / input を持つ、または host と value を持ち ip・port を持たない
 *   - asset：port と、ip または host（API は domain）を持つ
 * - 書き出しは MongoDB の項目名、API/MCP は別名（domain=host・products=technologies・status=statuscode・
 *   vulnerability=vulname・host=input・type=cname）なので両方を読む
 *
 * 方針：
 * - **本文を読まない。** body・rawheaders・banner・metadata・screenshot・iconcontent・request・response・hashes・jarm・
 *   title・matched は宣言しない（Zod の object は未知キーを捨てるので、スキーマに書いたものしか手元に残らない）。
 *   URL は脆弱性をノードに結びつける照合にだけ使い、図には出さない（userinfo・クエリは照合前に捨てる）。
 * - **脅威の知識を持たない。** 型の分類は `asmToLayer`、脅威の判定は既存ルールに任せる。
 * - 乗っ取りは rootDomain ごとに DNS_ZONE ノードを 1 つ置き、報告ホストを「未検証」として説明欄に書く。
 *   posture は未入力のまま（未入力＝悪い値と同じ扱いで、乗っ取りの脅威が出る）。線は引かない
 *   （DNS の乗っ取りは図上の接続ではなく名前の問題で、既存のサービスとの接続を ScopeSentry の結果から確定できないため）。
 */

const MAX_TECH = 8;
const MAX_TAKEOVER_HOSTS = 10;

export interface ScopesentryImportSummary {
  records: number;
  services: number;
  hosts: number;
  vulns: number;
  unmatchedVulns: number;
  takeovers: number;
  skipped: number;
  truncated: number;
}

export type ScopesentryImportResult =
  | { ok: true; name: string; layer: LayerData; summary: ScopesentryImportSummary }
  | { ok: false; error: string };

const str = z.string().optional().catch(undefined);
const strList = z.array(z.string()).optional().catch(undefined);
// 書き出しは port が文字列（"443"）、数値で来ても読む。
const portField = z.union([z.string(), z.number()]).optional().catch(undefined);

const AssetSchema = z.object({
  host: str,
  domain: str,
  ip: str,
  port: portField,
  service: str,
  type: str,
  url: str,
  technologies: strList,
  products: strList,
  webServer: str,
  cdnname: str,
  tls: z.unknown(),
  transport: str,
  version: str,
  tags: strList,
  time: str,
  lastScanTime: str,
});
const VulnSchema = z.object({
  url: str,
  vulnid: str,
  vulname: str,
  vulnerability: str,
  level: str,
});
const TakeoverSchema = z.object({
  input: str,
  host: str,
  value: str,
  cname: str,
  type: str,
  rootDomain: str,
});

const has = (o: Record<string, unknown>, k: string) => typeof o[k] === 'string' && o[k] !== '';

type Kind = 'vuln' | 'takeover' | 'asset' | undefined;
function kindOf(o: Record<string, unknown>): Kind {
  if (has(o, 'vulnid') || has(o, 'vulname') || has(o, 'vulnerability')) return 'vuln';
  const noAddr = o.ip === undefined && o.port === undefined;
  if (has(o, 'cname') || has(o, 'input') || (has(o, 'host') && has(o, 'value') && noAddr)) return 'takeover';
  if (o.port !== undefined && (has(o, 'ip') || has(o, 'host') || has(o, 'domain'))) return 'asset';
  return undefined;
}

/** 入力テキストから、レコード候補を取り出す。JSON 配列・`{ list }`・JSON Lines に対応。 */
function candidates(text: string): unknown[] {
  try {
    const whole: unknown = JSON.parse(text);
    if (Array.isArray(whole)) return whole;
    if (whole && typeof whole === 'object' && Array.isArray((whole as { list?: unknown }).list)) {
      return (whole as { list: unknown[] }).list;
    }
    return [whole];
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

const safeId = (s: string) => s.replace(/[^\w-]/g, '_');

/** URL から小文字のホストとポート（既定は scheme 由来）だけを取り出す。userinfo・クエリ・パスは使わない。 */
function hostPortOf(url: string): { host: string; port: number } | undefined {
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `http://${url}`);
    if (!u.hostname) return undefined;
    const port = u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : u.protocol === 'http:' ? 80 : NaN;
    return Number.isInteger(port) ? { host: u.hostname.toLowerCase().replace(/^\[|\]$/g, ''), port } : undefined;
  } catch {
    return undefined;
  }
}

/** 乗っ取りの対象ホストから根ドメイン（末尾 2 ラベル）を求める。 */
const rootOf = (host: string) => host.toLowerCase().replace(/\.$/, '').split('.').slice(-2).join('.');

const isTls = (v: unknown, url: string | undefined) =>
  (v !== undefined && v !== null && v !== false && v !== '' && v !== 'false') || /^https:/i.test(url ?? '');

interface Merged {
  service: ExposedService;
  hosts: Set<string>;
  techs: Set<string>;
  vulns: Set<string>;
}

/** 取り出し済みのレコード（JSON をパースした値）から図を作る。ファイルと MCP 取得の共通の入口。 */
export function scopesentryRecordsToLayer(records: unknown[]): ScopesentryImportResult {
  const locale = getLocale();
  const t = (key: TranslationKey, params?: Record<string, string | number>) => translate(key, locale, params);

  let skipped = 0;
  let recordCount = 0;
  const assets = new Map<string, Merged>();
  const vulns: z.infer<typeof VulnSchema>[] = [];
  const takeovers: z.infer<typeof TakeoverSchema>[] = [];

  for (const raw of records) {
    const o = raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, unknown>) : undefined;
    const kind = o ? kindOf(o) : undefined;
    if (!o || !kind) {
      skipped++;
      continue;
    }
    recordCount++;
    if (kind === 'vuln') {
      vulns.push(VulnSchema.parse(o));
    } else if (kind === 'takeover') {
      takeovers.push(TakeoverSchema.parse(o));
    } else {
      const a = AssetSchema.parse(o);
      const port = Number(a.port);
      const host = (a.host ?? a.domain)?.trim().toLowerCase();
      const ip = a.ip?.trim() || host;
      if (!Number.isInteger(port) || port < 1 || port > 65535 || !ip) {
        recordCount--;
        skipped++;
        continue;
      }
      const transport = a.transport || 'tcp';
      const key = `${ip}:${port}/${transport}`;
      const observedAt = a.lastScanTime || a.time;
      let m = assets.get(key);
      if (!m) {
        m = {
          service: { ip, port, transport, serviceHint: a.service },
          hosts: new Set(),
          techs: new Set(),
          vulns: new Set(),
        };
        assets.set(key, m);
      }
      const s = m.service;
      if (host && host !== ip) m.hosts.add(host);
      (a.technologies ?? a.products ?? []).forEach((x) => x.trim() && m.techs.add(x.trim()));
      if (a.webServer?.trim() && !s.product) s.product = a.webServer.trim();
      if (a.version && !s.version) s.version = a.version;
      s.isHttp ||= a.type === 'http' || !!a.url;
      s.hasTls ||= isTls(a.tls, a.url);
      s.tags = [...new Set([...(s.tags ?? []), ...(a.tags ?? [])])];
      if (a.cdnname?.trim()) s.notes = [...new Set([...(s.notes ?? []), t('scopesentry.desc.cdn', { name: a.cdnname.trim() })])];
      if ((observedAt ?? '') > (s.observedAt ?? '')) s.observedAt = observedAt;
    }
  }

  // 製品名：webServer が無ければ検出された技術の先頭（"Nginx:1.18.0" 形式なら名前とバージョンに分ける）。LLM 系の技術があれば優先する。
  for (const m of assets.values()) {
    const s = m.service;
    const techs = [...m.techs];
    if (!s.product || LLM_PRODUCT.test(techs.join(' '))) {
      const pick = techs.find((x) => LLM_PRODUCT.test(x)) ?? s.product ?? techs[0];
      if (pick) {
        const i = pick.lastIndexOf(':');
        s.product = i > 0 ? pick.slice(0, i) : pick;
        if (i > 0 && !s.version) s.version = pick.slice(i + 1);
      }
    }
    s.hostnames = [...m.hosts].sort();
    if (techs.length) {
      const shown = techs.slice(0, MAX_TECH).join(', ');
      s.notes = [...(s.notes ?? []), t('scopesentry.desc.tech', { names: techs.length > MAX_TECH ? `${shown} ...` : shown })];
    }
  }

  // 脆弱性：URL のホスト（ホスト名または IP）とポートが一致するサービスに結びつける。結びつかないものは件数だけ数える。
  let unmatchedVulns = 0;
  for (const v of vulns) {
    const hp = v.url ? hostPortOf(v.url) : undefined;
    const label = (v.vulnid || v.vulname || v.vulnerability || '').trim();
    const target = hp && [...assets.values()].find((m) => m.service.port === hp.port && (m.service.ip.toLowerCase() === hp.host || m.hosts.has(hp.host)));
    if (!target || !label) {
      unmatchedVulns++;
      continue;
    }
    target.vulns.add(v.level?.trim() ? `${label} (${v.level.trim()})` : label);
  }
  for (const m of assets.values()) m.service.cves = [...m.vulns];

  // サブドメイン乗っ取り：根ドメインごとに DNS_ZONE を 1 つ。
  const zones = new Map<string, Set<string>>();
  for (const r of takeovers) {
    const host = (r.input ?? r.host)?.trim().toLowerCase();
    if (!host) {
      recordCount--;
      skipped++;
      continue;
    }
    const cname = r.cname ?? r.type;
    const detail = [cname?.trim(), r.value?.trim()].filter(Boolean);
    const entry = detail.length ? `${host} → ${detail.join(' / ')}` : host;
    const root = r.rootDomain?.trim().toLowerCase() || rootOf(host);
    (zones.get(root) ?? zones.set(root, new Set()).get(root)!).add(entry);
  }
  const extraNodes: ExtraNode[] = [...zones.entries()]
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([domain, entries]) => {
      const list = [...entries].sort();
      const shown = list.slice(0, MAX_TAKEOVER_HOSTS).join(', ');
      return {
        id: `scopesentry-dns-${safeId(domain)}`,
        type: 'DNS_ZONE',
        label: t('scopesentry.node.dnsZone', { domain }),
        description: t('scopesentry.desc.takeover', {
          hosts: list.length > MAX_TAKEOVER_HOSTS ? `${shown} ${t('scopesentry.desc.more', { n: list.length - MAX_TAKEOVER_HOSTS })}` : shown,
        }),
      };
    });

  const services = [...assets.values()].map((m) => m.service);
  if (services.length === 0 && extraNodes.length === 0) return { ok: false, error: t('scopesentry.error.noRecords') };

  const { layer, summary } = asmToLayer(services, { prefix: 'scopesentry', extraNodes });
  return {
    ok: true,
    name: t('scopesentry.templateName'),
    layer,
    summary: {
      records: recordCount,
      services: summary.services,
      hosts: summary.hosts,
      vulns: summary.cves,
      unmatchedVulns,
      takeovers: [...zones.values()].reduce((n, e) => n + e.size, 0),
      skipped,
      truncated: summary.truncated,
    },
  };
}

export function scopesentryToLayer(text: string): ScopesentryImportResult {
  return scopesentryRecordsToLayer(candidates(text));
}
