import { formatIpv6, normalizeIdentifierValue, parseIpv4, parseIpv6 } from './identifierSchemes';

/**
 * サービスの担当範囲（`projectMeta.serviceScope`）の正規化と包含判定（docs/identifiers.md §5.2、docs/org-view.md §2.3）。
 * 範囲は識別子ではなく「どれを含むか」の宣言。OSS の `asm-reconcile`・`export-scope` と Enterprise の
 * 「持ち主のいない範囲」の計算が同じ関数を使う。DOM にも Node にも依存しない純粋関数。
 */

export const SERVICE_SCOPE_KINDS = ['host', 'domain', 'cidr', 'url-prefix'] as const;
export type ServiceScopeKind = (typeof SERVICE_SCOPE_KINDS)[number];

export interface ServiceScopeEntry {
  kind: ServiceScopeKind;
  /** 入力のまま保存する（比べるときに正規化する）。 */
  value: string;
  note?: string;
}

/** 範囲に含まれるかを調べる相手（観測した資産等）。持っている項目だけ渡す。 */
export interface ScopeTarget {
  host?: string;
  ip?: string;
  url?: string;
}

const LABEL_RE = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/;

function normalizeHost(value: string): string | undefined {
  const h = normalizeIdentifierValue('fqdn', value.trim());
  if (h.length === 0 || h.length > 253) return undefined;
  return h.split('.').every((l) => LABEL_RE.test(l)) ? h : undefined;
}

interface ParsedIp {
  /** 4（IPv4 のオクテット）か 16（IPv6 のグループ）ビットずつの値。 */
  groups: number[];
  bits: 8 | 16;
}

function parseIp(value: string): ParsedIp | undefined {
  const bare = value.trim().replace(/^\[(.*)\]$/, '$1').replace(/%.*$/, '');
  const v4 = parseIpv4(bare);
  if (v4) return { groups: v4, bits: 8 };
  const v6 = parseIpv6(bare);
  return v6 ? { groups: v6, bits: 16 } : undefined;
}

function formatIp(ip: ParsedIp): string {
  return ip.bits === 8 ? ip.groups.join('.') : formatIpv6(ip.groups);
}

/** 先頭 `prefix` ビットだけを残す。 */
function maskIp(ip: ParsedIp, prefix: number): number[] {
  return ip.groups.map((g, i) => {
    const keep = Math.max(0, Math.min(ip.bits, prefix - i * ip.bits));
    const mask = keep === 0 ? 0 : ((0xffff << (ip.bits - keep)) & ((1 << ip.bits) - 1));
    return g & mask;
  });
}

interface ParsedCidr {
  ip: ParsedIp;
  prefix: number;
}

function parseCidr(value: string): ParsedCidr | undefined {
  const m = /^([^/]+)(?:\/(\d{1,3}))?$/.exec(value.trim());
  if (!m) return undefined;
  const ip = parseIp(m[1]);
  if (!ip) return undefined;
  const max = ip.groups.length * ip.bits;
  const prefix = m[2] === undefined ? max : Number(m[2]);
  if (prefix > max) return undefined;
  return { ip: { ...ip, groups: maskIp(ip, prefix) }, prefix };
}

interface ParsedUrl {
  origin: string;
  host: string;
  path: string;
}

function parseUrl(value: string): ParsedUrl | undefined {
  const n = normalizeIdentifierValue('url', value.trim());
  const m = /^(https?):\/\/(?:[^@/?#]*@)?([^/?#]+)([^?#]*)/.exec(n);
  if (!m) return undefined;
  const hostPort = m[2];
  // `[IPv6]:port` と `host:port` からホストの部分を取り出す
  const bare = /^\[(.*)\](?::\d+)?$/.exec(hostPort)?.[1] ?? hostPort.replace(/:\d+$/, '');
  const ip = parseIp(bare);
  const host = ip ? formatIp(ip) : normalizeHost(bare);
  if (!host) return undefined;
  const path = m[3].replace(/\/+$/, '') || '/';
  return { origin: `${m[1]}://${hostPort}`, host, path };
}

/**
 * 範囲の値を正規化する。解釈できない値は undefined（入力欄で受け付けない）。
 * host・domain は小文字で末尾のドットを除く（domain は先頭の `*.` も除く）。cidr はネットワーク部だけを残す。
 * url-prefix は scheme・ホストを小文字にし、既定のポート・クエリ・フラグメント・末尾の `/` を除く。
 */
export function normalizeScopeValue(kind: ServiceScopeKind, value: string): string | undefined {
  switch (kind) {
    case 'host':
      return normalizeHost(value);
    case 'domain':
      return normalizeHost(value.trim().replace(/^\*\./, ''));
    case 'cidr': {
      const c = parseCidr(value);
      return c ? `${formatIp(c.ip)}/${c.prefix}` : undefined;
    }
    case 'url-prefix': {
      const u = parseUrl(value);
      return u ? `${u.origin}${u.path === '/' ? '/' : u.path}` : undefined;
    }
  }
}

function hostOf(target: ScopeTarget): string | undefined {
  if (target.host) {
    const ip = parseIp(target.host);
    return ip ? formatIp(ip) : normalizeHost(target.host);
  }
  return target.url ? parseUrl(target.url)?.host : undefined;
}

/** 範囲 1 件が相手を含むか。範囲の値が解釈できなければ false。 */
export function scopeContains(entry: ServiceScopeEntry, target: ScopeTarget): boolean {
  switch (entry.kind) {
    case 'host': {
      const v = normalizeHost(entry.value);
      return v !== undefined && hostOf(target) === v;
    }
    case 'domain': {
      const v = normalizeScopeValue('domain', entry.value);
      const h = hostOf(target);
      return v !== undefined && h !== undefined && (h === v || h.endsWith(`.${v}`));
    }
    case 'cidr': {
      const c = parseCidr(entry.value);
      const ip = target.ip ? parseIp(target.ip) : undefined;
      if (!c || !ip || ip.bits !== c.ip.bits) return false;
      const masked = maskIp(ip, c.prefix);
      return masked.every((g, i) => g === c.ip.groups[i]);
    }
    case 'url-prefix': {
      const p = parseUrl(entry.value);
      if (!p) return false;
      if (!target.url) return hostOf(target) === p.host;
      const u = parseUrl(target.url);
      if (!u || u.origin !== p.origin) return false;
      return p.path === '/' || u.path === p.path || u.path.startsWith(`${p.path}/`);
    }
  }
}

/** 担当範囲のうち、相手を含む最初の 1 件。無ければ undefined。 */
export function matchServiceScope(
  entries: readonly ServiceScopeEntry[],
  target: ScopeTarget,
): ServiceScopeEntry | undefined {
  return entries.find((e) => scopeContains(e, target));
}
