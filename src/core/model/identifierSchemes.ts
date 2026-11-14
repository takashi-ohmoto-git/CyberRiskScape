import { stripPurl } from './purl';
import type { FindingIdentifier } from './types';

/**
 * 識別子（`identifiers` の `{ scheme, value }`）の種類の定義と、値の正規化・同一判定の鍵。
 * 指摘・資産・部品が共通で使う（docs/identifiers.md、docs/common-data-model.md §7.2 C）。
 *
 * scheme を新しく使うときは、ここに 1 行足す（何の種類か・どの範囲で一意かを決めてから使う）。
 * DOM にも Node にも依存しない純粋関数。
 */

/**
 * 識別子の種類。
 * - `identity`：同じものかを決める鍵（同じ値なら同じ資産・部品・脆弱性）
 * - `classification`：分類（同じ値でも別の個体。CWE・検査 ID など）
 * - `product`：取り込み元の製品の中だけで通じる ID
 * - `annotation`：識別子ではない付加情報（値が変わり得る。同一判定に使わない）
 */
export type IdentifierKind = 'identity' | 'classification' | 'product' | 'annotation';

/**
 * 一意な範囲。
 * - `global`：どの組織でも同じ値は同じものを指す
 * - `organization`：同じ組織（＋任意のネットワーク）の中でだけ同じものを指す
 * - `product`：取り込み元の製品の中でだけ通じる
 */
export type IdentifierScope = 'global' | 'organization' | 'product';

export interface IdentifierSchemeDef {
  kind: IdentifierKind;
  /** 一意な範囲。値によって変わるもの（IP）は関数で決める。 */
  scope: IdentifierScope | ((normalizedValue: string) => IdentifierScope);
  /** 値の正規化（前後の空白は呼び出し側で除いてある）。無ければそのまま。 */
  normalize?: (value: string) => string;
}

const lower = (v: string) => v.toLowerCase();
const upper = (v: string) => v.toUpperCase();
const hostName = (v: string) => v.toLowerCase().replace(/\.$/, '');

// ── IP ──

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function parseIpv4(v: string): number[] | undefined {
  const m = IPV4_RE.exec(v);
  if (!m) return undefined;
  const octets = m.slice(1).map(Number);
  return octets.every((o) => o <= 255) ? octets : undefined;
}

/** IPv6 を 8 個の 16 ビット値にする。解釈できなければ undefined。 */
function parseIpv6(v: string): number[] | undefined {
  let text = v;
  // 末尾が IPv4 の表記（::ffff:192.0.2.1）は 2 グループに直す
  const lastColon = text.lastIndexOf(':');
  const tail = parseIpv4(text.slice(lastColon + 1));
  if (tail) {
    const hex = (a: number, b: number) => ((a << 8) | b).toString(16);
    text = `${text.slice(0, lastColon + 1)}${hex(tail[0], tail[1])}:${hex(tail[2], tail[3])}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return undefined;
  const groups = (s: string) => (s === '' ? [] : s.split(':'));
  const head = groups(halves[0]);
  const rest = halves.length === 2 ? groups(halves[1]) : [];
  const missing = 8 - head.length - rest.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return undefined;
  const all = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...rest];
  if (!all.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return undefined;
  return all.map((g) => parseInt(g, 16));
}

/** RFC 5952 の表記にする（小文字・先頭の 0 を除く・最長の 0 の並びを `::` に）。 */
function formatIpv6(groups: number[]): string {
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i += 1;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = (gs: number[]) => gs.map((g) => g.toString(16)).join(':');
  if (bestLen < 2) return hex(groups);
  return `${hex(groups.slice(0, bestStart))}::${hex(groups.slice(bestStart + bestLen))}`;
}

/** IP の表記をそろえる。IPv4 は先頭の 0 を除き、IPv6 は RFC 5952 の表記にする。解釈できなければ小文字にするだけ。 */
function normalizeIp(value: string): string {
  const bare = value.replace(/^\[(.*)\]$/, '$1').replace(/%.*$/, '');
  const v4 = parseIpv4(bare);
  if (v4) return v4.join('.');
  const v6 = parseIpv6(bare);
  return v6 ? formatIpv6(v6) : bare.toLowerCase();
}

/**
 * 組織の外でも同じものを指す IP か。プライベート・ループバック・リンクローカル等は false
 * （別の組織・別のネットワークで同じ値が普通に出るため）。解釈できない値も false（安全側）。
 */
export function isGloballyUniqueIp(ip: string): boolean {
  const normalized = normalizeIp(ip.trim());
  const v4 = parseIpv4(normalized);
  if (v4) {
    const [a, b] = v4;
    return !(
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) || // 共有アドレス空間（CGNAT）
      (a === 169 && b === 254) || // リンクローカル
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      a >= 224 // マルチキャスト・予約
    );
  }
  const v6 = parseIpv6(normalized);
  if (!v6) return false;
  const first = v6[0];
  if (v6.slice(0, 7).every((g) => g === 0)) return false; // :: と ::1
  if ((first & 0xfe00) === 0xfc00) return false; // ユニークローカル fc00::/7
  if ((first & 0xffc0) === 0xfe80) return false; // リンクローカル fe80::/10
  if ((first & 0xff00) === 0xff00) return false; // マルチキャスト
  return true;
}

// ── そのほかの値の正規化 ──

const DEFAULT_PORTS: Record<string, string> = { http: '80', https: '443' };

/**
 * URL の scheme とホストを小文字にし、既定のポートとフラグメントを除く。`scheme://` の形でなければそのまま。
 * パスとクエリは触らない（符号化し直さないので、正規化で値が長くなることはない）。
 */
function normalizeUrl(value: string): string {
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)([^#]*)/i.exec(value);
  if (!m) return value;
  const scheme = m[1].toLowerCase();
  const at = m[2].lastIndexOf('@');
  const userinfo = m[2].slice(0, at + 1);
  let host = m[2].slice(at + 1).toLowerCase();
  const port = /:(\d+)$/.exec(host)?.[1];
  if (port !== undefined && port === DEFAULT_PORTS[scheme]) host = host.slice(0, -port.length - 1);
  return `${scheme}://${userinfo}${host}${m[3]}`;
}

/** purl の修飾子（?）とサブパス（#）を除き、`pkg:type` の部分を小文字にする（名前の大文字小文字は型によるので触らない）。 */
function normalizePurlIdentity(value: string): string {
  const stripped = stripPurl(value);
  const slash = stripped.indexOf('/');
  return slash < 0 ? stripped.toLowerCase() : `${stripped.slice(0, slash).toLowerCase()}${stripped.slice(slash)}`;
}

/** `CWE-079`・`cwe-79`・`79` を `79` にそろえる（保存している形）。 */
function normalizeCwe(value: string): string {
  const m = /^(?:cwe-?)?0*(\d+)$/i.exec(value);
  return m ? m[1] : value;
}

/** `GHSA-` は大文字、後ろは小文字（GitHub の表記）。 */
function normalizeGhsa(value: string): string {
  const m = /^ghsa-(.+)$/i.exec(value);
  return m ? `GHSA-${m[1].toLowerCase()}` : value;
}

/** ハッシュ値は小文字。`sha256:` の接頭辞が付いていれば除く。 */
function normalizeSha256(value: string): string {
  return value.toLowerCase().replace(/^sha-?256:/, '');
}

// ── 定義 ──

/**
 * 識別子の scheme の一覧。キーは小文字。
 * ここに無い scheme も保存・表示はできるが、同一判定には使わない（`identityKey` が undefined を返す）。
 */
export const IDENTIFIER_SCHEMES = {
  // 同じものかを決める鍵
  ip: { kind: 'identity', scope: (v) => (isGloballyUniqueIp(v) ? 'global' : 'organization'), normalize: normalizeIp },
  fqdn: { kind: 'identity', scope: 'global', normalize: hostName },
  hostname: { kind: 'identity', scope: 'organization', normalize: hostName },
  url: { kind: 'identity', scope: 'global', normalize: normalizeUrl },
  purl: { kind: 'identity', scope: 'global', normalize: normalizePurlIdentity },
  cpe: { kind: 'identity', scope: 'global', normalize: lower },
  'sha-256': { kind: 'identity', scope: 'global', normalize: normalizeSha256 },
  cve: { kind: 'identity', scope: 'global', normalize: upper },
  ghsa: { kind: 'identity', scope: 'global', normalize: normalizeGhsa },
  // 分類
  cwe: { kind: 'classification', scope: 'global', normalize: normalizeCwe },
  cce: { kind: 'classification', scope: 'global', normalize: upper },
  'prowler-check': { kind: 'classification', scope: 'global' },
  'oval-def': { kind: 'classification', scope: 'global' },
  'xccdf-rule': { kind: 'classification', scope: 'global' },
  rule: { kind: 'classification', scope: 'product' },
  'security-audit-attack-class': { kind: 'classification', scope: 'product' },
  // 取り込み元の製品の中だけで通じる ID
  'artex-asset-id': { kind: 'product', scope: 'product' },
  'cyberstrikeai-asset-id': { kind: 'product', scope: 'product' },
  'pentest-id': { kind: 'product', scope: 'product' },
  'metasploit-service': { kind: 'product', scope: 'product' },
  'security-audit-fingerprint': { kind: 'product', scope: 'product' },
  // 識別子ではない付加情報（Nuclei の取り込みが以前スコアを入れていた。古い保存データのために残す）
  epss: { kind: 'annotation', scope: 'global' },
} as const satisfies Record<string, IdentifierSchemeDef>;

export type KnownIdentifierScheme = keyof typeof IDENTIFIER_SCHEMES;

/** scheme の定義を引く（大文字小文字は区別しない）。一覧に無ければ undefined。 */
export function identifierSchemeOf(scheme: string): IdentifierSchemeDef | undefined {
  const key = scheme.trim().toLowerCase();
  return Object.hasOwn(IDENTIFIER_SCHEMES, key) ? IDENTIFIER_SCHEMES[key as KnownIdentifierScheme] : undefined;
}

/**
 * 識別子の表記をそろえる。scheme は小文字、値は前後の空白を除いて scheme ごとの規則で正規化する。
 * 一覧に無い scheme は、scheme の小文字化と空白の除去だけを行う。
 */
export function normalizeIdentifier(id: FindingIdentifier): FindingIdentifier {
  const scheme = id.scheme.trim().toLowerCase();
  const value = id.value.trim();
  const def = identifierSchemeOf(scheme);
  const normalized = def?.normalize ? def.normalize(value) : value;
  // 正規化で空になる値は元のまま返す（保存スキーマは空の値を受け付けない）
  return { scheme, value: normalized || value || id.value };
}

/**
 * 識別子の配列の表記をそろえ、正規化した結果が同じになるものは先のものだけを残す。
 * 取り込みで書き込む前と、保存データを読み込むときに通す（保存データの表記の揺れをここで吸収する）。
 * 正規化で値が長くなること・件数が増えることはないので、保存スキーマの上限を超えない。
 */
export function normalizeIdentifiers(identifiers: readonly FindingIdentifier[]): FindingIdentifier[] {
  const seen = new Set<string>();
  const out: FindingIdentifier[] = [];
  for (const id of identifiers) {
    const n = normalizeIdentifier(id);
    const key = `${n.scheme}\u0000${n.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(n);
  }
  return out;
}

/** 値 1 つを、指定の scheme の規則で正規化する（項目として持っている IP・ホスト名などを比べるときに使う）。 */
export function normalizeIdentifierValue(scheme: KnownIdentifierScheme, value: string): string {
  return normalizeIdentifier({ scheme, value }).value;
}

/**
 * 識別子の配列から、指定の scheme の値を正規化して取り出す（scheme の大文字小文字は区別しない。重複は除く）。
 * 保存済みのデータは正規化されていないことがあるので、読む側はこれを通して比べる。
 */
export function identifierValues(
  identifiers: readonly FindingIdentifier[],
  ...schemes: KnownIdentifierScheme[]
): string[] {
  const out = new Set<string>();
  for (const id of identifiers) {
    const n = normalizeIdentifier(id);
    if ((schemes as string[]).includes(n.scheme)) out.add(n.value);
  }
  return [...out];
}

/** 識別子の一意な範囲。一覧に無い scheme は undefined。 */
export function identifierScope(id: FindingIdentifier): IdentifierScope | undefined {
  const def = identifierSchemeOf(id.scheme);
  if (!def) return undefined;
  return typeof def.scope === 'function' ? def.scope(normalizeIdentifier(id).value) : def.scope;
}

/**
 * 同一判定の鍵。2 つの識別子の鍵が同じなら、同じものを指す。
 *
 * - 種類が `identity` の識別子だけが鍵を持つ（分類・製品内の ID・付加情報・一覧に無い scheme は undefined）
 * - 一意な範囲が `organization` の識別子（プライベート IP・ドメインなしのホスト名）は、`scope` を鍵に含める。
 *   `scope` は「同じ組織（＋任意のネットワーク）」を表す文字列で、呼び出し側が決める。1 つのプロジェクトの
 *   中で比べるなら省略でよい。組織をまたいで比べるときは、組織ごとに違う値を渡す
 */
export function identityKey(id: FindingIdentifier, scope = ''): string | undefined {
  const def = identifierSchemeOf(id.scheme);
  if (def?.kind !== 'identity') return undefined;
  const n = normalizeIdentifier(id);
  const base = `${n.scheme}:${n.value}`;
  return identifierScope(n) === 'organization' ? `${base}@${scope}` : base;
}
