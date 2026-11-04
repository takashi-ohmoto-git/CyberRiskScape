import type { FindingIdentifier } from './types';

/**
 * 資産の同一判定の鍵と観測時刻の正規化（docs/architecture.md §8.7）。
 * 取り込みと保存データの読み込みの両方で使う純粋関数。
 */

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** ホストの文字列を、IP・FQDN・ホスト名のどれかの識別子にする。 */
export function hostIdentifier(host: string): FindingIdentifier {
  if (IPV4.test(host) || host.includes(':')) return { scheme: 'ip', value: host };
  return { scheme: host.includes('.') ? 'fqdn' : 'hostname', value: host.toLowerCase() };
}

/** 資産の項目から同一判定の鍵を作る。重複は除く。 */
export function assetIdentifiers(asset: {
  host: string;
  ip?: string;
  domain?: string;
  url?: string;
}): FindingIdentifier[] {
  const candidates: FindingIdentifier[] = [
    ...(asset.ip ? [hostIdentifier(asset.ip)] : []),
    ...(asset.domain ? [hostIdentifier(asset.domain)] : []),
    hostIdentifier(asset.host),
    ...(asset.url ? [{ scheme: 'url', value: asset.url }] : []),
  ];
  const seen = new Set<string>();
  return candidates.filter((id) => {
    const key = `${id.scheme}\u0000${id.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * 時刻の文字列を ISO 8601（UTC）にする。解釈できなければ undefined。
 * PostgreSQL の表記（`2026-11-04 06:58:29.773049+00`）と、日付だけの表記も受ける。
 */
export function toIsoTimestamp(value: string): string | undefined {
  const normalized = value
    .trim()
    .replace(/^(\d{4}-\d{2}-\d{2}) /, '$1T')
    .replace(/(T.*[+-]\d{2})$/, '$1:00');
  const time = Date.parse(normalized);
  return Number.isNaN(time) ? undefined : new Date(time).toISOString();
}
