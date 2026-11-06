import type { Asset, AssetFormat } from '../../core/model/types';
import { hostIdentifier, toIsoTimestamp } from '../../core/model/assetIdentity';
import type { ExposedService } from './asmToLayer';

/**
 * ASM・偵察ツール（Shodan・ScopeSentry）の観測サービスを、共通モデルの資産（kind: 'service'）にする（docs/architecture.md §8.7）。
 * 図の下書き（`asmToLayer`）とは別に、観測した事実として保存するための変換。
 *
 * 方針：
 * - 安定 ID は 製品 × scope × ip:port/transport。同じサービスが複数あれば observedAt が最新のものを採る
 * - identifiers は ip・hostnames（fqdn / hostname）と、製品が報告した CVE（scheme 'cve'・最大 MAX_CVES 件・未検証。指摘にはしない）
 * - バナー・本文・証明書の中身は ExposedService に無いので保存しない
 * - ノードとの結合（subject）はここでは行わない（呼び出し側が明示の対応表で結ぶ。推測しない）
 */

const MAX_CVES = 10;
const MAX_HOSTNAMES = 9;
/** 先頭が CVE ID のものだけ拾う（ScopeSentry は `CVE-2024-0001 (high)` の形で来る）。 */
const CVE_ID = /^(CVE-\d{4}-\d{4,})(?!\d)/i;

/** タイムゾーンの無い時刻（Shodan の `2026-09-20T00:00:00`）は UTC とみなして ISO 8601 にする。 */
const observedAtOf = (value: string | undefined) => {
  if (!value) return undefined;
  return toIsoTimestamp(/^\d{4}-\d{2}-\d{2}T[\d:.]+$/.test(value) ? `${value}Z` : value);
};

export function exposedServicesToAssets(
  services: readonly ExposedService[],
  source: { format: AssetFormat; product: string; scope: string; importedAt: string },
): Asset[] {
  const latest = new Map<string, ExposedService>();
  for (const s of services) {
    const key = `${s.ip}:${s.port}/${s.transport || 'tcp'}`;
    const prev = latest.get(key);
    if (!prev || (s.observedAt ?? '') >= (prev.observedAt ?? '')) latest.set(key, s);
  }

  return [...latest.entries()].map(([externalId, s]) => {
    const ipId = hostIdentifier(s.ip);
    const hostnames = [...new Set((s.hostnames ?? []).map((h) => h.trim().toLowerCase()).filter(Boolean))].slice(0, MAX_HOSTNAMES);
    const cves = [...new Set((s.cves ?? []).flatMap((c) => CVE_ID.exec(c.trim())?.[1].toUpperCase() ?? []))].sort().slice(0, MAX_CVES);
    const identifiers = [ipId, ...hostnames.map(hostIdentifier), ...cves.map((value) => ({ scheme: 'cve', value }))];
    const product = [s.product?.trim(), s.version?.trim()].filter(Boolean).join(' ');
    const observedAt = observedAtOf(s.observedAt);
    return {
      id: `${source.product}:${source.scope}:${externalId}`,
      source,
      externalId,
      identifiers,
      kind: 'service' as const,
      host: s.ip,
      ...(ipId.scheme === 'ip' ? { ip: s.ip } : {}),
      ...(hostnames[0] ? { domain: hostnames[0] } : {}),
      port: s.port,
      ...(s.serviceHint ? { serviceName: s.serviceHint } : {}),
      ...(product ? { technologies: [product] } : {}),
      ...(observedAt ? { observedAt } : {}),
    };
  });
}
