import { MAX_ASSETS, type Asset, type AssetSubject, type FindingIdentifier } from '../../core/model/types';

/**
 * NodePanel の資産ポップアップから、人が手で入力したホスト・エンドポイントを Asset にする
 * （docs/node-address-asset-panel.md §3.2）。取り込みと同じ Asset モデルに乗せ、`subject` でノードに結びつける。
 * 宣言した事実を記録するだけで、名前解決・到達確認はしない。DOM にも Node にも依存しない純粋関数。
 */

/** 手入力の資産の製品名。取り込み直し（product × scope で置き換え）と衝突しない名前にする。 */
export const MANUAL_ASSET_PRODUCT = 'Manual';

export interface ManualAssetInput {
  kind: 'service' | 'endpoint';
  /** ホスト名か IP。endpoint では省略でき、URL のホストを使う。 */
  host?: string;
  ip?: string;
  /** 文字列でも受ける（フォームの入力値のまま渡せるように）。 */
  port?: string | number;
  /** endpoint のときだけ使う。http / https のみ。クエリとフラグメントは保存しない。 */
  url?: string;
  method?: string;
}

export type ManualAssetError = 'hostRequired' | 'urlRequired' | 'urlInvalid' | 'ipInvalid' | 'portInvalid' | 'methodInvalid' | 'duplicate' | 'tooMany';

export type ManualAssetResult = { ok: true; asset: Asset } | { ok: false; error: ManualAssetError };

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6 = /^[0-9a-f]*:[0-9a-f:.]*$/i;
const HOSTNAME = /^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$/i;
const METHOD = /^[A-Z]{1,20}$/;

export function isIpAddress(value: string): boolean {
  return IPV4.test(value) || IPV6.test(value);
}

export function isManualAsset(asset: Asset): boolean {
  return asset.source.format === 'manual';
}

/** 入力を検証して Asset を 1 件作る。既存と同じものがあれば `duplicate`。 */
export function createManualAsset(
  input: ManualAssetInput,
  subject: AssetSubject,
  existing: readonly Asset[],
  importedAt: string,
): ManualAssetResult {
  if (existing.length >= MAX_ASSETS) return { ok: false, error: 'tooMany' };

  let url: string | undefined;
  let urlHost: string | undefined;
  if (input.kind === 'endpoint') {
    const raw = input.url?.trim();
    if (!raw) return { ok: false, error: 'urlRequired' };
    let parsed: URL;
    try {
      parsed = new URL(raw);
    } catch {
      return { ok: false, error: 'urlInvalid' };
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return { ok: false, error: 'urlInvalid' };
    // クエリ・フラグメントにはトークン等が入りうるので保存しない
    url = `${parsed.origin}${parsed.pathname}`;
    urlHost = parsed.hostname.replace(/^\[|\]$/g, '');
  }

  const host = (input.host?.trim() || urlHost || '').toLowerCase();
  if (!host) return { ok: false, error: 'hostRequired' };
  if (!isIpAddress(host) && !HOSTNAME.test(host)) return { ok: false, error: 'hostRequired' };

  const ipRaw = input.ip?.trim();
  if (ipRaw && !isIpAddress(ipRaw)) return { ok: false, error: 'ipInvalid' };
  const ip = ipRaw || (isIpAddress(host) ? host : undefined);

  let port: number | undefined;
  const portRaw = typeof input.port === 'number' ? String(input.port) : input.port?.trim();
  if (portRaw) {
    if (!/^\d+$/.test(portRaw)) return { ok: false, error: 'portInvalid' };
    port = Number(portRaw);
    if (port < 1 || port > 65535) return { ok: false, error: 'portInvalid' };
  }

  let method: string | undefined;
  if (input.kind === 'endpoint' && input.method?.trim()) {
    method = input.method.trim().toUpperCase();
    if (!METHOD.test(method)) return { ok: false, error: 'methodInvalid' };
  }

  const identifiers: FindingIdentifier[] = [];
  if (ip) identifiers.push({ scheme: 'ip', value: ip });
  if (!isIpAddress(host)) identifiers.push({ scheme: 'fqdn', value: host });
  if (url) identifiers.push({ scheme: 'url', value: url });

  const externalId = [subject.layer, subject.nodeId, input.kind, url ?? host, port ?? '', method ?? ''].join('|');
  const id = `manual:${externalId}`;
  if (existing.some((a) => a.id === id)) return { ok: false, error: 'duplicate' };

  return {
    ok: true,
    asset: {
      id,
      source: { format: 'manual', product: MANUAL_ASSET_PRODUCT, importedAt },
      externalId,
      identifiers,
      kind: input.kind,
      host,
      ...(ip ? { ip } : {}),
      ...(!isIpAddress(host) ? { domain: host } : {}),
      ...(port !== undefined ? { port } : {}),
      ...(method ? { method } : {}),
      ...(url ? { url } : {}),
      subject,
    },
  };
}
