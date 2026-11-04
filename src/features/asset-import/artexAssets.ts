import { z } from 'zod';
import type { AssetParam } from '../../core/model/types';

/**
 * ARTEX の資産 API（`GET /api/assets?type=service|endpoint&task_id=N`）の応答を、取り込みに必要な項目だけに読む。
 * DOM にも Node にも依存しない純粋関数（docs/architecture.md §8.7）。
 *
 * - パラメータの値は読まない（パスワード等が入っていることがある）。名前と場所だけを持つ
 * - `task_source` が `agent` の資産だけを使う。`company` はタスク作成時に企業の資産が結びついただけで、
 *   そのタスクの観測ではない
 * - URL の資格情報と、名前が秘密に見えるクエリの値は伏せる
 */

const Text = z.string().max(2000);

const RecordSchema = z.object({
  type: z.enum(['service', 'endpoint']),
  task_source: z.string().max(50).optional(),
  domain: Text.optional(),
  ip: z.string().max(100).optional(),
  port: z.number().int().min(1).max(65535).optional(),
  url: Text.optional(),
  service_name: z.string().max(200).optional(),
  technologies: z.array(z.string().max(200)).max(100).optional(),
  method: z.string().max(20).optional(),
  params: z.array(z.object({ name: z.string().max(200), location: z.string().max(50).optional() })).max(200).optional(),
  last_seen: z.string().max(40).optional(),
});

const ResponseSchema = z.object({ assets: z.array(RecordSchema).max(100_000) });

export interface ArtexServiceRecord {
  host: string;
  ip?: string;
  domain?: string;
  port?: number;
  serviceName?: string;
  technologies: string[];
  observedAt?: string;
}

export interface ArtexEndpointRecord {
  host: string;
  method: string;
  url: string;
  port?: number;
  params: AssetParam[];
  observedAt?: string;
}

export type ParseArtexResult<T> =
  | { ok: true; records: T[]; skippedBySource: number }
  | { ok: false; error: string };

const SECRET_NAME = /pass|pwd|secret|token|key|auth|session|sid|cookie|credential/i;

/** URL の資格情報を除き、名前が秘密に見えるクエリの値を伏せる。`<page>` のようなひな形を壊さないよう文字列で処理する。 */
export function sanitizeUrl(raw: string): string {
  const noCredentials = raw.replace(/^([a-z][a-z0-9+.-]*:\/\/)[^/?#@]*@/i, '$1');
  const q = noCredentials.indexOf('?');
  if (q < 0) return noCredentials;
  const [query, ...fragment] = noCredentials.slice(q + 1).split('#');
  const masked = query
    .split('&')
    .map((pair) => {
      const eq = pair.indexOf('=');
      return eq > 0 && SECRET_NAME.test(pair.slice(0, eq)) ? `${pair.slice(0, eq)}=***` : pair;
    })
    .join('&');
  return `${noCredentials.slice(0, q)}?${masked}${fragment.length > 0 ? `#${fragment.join('#')}` : ''}`;
}

function hostFromUrl(url: string | undefined): string | undefined {
  return url ? /^[a-z][a-z0-9+.-]*:\/\/(?:[^/?#@]*@)?([^/?#:]+)/i.exec(url)?.[1] : undefined;
}

function parseResponse(raw: unknown, type: 'service' | 'endpoint') {
  const checked = ResponseSchema.safeParse(raw);
  if (!checked.success) {
    const issue = checked.error.issues[0];
    return { ok: false as const, error: `ARTEX の資産の形が想定と異なります（${issue.path.join('.')}）: ${issue.message}` };
  }
  const other = checked.data.assets.find((a) => a.type !== type);
  if (other) return { ok: false as const, error: `type=${type} の応答ではありません（${other.type} を含みます）` };
  const records = checked.data.assets.filter((a) => a.task_source === 'agent');
  return { ok: true as const, records, skippedBySource: checked.data.assets.length - records.length };
}

export function parseArtexServices(raw: unknown): ParseArtexResult<ArtexServiceRecord> {
  const parsed = parseResponse(raw, 'service');
  if (!parsed.ok) return parsed;
  const records = parsed.records.flatMap((a): ArtexServiceRecord[] => {
    const host = a.ip || a.domain || hostFromUrl(a.url);
    if (!host) return [];
    return [
      {
        host,
        ...(a.ip ? { ip: a.ip } : {}),
        ...(a.domain && a.domain !== a.ip ? { domain: a.domain } : {}),
        ...(a.port ? { port: a.port } : {}),
        ...(a.service_name ? { serviceName: a.service_name.toLowerCase() } : {}),
        technologies: a.technologies ?? [],
        ...(a.last_seen ? { observedAt: a.last_seen } : {}),
      },
    ];
  });
  return { ok: true, records, skippedBySource: parsed.skippedBySource };
}

export function parseArtexEndpoints(raw: unknown): ParseArtexResult<ArtexEndpointRecord> {
  const parsed = parseResponse(raw, 'endpoint');
  if (!parsed.ok) return parsed;
  const records = parsed.records.flatMap((a): ArtexEndpointRecord[] => {
    if (!a.url || !a.method) return [];
    const host = hostFromUrl(a.url) || a.domain;
    if (!host) return [];
    return [
      {
        host,
        method: a.method.toUpperCase(),
        url: sanitizeUrl(a.url),
        ...(a.port ? { port: a.port } : {}),
        params: (a.params ?? []).map((p) => ({ name: p.name, location: p.location ?? '' })),
        ...(a.last_seen ? { observedAt: a.last_seen } : {}),
      },
    ];
  });
  return { ok: true, records, skippedBySource: parsed.skippedBySource };
}
