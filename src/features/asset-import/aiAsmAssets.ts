import { z } from 'zod';
import { toIsoTimestamp } from '../../core/model/assetIdentity';
import { sanitizeUrl } from './artexAssets';
import type { ParsePentestAssetsResult, PentestEndpointRecord } from './pentestAssetRecord';

/**
 * AI-ASM（ローカルの ASM ツール）が見つけた API の操作を、エンドポイント資産として読む。入力の形は CRS が定める：
 * `{ "endpoints": [ { "method"?, "url", "params"?, "observedAt"? } ] }`。
 * DOM にも Node にも依存しない純粋関数（docs/architecture.md §8.7）。
 *
 * - method は任意（JS バンドルから拾ったパス等で不明なことがある）。無ければそのまま未指定にする
 * - パラメータは名前と場所だけ。値は受け取らない
 * - URL の資格情報と、名前が秘密に見えるクエリの値は伏せる
 */

const RecordSchema = z.object({
  method: z.string().max(20).optional(),
  url: z.string().max(2000),
  params: z.array(z.object({ name: z.string().max(200), location: z.string().max(50).optional() })).max(200).optional(),
  observedAt: z.string().max(40).optional(),
});

const InputSchema = z.object({ endpoints: z.array(RecordSchema).max(100_000) });

export function parseAiAsmEndpoints(raw: unknown): ParsePentestAssetsResult<PentestEndpointRecord> {
  const checked = InputSchema.safeParse(raw);
  if (!checked.success) {
    const issue = checked.error.issues[0];
    return { ok: false, error: `AI-ASM の資産の形が想定と異なります（${issue.path.join('.')}）: ${issue.message}` };
  }
  const records = checked.data.endpoints.flatMap((e): PentestEndpointRecord[] => {
    const host = /^https?:\/\/(?:[^/?#@]*@)?([^/?#:]+)/i.exec(e.url)?.[1];
    if (!host) return [];
    const observedAt = e.observedAt ? toIsoTimestamp(e.observedAt) : undefined;
    return [
      {
        host,
        ...(e.method ? { method: e.method.toUpperCase() } : {}),
        url: sanitizeUrl(e.url),
        params: (e.params ?? []).map((p) => ({ name: p.name, location: p.location ?? '' })),
        ...(observedAt ? { observedAt } : {}),
      },
    ];
  });
  return { ok: true, records, skippedBySource: 0 };
}
