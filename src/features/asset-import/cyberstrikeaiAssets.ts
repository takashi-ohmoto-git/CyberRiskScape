import { z } from 'zod';
import { toIsoTimestamp } from '../../core/model/assetIdentity';
import type { ParsePentestAssetsResult, PentestServiceRecord } from './pentestAssetRecord';

/**
 * CyberStrikeAI の資産の一覧 API（`GET /api/assets`。1 ページ 100 件まで）の応答を、取り込みに必要な項目だけに読む。
 * DOM にも Node にも依存しない純粋関数（docs/architecture.md §8.7）。
 *
 * - 資産はサービス（ホスト・IP・ポート・プロトコル）の単位。エンドポイント（URL・パラメータ）は持たない
 * - 手で登録した資産（`source` が `manual`）と、使っていない資産（`status` が `inactive`）は観測ではないので読まない。
 *   ARTEX で `task_source` が agent 以外を読まないのと同じ考え方
 * - 担当者・部署・業務システム・所在地・タグ・メモの類は読まない（個人情報や社内の情報が入りうるため）
 * - 応答の形は公式のソース（internal/database/asset.go・internal/handler/asset.go）で確かめたもの。実機では未検証
 */

const Text = z.string().max(2000);

const RecordSchema = z.object({
  id: z.union([z.string().max(100), z.number().int()]).optional(),
  host: Text.optional(),
  ip: z.string().max(100).optional(),
  port: z.number().int().min(0).max(65535).optional(),
  domain: Text.optional(),
  protocol: z.string().max(50).optional(),
  server: z.string().max(200).optional(),
  source: z.string().max(100).optional(),
  status: z.string().max(50).optional(),
  last_seen_at: z.string().max(40).optional(),
});

const ResponseSchema = z.object({ assets: z.array(RecordSchema).max(100_000) });

/** Go の time.Time の未設定（0001-01-01）は観測時刻として扱わない。 */
const observedAtOf = (raw: string | undefined) =>
  raw && !raw.startsWith('0001-') ? toIsoTimestamp(raw) : undefined;

export function parseCyberStrikeAiAssets(raw: unknown): ParsePentestAssetsResult<PentestServiceRecord> {
  const checked = ResponseSchema.safeParse(raw);
  if (!checked.success) {
    const issue = checked.error.issues[0];
    return { ok: false, error: `CyberStrikeAI の資産の形が想定と異なります（${issue.path.join('.')}）: ${issue.message}` };
  }
  const observed = checked.data.assets.filter(
    (a) => (a.source ?? '').trim().toLowerCase() !== 'manual' && (a.status ?? 'active').trim().toLowerCase() === 'active',
  );
  const records = observed.flatMap((a): PentestServiceRecord[] => {
    const host = a.ip || a.domain || a.host;
    if (!host) return [];
    const observedAt = observedAtOf(a.last_seen_at);
    return [
      {
        host,
        ...(a.id !== undefined ? { assetId: String(a.id) } : {}),
        ...(a.ip ? { ip: a.ip } : {}),
        ...(a.domain && a.domain !== a.ip ? { domain: a.domain } : {}),
        ...(a.port ? { port: a.port } : {}),
        ...(a.protocol ? { serviceName: a.protocol.toLowerCase() } : {}),
        technologies: a.server ? [a.server] : [],
        ...(observedAt ? { observedAt } : {}),
      },
    ];
  });
  return { ok: true, records, skippedBySource: checked.data.assets.length - observed.length };
}
