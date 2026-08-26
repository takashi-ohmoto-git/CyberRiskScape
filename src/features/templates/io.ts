import { z } from 'zod';
import type { LayerData } from '../../core/model/types';
import { PersistedLayerDataSchema } from '../persistence/schema';

/**
 * レイヤーテンプレートの **可搬な** エクスポート形式（JSON）。
 *
 * 1 レイヤー分の図（nodes / edges / boundaries）に任意の名称を付けたもの。
 * インスタンス固有の連番（各要素の `seq` = レイヤー固有の ElementalID）は
 * シリアライズ時に除去し、インポート側で採番し直す（別レイヤー間で衝突しない）。
 * `kind` マーカーは任意（手書き JSON も受理。存在する場合は一致を要求）。
 */
export const TEMPLATE_EXPORT_SCHEMA_VERSION = 1 as const;
export const TEMPLATE_EXPORT_KIND = 'cyberriskscape-template' as const;

export const TemplateExportSchema = z.object({
  schemaVersion: z.literal(TEMPLATE_EXPORT_SCHEMA_VERSION),
  kind: z.literal(TEMPLATE_EXPORT_KIND).optional(),
  name: z.string().min(1).max(200),
  // レイヤー図の検証は永続化スキーマを再利用（node/edge/boundary の二重定義を避ける）。
  layer: PersistedLayerDataSchema,
});

export type TemplateExport = z.infer<typeof TemplateExportSchema>;

/** 各要素から `seq`（レイヤー固有の連番）を落とす。可搬性のためインポート側で振り直す。 */
function stripSeq(layer: LayerData): LayerData {
  return {
    nodes: layer.nodes.map(({ seq: _seq, ...n }) => n),
    edges: layer.edges.map(({ seq: _seq, ...e }) => e),
    boundaries: layer.boundaries.map(({ seq: _seq, ...b }) => b),
  };
}

/** アクティブレイヤーの図を、名称付きの可搬 JSON 文字列に変換する（整形済み）。 */
export function serializeTemplateToJson(name: string, layer: LayerData): string {
  return JSON.stringify(
    {
      schemaVersion: TEMPLATE_EXPORT_SCHEMA_VERSION,
      kind: TEMPLATE_EXPORT_KIND,
      name,
      layer: stripSeq(layer),
    },
    null,
    2,
  );
}

export type ParseTemplateResult =
  | { ok: true; name: string; layer: LayerData }
  | { ok: false; error: string };

/**
 * JSON 文字列を検証し、取り込み可能なテンプレート（名称＋レイヤー図）を生成する。
 * 失敗時はユーザー表示用のエラーメッセージを返す（throw しない）。
 */
export function parseTemplateFromJson(text: string): ParseTemplateResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return { ok: false, error: `JSON 構文エラー: ${(e as Error).message}` };
  }

  const result = TemplateExportSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('; ');
    return { ok: false, error: `検証エラー: ${issues}` };
  }

  return { ok: true, name: result.data.name, layer: result.data.layer as LayerData };
}
