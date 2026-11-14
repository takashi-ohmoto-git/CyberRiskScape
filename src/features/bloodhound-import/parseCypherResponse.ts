import { z } from 'zod';

/**
 * BloodHound CE の `POST /api/v2/graphs/cypher` の応答（ファイルに保存したものを含む）から、ノードの種類・名前・
 * Tier Zero の印だけを取り出す。応答の形は公式の API 仕様（packages/go/openapi/src/schemas/model.unified-graph.*）。
 * 未知のキーは捨てる（SID 等の識別子・その他の属性は持たない）。DOM にも Node にも依存しない。
 */

const NodeSchema = z.object({
  label: z.string().optional(),
  kind: z.string().optional(),
  kinds: z.array(z.string()).optional(),
  isTierZero: z.boolean().optional(),
  properties: z.object({ name: z.string().optional() }).passthrough().optional(),
});

const GraphSchema = z.object({ nodes: z.record(z.string(), NodeSchema) });

/** `{ data: グラフ }`（API の応答そのまま）と、グラフだけのどちらも受ける。 */
const ResponseSchema = z.union([z.object({ data: GraphSchema }), GraphSchema]);

/**
 * 該当が 0 件のとき、BloodHound CE は HTTP 404 で次の本文を返す（2026-11-15 に実機で確認）。
 * `{"http_status":404, ..., "errors":[{"context":"","message":"resource not found"}]}`
 */
const EmptyResultSchema = z.object({
  http_status: z.literal(404),
  errors: z.array(z.object({ message: z.literal('resource not found') })).nonempty(),
});

export interface CypherNode {
  /** ノードの種類（User・Computer・Group 等）。分からなければ undefined。 */
  kind?: string;
  /** 表示名（label、無ければ properties.name）。 */
  name?: string;
  isTierZero: boolean;
}

export type ParseCypherResult = { ok: true; nodes: CypherNode[] } | { ok: false; error: string };

export function parseCypherResponse(raw: unknown): ParseCypherResult {
  if (EmptyResultSchema.safeParse(raw).success) return { ok: true, nodes: [] };
  const r = ResponseSchema.safeParse(raw);
  if (!r.success) return { ok: false, error: 'BloodHound の Cypher の応答の形ではありません（data.nodes が必要です）。' };
  const graph = 'data' in r.data ? r.data.data : r.data;
  return {
    ok: true,
    nodes: Object.values(graph.nodes).map((n) => {
      const name = n.label ?? n.properties?.name;
      const kind = n.kind ?? n.kinds?.[0];
      return { ...(kind ? { kind } : {}), ...(name ? { name } : {}), isTierZero: n.isTierZero === true };
    }),
  };
}
