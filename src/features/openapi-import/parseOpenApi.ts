import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

/**
 * OpenAPI（3.0・3.1）と Swagger 2.0 の定義から、API の在庫に要る項目だけを取り出す（業界標準。OpenAPI Initiative）。
 * - 読むのは、サーバーの URL・パス・メソッド・パラメータの名前と場所・認証の指定の有無だけ
 * - 例の値（example・examples）・既定値（default）・説明文・認証の設定の中身（securitySchemes）は読まない
 * - パラメータの $ref は、同じ文書の中の参照（#/components/parameters・#/parameters）だけを解く
 * DOM にも Node にも依存しない。
 */

const METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'] as const;

const ParamSchema = z.object({ name: z.string().optional(), in: z.string().optional(), $ref: z.string().optional() });
const SecuritySchema = z.array(z.record(z.string(), z.unknown())).optional();

const OperationSchema = z.object({
  parameters: z.array(z.unknown()).optional(),
  security: SecuritySchema,
});

const DocSchema = z.object({
  openapi: z.string().optional(),
  swagger: z.string().optional(),
  info: z.object({ title: z.string().optional(), version: z.string().optional() }).optional(),
  servers: z
    .array(z.object({ url: z.string(), variables: z.record(z.string(), z.object({ default: z.string().optional() })).optional() }))
    .optional(),
  host: z.string().optional(),
  basePath: z.string().optional(),
  schemes: z.array(z.string()).optional(),
  security: SecuritySchema,
  paths: z.record(z.string(), z.record(z.string(), z.unknown())).optional(),
  components: z.object({ parameters: z.record(z.string(), z.unknown()).optional() }).optional(),
  parameters: z.record(z.string(), z.unknown()).optional(),
});

export interface OpenApiOperation {
  method: string;
  /** パスのテンプレート（例：/users/{id}）。 */
  path: string;
  params: { name: string; location: string }[];
  /** 認証の指定があるか（操作の security、無ければ文書全体の security。空の配列は「認証なし」）。 */
  requiresAuth: boolean;
}

export interface ParsedOpenApi {
  title?: string;
  version?: string;
  /** サーバーの URL（変数は既定値で埋める。相対の URL はそのまま）。 */
  servers: string[];
  operations: OpenApiOperation[];
}

export type ParseOpenApiResult = { ok: true; doc: ParsedOpenApi } | { ok: false; error: string };

function readText(text: string): unknown {
  const t = text.trim();
  if (t.startsWith('{')) return JSON.parse(t);
  return parseYaml(t);
}

export function parseOpenApi(text: string): ParseOpenApiResult {
  let raw: unknown;
  try {
    raw = readText(text);
  } catch (e) {
    return { ok: false, error: `JSON・YAML として読めません（${e instanceof Error ? e.message.split('\n')[0] : String(e)}）。` };
  }
  const r = DocSchema.safeParse(raw);
  if (!r.success) return { ok: false, error: 'OpenAPI の定義の形ではありません。' };
  const d = r.data;
  const v3 = d.openapi !== undefined && /^3\./.test(d.openapi);
  const v2 = d.swagger !== undefined && d.swagger.startsWith('2.');
  if (!v3 && !v2) return { ok: false, error: 'OpenAPI 3.x（openapi: 3.x）か Swagger 2.0（swagger: "2.0"）の定義にしてください。' };

  const servers = v3
    ? (d.servers ?? []).map((s) => s.url.replace(/\{([^}]+)\}/g, (m, name: string) => s.variables?.[name]?.default ?? m))
    : d.host
      ? (d.schemes?.length ? d.schemes : ['https']).map((sc) => `${sc}://${d.host}${d.basePath ?? ''}`)
      : d.basePath
        ? [d.basePath]
        : [];

  const refParams = v3 ? (d.components?.parameters ?? {}) : (d.parameters ?? {});
  const resolveParam = (p: unknown): { name: string; location: string } | undefined => {
    const pr = ParamSchema.safeParse(p);
    if (!pr.success) return undefined;
    let param = pr.data;
    if (param.$ref) {
      const m = /^#\/(?:components\/parameters|parameters)\/(.+)$/.exec(param.$ref);
      const target = m ? ParamSchema.safeParse(refParams[m[1]]) : undefined;
      if (!target?.success) return undefined;
      param = target.data;
    }
    return param.name && param.in ? { name: param.name.slice(0, 100), location: param.in.slice(0, 20) } : undefined;
  };

  const operations: OpenApiOperation[] = [];
  for (const [path, item] of Object.entries(d.paths ?? {})) {
    const shared = Array.isArray(item.parameters) ? item.parameters : [];
    for (const method of METHODS) {
      const op = OperationSchema.safeParse(item[method]);
      if (item[method] === undefined || !op.success) continue;
      const params = new Map<string, { name: string; location: string }>();
      for (const p of [...shared, ...(op.data.parameters ?? [])]) {
        const rp = resolveParam(p);
        if (rp) params.set(`${rp.location}:${rp.name}`, rp);
      }
      const security = op.data.security ?? d.security;
      operations.push({
        method: method.toUpperCase(),
        path: path.slice(0, 500),
        params: [...params.values()],
        requiresAuth: security !== undefined && security.length > 0 && security.some((req) => Object.keys(req).length > 0),
      });
    }
  }
  return {
    ok: true,
    doc: {
      ...(d.info?.title ? { title: d.info.title.slice(0, 200) } : {}),
      ...(d.info?.version ? { version: d.info.version.slice(0, 50) } : {}),
      servers,
      operations,
    },
  };
}
