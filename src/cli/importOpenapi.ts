import { resolveProject } from './analyze';
import { LAYER_KEYS, MAX_ASSETS, type Asset } from '../core/model/types';
import { formatElementalId } from '../core/model/elementalId';
import { assetIdentifiers } from '../core/model/assetIdentity';
import { deserializeProject } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import { lookupNode, type ImportNodeRef } from '../features/findings-import/resolveNode';
import type { ParsedOpenApi } from '../features/openapi-import/parseOpenApi';

/**
 * CLI `import-openapi`：OpenAPI の定義の操作を、API の定義の資産（エンドポイント、`source.definition: true`）として
 * プロジェクト JSON に保存する（plan §2.148）。取り込み直しは製品（OpenAPI）× scope の単位で置き換える。
 * 認証の指定が無い操作は報告にだけ出す。ファイル I/O は呼び出し側（main.ts）。
 */

export const OPENAPI_PRODUCT = 'OpenAPI';

export interface ImportOpenapiOptions {
  scope: string;
  /** サーバーの URL を上書き・補う（定義に servers が無い・相対のとき）。 */
  baseUrl?: string;
  node?: string;
  importedAt?: string;
}

export interface ImportOpenapiOutput {
  project: PersistedProject;
  scope: string;
  title?: string;
  version?: string;
  baseUrl: string;
  endpoints: number;
  /** 認証の指定が無い操作（メソッドとパス）。 */
  withoutAuth: { method: string; path: string }[];
  linked?: string;
  unlinkedReason?: 'unknownNode' | 'ambiguous';
}

export function importOpenapi(rawProject: unknown, doc: ParsedOpenApi, options: ImportOpenapiOptions): ImportOpenapiOutput {
  const resolved = resolveProject(rawProject);
  const loaded = deserializeProject(rawProject);
  if (!loaded) throw new Error('プロジェクト JSON の形式が不正です。');
  const base = (options.baseUrl ?? doc.servers.find((s) => /^https?:\/\//i.test(s)))?.replace(/\/+$/, '');
  if (!base || !/^https?:\/\/[^/?#]+/i.test(base)) {
    throw new Error('サーバーの URL（https://…）が定義にありません。--base-url で指定してください。');
  }
  const host = /^https?:\/\/(?:[^@/?#]*@)?([^/?#:]+|\[[^\]]+\])/i.exec(base)![1].toLowerCase();

  const nodes: ImportNodeRef[] = LAYER_KEYS.flatMap((layer) =>
    resolved.layers[layer].nodes.map((n) => ({ id: n.id, layer, seq: n.seq, type: n.type, label: n.label })),
  );
  const lookup = options.node === undefined ? undefined : lookupNode(nodes, options.node);
  const found = lookup?.kind === 'found' ? lookup.node : undefined;
  const importedAt = options.importedAt ?? new Date().toISOString();
  const source = {
    format: 'openapi' as const,
    product: OPENAPI_PRODUCT,
    ...(doc.version ? { productVersion: doc.version } : {}),
    scope: options.scope,
    importedAt,
    definition: true,
  };

  const endpoints = new Map<string, Asset>();
  for (const op of doc.operations) {
    const url = `${base}${op.path.startsWith('/') ? '' : '/'}${op.path}`.slice(0, 2000);
    const externalId = `endpoint:${op.method}:${url}`;
    const id = `${OPENAPI_PRODUCT}:${options.scope}:${externalId}`;
    endpoints.set(id, {
      id,
      source,
      externalId,
      identifiers: assetIdentifiers({ host, url }),
      kind: 'endpoint',
      host,
      method: op.method,
      url,
      ...(op.params.length > 0 ? { params: op.params.slice(0, 200) } : {}),
      ...(found ? { subject: { layer: found.layer, nodeId: found.id } } : {}),
    });
  }

  const others = (loaded.assets ?? []).filter((a) => !(a.source.product === OPENAPI_PRODUCT && a.source.scope === options.scope));
  const assets = [...others, ...endpoints.values()];
  if (assets.length > MAX_ASSETS) throw new Error(`資産が上限（${MAX_ASSETS} 件）を超えます: ${assets.length} 件`);
  const project: PersistedProject = { ...loaded };
  if (assets.length > 0) project.assets = assets;
  else delete project.assets;

  return {
    project,
    scope: options.scope,
    ...(doc.title ? { title: doc.title } : {}),
    ...(doc.version ? { version: doc.version } : {}),
    baseUrl: base,
    endpoints: endpoints.size,
    withoutAuth: doc.operations.filter((o) => !o.requiresAuth).map((o) => ({ method: o.method, path: o.path })),
    ...(found
      ? { linked: `${found.seq != null ? formatElementalId('node', found.seq) : found.id} ${found.label?.trim() || found.type}` }
      : lookup && lookup.kind !== 'found'
        ? { unlinkedReason: lookup.kind === 'ambiguous' ? ('ambiguous' as const) : ('unknownNode' as const) }
        : {}),
  };
}

const cell = (s: string) => s.replace(/[\r\n]+/g, ' ').replace(/\|/g, '\\|');

export function openapiReportToMarkdown(out: ImportOpenapiOutput): string {
  const lines = [
    '# OpenAPI の取り込みレポート',
    '',
    `- 定義：${out.title ?? '（題名なし）'}${out.version ? ` ${out.version}` : ''} / サーバー ${out.baseUrl}`,
    `- scope: ${out.scope}（同じ scope の API の定義を置き換えた）/ エンドポイント ${out.endpoints} 件（API の定義として保存。Asset タブの API に出る）`,
    '- 読んだのはパス・メソッド・パラメータの名前と場所だけ。例の値・既定値・説明文・認証の設定の中身は保存していない',
    out.linked
      ? `- ノード: ${out.linked}`
      : `- ノード: 未結合（${out.unlinkedReason === 'ambiguous' ? 'C 番号が複数のレイヤーに該当（ノード ID で指定してください）' : out.unlinkedReason === 'unknownNode' ? '指定されたノードが図に無い' : '--node の指定が無い'}）`,
    '',
    `## 認証の指定が無い操作（${out.withoutAuth.length} 件）`,
    '',
    '> 定義の security が空（操作にも文書全体にも無い）のもの。公開してよい操作か、定義の書き漏れかを確かめる。判定ではない。',
    '',
  ];
  if (out.withoutAuth.length === 0) lines.push('- 該当なし');
  else lines.push('| メソッド | パス |', '| --- | --- |', ...out.withoutAuth.map((o) => `| ${o.method} | ${cell(o.path)} |`));
  lines.push('', '- 観測した API との突き合わせ（定義に無い API）は `asm-reconcile` で出る');
  return lines.join('\n');
}

export function openapiReportToJson(out: ImportOpenapiOutput): Record<string, unknown> {
  const { project: _project, ...rest } = out;
  return { schemaVersion: 1, kind: 'cyberriskscape-openapi-import-report', ...rest };
}
