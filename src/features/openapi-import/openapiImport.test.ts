import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseOpenApi } from './parseOpenApi';
import { matchesApiDefinition } from './matchApiPath';
import { importOpenapi, openapiReportToMarkdown } from '../../cli/importOpenapi';
import { reconcileAsm } from '../asm-import/reconcileAsm';
import type { Asset } from '../../core/model/types';

/** 架空の API の定義（OpenAPI 3.0、YAML）。例の値・既定値に秘密に見える文字列を入れておく。 */
const V3 = `
openapi: 3.0.3
info: { title: Partner Portal API, version: 1.2.0 }
servers:
  - url: https://{env}.portal.example.com/v1
    variables: { env: { default: api } }
security:
  - bearerAuth: []
components:
  parameters:
    OrderId: { name: orderId, in: path, required: true, schema: { type: string, example: EXAMPLE-SECRET-ORDER } }
  securitySchemes:
    bearerAuth: { type: http, scheme: bearer, description: TOKEN-DESCRIPTION-SHOULD-NOT-BE-STORED }
paths:
  /orders/{orderId}:
    parameters: [ { $ref: '#/components/parameters/OrderId' } ]
    get:
      parameters: [ { name: fields, in: query, schema: { default: EXAMPLE-DEFAULT-VALUE } } ]
    delete: {}
  /health:
    get:
      security: []
  /search:
    post:
      security: [ {} ]
`;

const V2 = JSON.stringify({
  swagger: '2.0',
  info: { title: 'Mobile Backend', version: '0.9' },
  host: 'm.example.com',
  basePath: '/api',
  schemes: ['https'],
  paths: { '/users/{id}': { get: { parameters: [{ name: 'id', in: 'path' }] } } },
});

const PROJECT = new URL('../../cli/__fixtures__/sample-project.json', import.meta.url);
const project = () => JSON.parse(readFileSync(PROJECT, 'utf8')) as unknown;

describe('parseOpenApi', () => {
  it('OpenAPI 3：サーバーの変数を既定値で埋め、操作・パラメータ（$ref を解く）・認証の有無を取り出す', () => {
    const r = parseOpenApi(V3);
    if (!r.ok) throw new Error(r.error);
    expect(r.doc).toMatchObject({ title: 'Partner Portal API', version: '1.2.0', servers: ['https://api.portal.example.com/v1'] });
    const ops = r.doc.operations.map((o) => `${o.method} ${o.path} ${o.requiresAuth}`);
    expect(ops).toEqual(['GET /orders/{orderId} true', 'DELETE /orders/{orderId} true', 'GET /health false', 'POST /search false']);
    expect(r.doc.operations[0].params).toEqual([
      { name: 'orderId', location: 'path' },
      { name: 'fields', location: 'query' },
    ]);
    expect(JSON.stringify(r)).not.toMatch(/EXAMPLE-SECRET-ORDER|EXAMPLE-DEFAULT-VALUE|TOKEN-DESCRIPTION/);
  });

  it('Swagger 2.0：schemes・host・basePath からサーバーを作る', () => {
    const r = parseOpenApi(V2);
    if (!r.ok) throw new Error(r.error);
    expect(r.doc.servers).toEqual(['https://m.example.com/api']);
    expect(r.doc.operations).toEqual([{ method: 'GET', path: '/users/{id}', params: [{ name: 'id', location: 'path' }], requiresAuth: false }]);
  });

  it('OpenAPI でない・読めない文書はエラー', () => {
    expect(parseOpenApi('openapi: 4.0.0\npaths: {}').ok).toBe(false);
    expect(parseOpenApi('{ not json').ok).toBe(false);
  });
});

describe('matchesApiDefinition', () => {
  const def = { method: 'GET', url: 'https://api.example.com/v1/orders/{orderId}' };
  it.each([
    ['https://API.example.com:443/v1/orders/42?x=1', 'GET', true],
    ['https://api.example.com/v1/orders/42/', 'get', true],
    ['https://api.example.com/v1/orders', 'GET', false],
    ['https://api.example.com/v1/orders/42/items', 'GET', false],
    ['http://api.example.com/v1/orders/42', 'GET', false],
    ['https://api.example.com/v1/orders/42', 'DELETE', false],
  ] as const)('%s %s → %s', (url, method, expected) => {
    expect(matchesApiDefinition({ method, url }, def)).toBe(expected);
  });

  it('区切りの一部がテンプレートでも一致する（file.{ext}）', () => {
    expect(matchesApiDefinition({ url: 'https://x.example.com/f/report.pdf' }, { url: 'https://x.example.com/f/report.{ext}' })).toBe(true);
  });
});

describe('importOpenapi と asm-reconcile', () => {
  const doc = () => {
    const r = parseOpenApi(V3);
    if (!r.ok) throw new Error(r.error);
    return r.doc;
  };

  it('操作を API の定義の資産として保存し、認証の指定が無い操作を報告に出す', () => {
    const out = importOpenapi(project(), doc(), { scope: 'portal', importedAt: '2026-11-15T00:00:00Z' });
    expect(out.endpoints).toBe(4);
    const assets = out.project.assets ?? [];
    expect(assets.every((a) => a.source.definition === true && a.source.format === 'openapi' && a.kind === 'endpoint')).toBe(true);
    expect(assets.map((a) => `${a.method} ${a.url}`)).toContain('GET https://api.portal.example.com/v1/orders/{orderId}');
    expect(out.withoutAuth).toEqual([
      { method: 'GET', path: '/health' },
      { method: 'POST', path: '/search' },
    ]);
    expect(openapiReportToMarkdown(out)).toContain('/health');
  });

  it('サーバーの URL が無ければ --base-url が要る。同じ scope は置き換える', () => {
    const noServer = { ...doc(), servers: [] };
    expect(() => importOpenapi(project(), noServer, { scope: 'portal' })).toThrow(/--base-url/);
    const first = importOpenapi(project(), doc(), { scope: 'portal' });
    const again = importOpenapi(first.project, { ...doc(), operations: doc().operations.slice(0, 1) }, { scope: 'portal' });
    expect(again.project.assets).toHaveLength(1);
  });

  it('asm-reconcile：観測した API のうち、定義に当たらないものを「定義に無い API」として出す', () => {
    const defs = importOpenapi(project(), doc(), { scope: 'portal' }).project.assets ?? [];
    const observed = (url: string, method: string): Asset => ({
      id: `CyberStrikeAI:s:${method}:${url}`,
      source: { format: 'cyberstrikeai-assets', product: 'CyberStrikeAI', scope: 's', importedAt: 't' },
      externalId: url,
      identifiers: [],
      kind: 'endpoint',
      host: 'api.portal.example.com',
      method,
      url,
    });
    const r = reconcileAsm({
      layers: { L1: { nodes: [] } },
      assets: [
        ...defs,
        observed('https://api.portal.example.com/v1/orders/1001', 'GET'),
        observed('https://api.portal.example.com/v1/admin/export', 'GET'),
        observed('https://api.portal.example.com/v1/orders/1001', 'PUT'),
      ],
    });
    expect(r.apiDefinitions?.definitions).toBe(4);
    expect(r.apiDefinitions?.undocumented.map((e) => `${e.method} ${e.url}`)).toEqual([
      'GET https://api.portal.example.com/v1/admin/export',
      'PUT https://api.portal.example.com/v1/orders/1001',
    ]);
    expect(reconcileAsm({ layers: {}, assets: [observed('https://x.example.com/a', 'GET')] }).apiDefinitions).toBeUndefined();
  });
});
