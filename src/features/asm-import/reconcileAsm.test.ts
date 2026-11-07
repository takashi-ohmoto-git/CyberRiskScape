import { describe, expect, it } from 'vitest';
import type { Asset, DiagramNode } from '../../core/model/types';
import { assetIdentityKey, reconcileAsm } from './reconcileAsm';

const node = (id: string, seq: number, hasGlobalIp?: boolean): DiagramNode =>
  ({ id, seq, type: 'FRONT_END_SERVER', x: 0, y: 0, label: `サーバー${seq}`, ...(hasGlobalIp === undefined ? {} : { attackSurface: { hasGlobalIp } }) }) as DiagramNode;

const asset = (ip: string, port: number, extra: Partial<Asset> = {}): Asset => ({
  id: `Shodan:s:${ip}:${port}`,
  source: { format: 'shodan', product: 'Shodan', scope: 's', importedAt: '2026-11-01T00:00:00Z' },
  externalId: `${ip}:${port}/tcp`,
  identifiers: [],
  kind: 'service',
  host: ip,
  ip,
  port,
  ...extra,
});

const layers = { L1: { nodes: [node('a', 1, false), node('b', 2), node('c', 3, true), node('d', 4, true)] } };
const on = (nodeId: string) => ({ subject: { layer: 'L1' as const, nodeId } });

describe('reconcileAsm', () => {
  it('観測が無い → publicButUnseen は null（未取り込み）', () => {
    const r = reconcileAsm({ layers, assets: [] });
    expect(r.observedCount).toBe(0);
    expect(r.publicButUnseen).toBeNull();
  });

  it('未結合・結合先ノードが消えた観測 → unbound', () => {
    const r = reconcileAsm({ layers, assets: [asset('203.0.113.1', 443), asset('203.0.113.2', 22, on('zzz'))] });
    expect(r.unbound.map((l) => l.ip)).toEqual(['203.0.113.1', '203.0.113.2']);
  });

  it('hasGlobalIp の false / 未入力 → privateButObserved / unsetButObserved に分ける', () => {
    const r = reconcileAsm({ layers, assets: [asset('203.0.113.1', 443, on('a')), asset('203.0.113.2', 80, on('b'))] });
    expect(r.privateButObserved).toHaveLength(1);
    expect(r.privateButObserved[0].node).toBe('C1 サーバー1');
    expect(r.unsetButObserved.map((l) => l.node)).toEqual(['C2 サーバー2']);
  });

  it('true と入力したノードに観測が無い → publicButUnseen（観測のあるノードは除く）', () => {
    const r = reconcileAsm({ layers, assets: [asset('203.0.113.3', 443, on('c'))] });
    expect(r.publicButUnseen?.map((n) => n.nodeId)).toEqual(['d']);
  });

  it('API 定義由来と artex-assets は対象外', () => {
    const def = asset('203.0.113.4', 1, { source: { format: 'shodan', product: 'X', importedAt: 't', definition: true } });
    const artex = asset('203.0.113.5', 2, { source: { format: 'artex-assets', product: 'ARTEX', importedAt: 't' } });
    expect(reconcileAsm({ layers, assets: [def, artex] }).observedCount).toBe(0);
  });

  it('previous 指定 → ip:port で新しく見えた・見えなくなったを出す', () => {
    const prev = [asset('203.0.113.1', 443), asset('203.0.113.2', 22)];
    const cur = [asset('203.0.113.1', 443, { id: 'other-id' }), asset('198.51.100.9', 8080)];
    const r = reconcileAsm({ layers, assets: cur }, prev);
    expect(r.diff?.appeared.map((l) => l.ip)).toEqual(['198.51.100.9']);
    expect(r.diff?.disappeared.map((l) => l.ip)).toEqual(['203.0.113.2']);
    expect(reconcileAsm({ layers, assets: cur }).diff).toBeUndefined();
  });
});

describe('assetIdentityKey', () => {
  it('ip:port → host:port → id の順に鍵を決める', () => {
    expect(assetIdentityKey(asset('203.0.113.1', 443))).toBe('203.0.113.1:443');
    expect(assetIdentityKey({ ...asset('x', 80), ip: undefined, host: 'example.com' })).toBe('example.com:80');
    expect(assetIdentityKey({ ...asset('x', 80), ip: undefined, port: undefined })).toBe('Shodan:s:x:80');
  });
});
