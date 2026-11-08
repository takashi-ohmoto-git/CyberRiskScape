import { describe, expect, it } from 'vitest';
import type { Asset, AssetSubject } from '../../core/model/types';
import { createManualAsset, isManualAsset, MANUAL_ASSET_PRODUCT } from './manualAsset';
import { buildNodeAssetViews } from './buildAssetViews';
import { PersistedProjectSchema } from '../persistence/schema';

const subject: AssetSubject = { layer: 'L1', nodeId: 'web' };
const at = '2026-11-08T00:00:00.000Z';
const ok = (r: ReturnType<typeof createManualAsset>): Asset => {
  if (!r.ok) throw new Error(`expected ok, got ${r.error}`);
  return r.asset;
};

describe('createManualAsset', () => {
  it('ホスト（FQDN＋IP＋ポート） → service の資産になり、識別子に ip と fqdn が入る', () => {
    const a = ok(createManualAsset({ kind: 'service', host: 'Staging.Example.com', ip: '203.0.113.10', port: '443' }, subject, [], at));
    expect(a).toMatchObject({
      kind: 'service',
      host: 'staging.example.com',
      domain: 'staging.example.com',
      ip: '203.0.113.10',
      port: 443,
      subject,
      source: { format: 'manual', product: MANUAL_ASSET_PRODUCT, importedAt: at },
    });
    expect(a.identifiers).toEqual([
      { scheme: 'ip', value: '203.0.113.10' },
      { scheme: 'fqdn', value: 'staging.example.com' },
    ]);
    expect(isManualAsset(a)).toBe(true);
  });

  it('ホストに IP だけ → ip にも入り、fqdn・domain は付かない', () => {
    const a = ok(createManualAsset({ kind: 'service', host: '203.0.113.20' }, subject, [], at));
    expect(a.ip).toBe('203.0.113.20');
    expect(a.domain).toBeUndefined();
    expect(a.identifiers).toEqual([{ scheme: 'ip', value: '203.0.113.20' }]);
  });

  it('エンドポイント → ホストは URL から取り、クエリ・フラグメントは保存しない', () => {
    const a = ok(
      createManualAsset({ kind: 'endpoint', url: 'https://api.example.com/v1/runs?token=secret#x', method: 'post' }, subject, [], at),
    );
    expect(a).toMatchObject({ kind: 'endpoint', host: 'api.example.com', url: 'https://api.example.com/v1/runs', method: 'POST' });
    expect(JSON.stringify(a)).not.toContain('secret');
  });

  it.each([
    [{ kind: 'service' as const }, 'hostRequired'],
    [{ kind: 'service' as const, host: 'bad host!' }, 'hostRequired'],
    [{ kind: 'service' as const, host: 'a.example.com', ip: '999.1.1.1' }, 'ipInvalid'],
    [{ kind: 'service' as const, host: 'a.example.com', port: '70000' }, 'portInvalid'],
    [{ kind: 'service' as const, host: 'a.example.com', port: '44x' }, 'portInvalid'],
    [{ kind: 'endpoint' as const }, 'urlRequired'],
    [{ kind: 'endpoint' as const, url: 'ftp://a.example.com/x' }, 'urlInvalid'],
    [{ kind: 'endpoint' as const, url: 'not a url' }, 'urlInvalid'],
    [{ kind: 'endpoint' as const, url: 'https://a.example.com/x', method: 'GE T' }, 'methodInvalid'],
  ])('不正な入力 %j → %s', (input, error) => {
    expect(createManualAsset(input, subject, [], at)).toEqual({ ok: false, error });
  });

  it('同じノードに同じ内容をもう一度 → duplicate', () => {
    const first = ok(createManualAsset({ kind: 'service', host: 'a.example.com', port: 443 }, subject, [], at));
    expect(createManualAsset({ kind: 'service', host: 'A.example.com', port: '443' }, subject, [first], at)).toEqual({
      ok: false,
      error: 'duplicate',
    });
  });

  it('作った資産 → そのノードのポップアップ（buildNodeAssetViews）に載り、保存形式の検証も通る', () => {
    const a = ok(createManualAsset({ kind: 'service', host: 'a.example.com', ip: '203.0.113.10', port: 443 }, subject, [], at));
    const v = buildNodeAssetViews('web', [a], [{ id: 'web', type: 'FRONT_END_SERVER', layer: 'L1' }]);
    expect(v.hosts.map((h) => h.host)).toEqual(['203.0.113.10']);
    const empty = { nodes: [], edges: [], boundaries: [] };
    const parsed = PersistedProjectSchema.safeParse({
      schemaVersion: 1,
      layers: { L0: empty, L1: empty, L2: empty, L3: empty },
      activeLayer: 'L1',
      activeFramework: 'ALL',
      updatedAt: 0,
      assets: [a],
    });
    expect(parsed.success).toBe(true);
  });
});
