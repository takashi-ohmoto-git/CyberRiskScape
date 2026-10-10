import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { conjurToLayer } from './conjurToLayer';
import { PersistedLayerDataSchema } from '../persistence/schema';
import { layerToProject } from '../kong-import/toProject';
import { analyzeProject } from '../../cli/analyze';
import type { LayerData } from '../../core/model/types';

const SAMPLE = readFileSync('guide/templates/conjur-policy.yml', 'utf-8');

function ok(text: string) {
  const r = conjurToLayer(text);
  if (!r.ok) throw new Error(r.error);
  return r;
}
const node = (l: LayerData, label: string) => l.nodes.find((n) => n.label === label);
const edge = (l: LayerData, s: string, t: string) => l.edges.find((e) => e.source === s && e.target === t);

describe('conjurToLayer', () => {
  it('host は認証方式で型を分ける（authn-k8s / authn-jwt＝ワークロードID、API キー＝サービスアカウント）', () => {
    const { layer } = ok(SAMPLE);
    expect(node(layer, 'orders/order-api')).toMatchObject({ type: 'WORKLOAD_IDENTITY', agentAttributes: { identityTier: 'Cryptographic' } });
    expect(node(layer, 'orders/deploy')).toMatchObject({ type: 'WORKLOAD_IDENTITY' });
    const batch = node(layer, 'orders/nightly-batch');
    expect(batch?.type).toBe('SERVICE_ACCOUNT');
    expect(batch?.agentAttributes).toBeUndefined();
  });

  it('host → Conjur の線の auth は認証方式で分ける（API キー＝ApiKey、authn-k8s＝Certificate、authn-jwt＝Token）', () => {
    const { layer } = ok(SAMPLE);
    const auth = (label: string) => edge(layer, node(layer, label)!.id, 'conjur-vault')?.auth;
    expect(auth('orders/nightly-batch')).toBe('ApiKey');
    expect(auth('orders/order-api')).toBe('Certificate');
    expect(auth('orders/deploy')).toBe('Token');
  });

  it('layer・grant をたどった実効権限で、取得・更新できる変数の件数を線に書く', () => {
    const { layer } = ok(SAMPLE);
    const id = (label: string) => node(layer, label)!.id;
    // nightly-batch は layer app 経由で db/* の 2 件
    expect(edge(layer, id('orders/nightly-batch'), 'conjur-vault')?.dataFlowName).toBe('変数の取得 2 件');
    // order-api は layer app（db 2 件）＋直接（payment 2 件）
    expect(edge(layer, id('orders/order-api'), 'conjur-vault')?.dataFlowName).toBe('変数の取得 4 件');
    // deploy は取得 4 件・更新 4 件
    expect(edge(layer, id('orders/deploy'), 'conjur-vault')?.dataFlowName).toBe('変数の取得 4 件 / 変数の更新 4 件');
  });

  it('権限を持つ人だけを描き、host のロールを付与された人は 人 → NHI の線で表す', () => {
    const { layer } = ok(SAMPLE);
    const alice = node(layer, 'ユーザー: alice')!;
    const ops = node(layer, 'グループ: ops')!;
    expect(alice.type).toBe('USER');
    expect(ops.type).toBe('USER');
    // alice は ops 経由で 4 件取得でき、nightly-batch のロールも持つ
    expect(edge(layer, alice.id, 'conjur-vault')?.dataFlowName).toBe('変数の取得 4 件');
    expect(edge(layer, alice.id, node(layer, 'orders/nightly-batch')!.id)).toBeDefined();
  });

  it('annotation の値は図に載せない（認証方式の判定にだけ使う）', () => {
    const dump = JSON.stringify(ok(SAMPLE).layer);
    expect(dump).not.toContain('example-org/orders');
    expect(dump).not.toContain('Operations engineer');
    expect(dump).toContain('authn-jwt');
  });

  it('件数を集計し、永続化スキーマに適合する', () => {
    const { layer, summary } = ok(SAMPLE);
    expect(summary).toEqual({ hosts: 3, layers: 1, variables: 4, users: 1, groups: 1, permits: 4, grants: 3 });
    expect(PersistedLayerDataSchema.safeParse(layer).success).toBe(true);
  });

  it('生成した図で NHI の脅威（人による NHI の利用・長期の静的シークレット 等）が出る', () => {
    const [result] = analyzeProject(layerToProject(ok(SAMPLE).layer));
    const ids = new Set(result.threats.map((t) => t.ruleId));
    expect(ids.has('nhi-human-use-001')).toBe(true);
    expect(ids.has('nhi-long-lived-secret-001')).toBe(true);
    expect(ids.has('nhi-workload-federation-trust-001')).toBe(true);
    expect(ids.has('api-secrets-vault-concentration-001')).toBe(true);
  });

  it('ポリシーでないもの・構文エラーはエラーを返す', () => {
    expect(conjurToLayer('services: []').ok).toBe(false);
    expect(conjurToLayer('- !host [').ok).toBe(false);
  });
});
