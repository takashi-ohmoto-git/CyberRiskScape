import { describe, expect, it } from 'vitest';
import { detectThreats } from './detectThreats';
import type { DiagramEdge, DiagramNode } from '../model/types';
import type { ThreatRule } from '../../threat-library/schema/threatRule';

/**
 * アイデンティティ軸（[[plan]] §2.39）のエンジン評価テスト。
 * - node: `identityProviderKind`
 * - edge: `sourceIdentityProviderKind` / `targetIdentityProviderKind` / `authProvider`
 *
 * いずれも `managedState` / `userTrust` と同じ「明示宣言時のみ発火」方式であることを確認する
 * （未宣言ノードを Hybrid 等と決めつけないため）。`authProvider` だけは例外で、
 * 未設定を `Undeclared` として**積極的にマッチさせる**（ローカル資格情報の検出が目的）。
 */

const ad: DiagramNode = {
  id: 'ad',
  type: 'IDENTITY_PROVIDER',
  x: 0,
  y: 0,
  identityProviderKind: 'Directory',
};
const entra: DiagramNode = {
  id: 'entra',
  type: 'IDENTITY_PROVIDER',
  x: 300,
  y: 0,
  identityProviderKind: 'IDaaS',
};
/** 種別を宣言していない IdP（旧データ / 未入力）。 */
const bareIdp: DiagramNode = { id: 'bare', type: 'IDENTITY_PROVIDER', x: 600, y: 0 };
const app: DiagramNode = { id: 'app', type: 'PROCESS', x: 0, y: 300 };

function edgeRule(when: Record<string, unknown>): ThreatRule {
  return {
    id: 'identity-edge',
    framework: 'STRIDE',
    category: 'Spoofing',
    severity: 'High',
    description: 'identity edge rule',
    appliesTo: { kind: 'edge', when } as ThreatRule['appliesTo'],
  };
}

describe('node 軸: identityProviderKind', () => {
  const rule: ThreatRule = {
    id: 'hybrid-idp',
    framework: 'STRIDE',
    category: 'Spoofing',
    severity: 'High',
    description: 'hybrid identity plane',
    appliesTo: {
      kind: 'node',
      nodeType: 'IDENTITY_PROVIDER',
      connection: { required: false },
      identityProviderKind: ['Hybrid'],
    } as ThreatRule['appliesTo'],
  };

  it('宣言された種別が一致するノードだけで発火する', () => {
    const hybrid: DiagramNode = { ...bareIdp, id: 'hy', identityProviderKind: 'Hybrid' };
    const out = detectThreats({
      nodes: [ad, entra, hybrid],
      edges: [],
      framework: 'STRIDE',
      rules: [rule],
    });
    expect(out.map((t) => t.nodeId)).toEqual(['hy']);
  });

  it('種別未宣言のノードでは発火しない（最悪を仮定しない）', () => {
    const out = detectThreats({
      nodes: [bareIdp],
      edges: [],
      framework: 'STRIDE',
      rules: [rule],
    });
    expect(out).toHaveLength(0);
  });
});

describe('edge 軸: source/targetIdentityProviderKind', () => {
  const sync: DiagramEdge = {
    id: 'e-sync',
    source: 'ad',
    target: 'entra',
    auth: 'Password',
    network: 'Internet',
    encryption: 'TLS',
    semantic: 'directory_sync',
  };

  it('Directory → IDaaS の同期エッジを捕まえられる', () => {
    const out = detectThreats({
      nodes: [ad, entra],
      edges: [sync],
      framework: 'STRIDE',
      rules: [
        edgeRule({
          semantic: ['directory_sync'],
          sourceIdentityProviderKind: ['Directory'],
          targetIdentityProviderKind: ['IDaaS'],
        }),
      ],
    });
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe('identity-edge-e-sync');
  });

  it('向きが逆（IDaaS → Directory）なら発火しない', () => {
    const reversed: DiagramEdge = { ...sync, id: 'e-rev', source: 'entra', target: 'ad' };
    const out = detectThreats({
      nodes: [ad, entra],
      edges: [reversed],
      framework: 'STRIDE',
      rules: [
        edgeRule({
          sourceIdentityProviderKind: ['Directory'],
          targetIdentityProviderKind: ['IDaaS'],
        }),
      ],
    });
    expect(out).toHaveLength(0);
  });

  it('種別未宣言のノードが端点なら発火しない', () => {
    const toBare: DiagramEdge = { ...sync, id: 'e-bare', target: 'bare' };
    const out = detectThreats({
      nodes: [ad, bareIdp],
      edges: [toBare],
      framework: 'STRIDE',
      rules: [edgeRule({ targetIdentityProviderKind: ['IDaaS'] })],
    });
    expect(out).toHaveLength(0);
  });
});

describe('edge 軸: authProvider（発行元の宣言状態）', () => {
  const local: DiagramEdge = {
    id: 'e-local',
    source: 'app',
    target: 'entra',
    auth: 'Password',
    network: 'VPC',
    encryption: 'TLS',
  };
  const federated: DiagramEdge = { ...local, id: 'e-fed', authProviderId: 'entra' };

  it('Undeclared: 認証ありで発行元未設定＝ローカル資格情報を捕まえる', () => {
    const out = detectThreats({
      nodes: [app, entra],
      edges: [local, federated],
      framework: 'STRIDE',
      rules: [edgeRule({ auth: ['Password', 'MFA'], authProvider: ['Undeclared'] })],
    });
    expect(out.map((t) => t.id)).toEqual(['identity-edge-e-local']);
  });

  it('Declared: 発行元が設定されたエッジだけで発火する', () => {
    const out = detectThreats({
      nodes: [app, entra],
      edges: [local, federated],
      framework: 'STRIDE',
      rules: [edgeRule({ authProvider: ['Declared'] })],
    });
    expect(out.map((t) => t.id)).toEqual(['identity-edge-e-fed']);
  });

  it('authProvider を指定しない既存ルールの挙動は変わらない', () => {
    const out = detectThreats({
      nodes: [app, entra],
      edges: [local, federated],
      framework: 'STRIDE',
      rules: [edgeRule({ auth: ['Password'] })],
    });
    expect(out).toHaveLength(2);
  });
});
