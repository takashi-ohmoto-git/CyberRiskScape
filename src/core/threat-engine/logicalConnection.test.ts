import { describe, expect, it } from 'vitest';
import { detectThreats } from './detectThreats';
import type { DiagramEdge, DiagramNode } from '../model/types';
import type { ThreatRule } from '../../threat-library/schema/threatRule';

/**
 * 発行元として参照されたノードを「論理的に接続されている」とみなす挙動
 * （[[plan]] §2.40、ユーザー判断 2026-09-20）。
 *
 * 全コンポーネントを IdP へ線で繋ぐのは実務上非現実的なので、`authProviderId` の参照を
 * 接続の一形態として扱う。ただし `direction` / `peerType` を指定するルールは実エッジのみ。
 */
const idp: DiagramNode = { id: 'idp', type: 'IDENTITY_PROVIDER', x: 0, y: 0 };
const user: DiagramNode = { id: 'u', type: 'USER', x: 100, y: 0 };
const app: DiagramNode = { id: 'app', type: 'PROCESS', x: 200, y: 0 };

/** idp に触れないが idp を発行元として宣言するエッジ。 */
const refEdge: DiagramEdge = {
  id: 'e1',
  source: 'u',
  target: 'app',
  auth: 'MFA',
  network: 'VPC',
  encryption: 'TLS',
  authProviderId: 'idp',
};

/** IDENTITY_PROVIDER を対象にする最小のノードルール。`connection` だけを差し替える。 */
function rule(connection?: Record<string, unknown>): ThreatRule {
  return {
    id: 'idp-rule',
    framework: 'STRIDE',
    category: 'Denial of Service',
    severity: 'Medium',
    description: 'idp rule',
    appliesTo: { kind: 'node', nodeType: 'IDENTITY_PROVIDER', ...connection },
  } as ThreatRule;
}

function fired(nodes: DiagramNode[], edges: DiagramEdge[], r: ThreatRule): string[] {
  return detectThreats({ nodes, edges, framework: 'STRIDE', rules: [r] }).map((t) => t.nodeId);
}

describe('authProviderId による論理接続', () => {
  it('参照だけで素の接続要件を満たす（エッジが触れていなくても発火）', () => {
    expect(fired([idp, user, app], [refEdge], rule())).toEqual(['idp']);
  });

  it('参照もエッジも無い IdP は発火しない（未使用はノイズにしない）', () => {
    const plain: DiagramEdge = { ...refEdge, id: 'e2', authProviderId: undefined };
    expect(fired([idp, user, app], [plain], rule())).toEqual([]);
  });

  it('依存先が解決できない参照でも「使われている」事実は成立する', () => {
    const dangling: DiagramEdge = { ...refEdge, id: 'e3', target: 'gone' };
    expect(fired([idp, user], [dangling], rule())).toEqual(['idp']);
  });

  it('direction を指定したルールは参照では満たされない（実エッジのみ）', () => {
    const r = rule({ connection: { required: true, direction: 'inbound' } });
    expect(fired([idp, user, app], [refEdge], r)).toEqual([]);
  });

  it('peerType を指定したルールも参照では満たされない', () => {
    const r = rule({ connection: { required: true, peerType: ['USER'] } });
    expect(fired([idp, user, app], [refEdge], r)).toEqual([]);
  });

  it('direction 指定でも実エッジがあれば従来どおり発火する', () => {
    const real: DiagramEdge = {
      id: 'e4',
      source: 'u',
      target: 'idp',
      auth: 'MFA',
      network: 'VPC',
      encryption: 'TLS',
    };
    const r = rule({ connection: { required: true, direction: 'inbound' } });
    expect(fired([idp, user, app], [real], r)).toEqual(['idp']);
  });

  it('connection.required=false の挙動は不変（参照の有無に関わらず発火）', () => {
    const r = rule({ connection: { required: false } });
    expect(fired([idp, user, app], [], r)).toEqual(['idp']);
  });
});
