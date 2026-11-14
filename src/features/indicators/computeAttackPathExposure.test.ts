import { describe, expect, it } from 'vitest';
import { computeAttackPathExposure } from './computeAttackPathExposure';
import type { LayerContext } from '../attack-tree/prioritizeFindings';
import type { DiagramEdge, DiagramNode, Severity, ThreatView } from '../../core/model/types';

function node(id: string, type: string, extra: Partial<DiagramNode> = {}): DiagramNode {
  return { id, type, x: 0, y: 0, ...extra } as DiagramNode;
}

function edge(id: string, source: string, target: string): DiagramEdge {
  return { id, source, target, auth: 'MFA', network: 'VPC', encryption: 'TLS' };
}

function threat(id: string, nodeId: string, severity: Severity, extra: Partial<ThreatView> = {}): ThreatView {
  return {
    id,
    nodeId,
    subject: { kind: 'node', id: nodeId },
    framework: 'STRIDE',
    category: 'Tampering',
    severity,
    description: '',
    origin: 'detected',
    ...extra,
  } as ThreatView;
}

function edgeThreat(id: string, edgeId: string, targetNodeId: string, severity: Severity): ThreatView {
  return threat(id, targetNodeId, severity, { subject: { kind: 'edge', id: edgeId } });
}

/** 入口の設定を全部入力した公開サーバー（仮定なし）。 */
const FIRM = { hasGlobalIp: true, hasUserAuthentication: true, hasSourceIpRestriction: true, hasRemoteAccessRestriction: true, hasWafProtection: true };

const atk = node('atk', 'AGENTIC_ATTACKER');
// web(入口) - mid - pii(標的)。side は web にだけ繋がり標的への経路の外。iso は線なし。
const nodes = [
  atk,
  node('web', 'FRONT_END_SERVER', { attackSurface: FIRM }),
  node('mid', 'DB'),
  node('pii', 'PERSONAL_INFO'),
  node('side', 'DB'),
  node('iso', 'DB'),
];
const edges = [edge('e1', 'web', 'mid'), edge('e2', 'mid', 'pii'), edge('e3', 'web', 'side')];

function ctx(threats: ThreatView[], ns: DiagramNode[] = nodes, es: DiagramEdge[] = edges): LayerContext[] {
  return [{ layer: 'L1', nodes: ns, edges: es, boundaries: [], threats }];
}

describe('computeAttackPathExposure', () => {
  it('攻撃者 → 標的の経路上（標的自身と経路の線を含む）の未対策の脅威だけを数え、重大度で重みを付ける', () => {
    const r = computeAttackPathExposure(
      ctx([
        threat('web', 'web', 'High'),
        threat('mid-done', 'mid', 'Medium', { controlStatus: { status: 'implemented' } as ThreatView['controlStatus'] }),
        threat('pii', 'pii', 'Critical'),
        edgeThreat('e2', 'e2', 'pii', 'Low'),
        threat('side', 'side', 'Critical'),
        edgeThreat('e3', 'e3', 'side', 'High'),
        threat('iso', 'iso', 'High'),
      ]),
    );
    expect(r).toMatchObject({ targets: 1, exposedTargets: 1, onPath: 4, open: 3, openWeighted: 8 + 4 + 1, truncated: false });
  });

  it('誤検知・適用外は数えない。受容は未対策として残る', () => {
    const r = computeAttackPathExposure(
      ctx([
        threat('fp', 'mid', 'Critical', { suppression: { status: 'false-positive' } as ThreatView['suppression'] }),
        threat('na', 'mid', 'Critical', { controlStatus: { status: 'not-applicable' } as ThreatView['controlStatus'] }),
        threat('acc', 'mid', 'High', { suppression: { status: 'accepted' } as ThreatView['suppression'] }),
      ]),
    );
    expect(r).toMatchObject({ onPath: 1, open: 1, openWeighted: 4, exposedTargets: 1 });
  });

  it('経路上の脅威がすべて実装済みなら、届く標的はあっても未対策は 0', () => {
    const done = { controlStatus: { status: 'implemented' } as ThreatView['controlStatus'] };
    const r = computeAttackPathExposure(ctx([threat('web', 'web', 'High', done), threat('pii', 'pii', 'Critical', done)]));
    expect(r).toMatchObject({ targets: 1, exposedTargets: 0, onPath: 2, open: 0, openWeighted: 0 });
  });

  it('内包された資産の脅威は親のノードが経路上にあれば数える', () => {
    const ns = [atk, node('web', 'FRONT_END_SERVER', { attackSurface: FIRM }), node('store', 'DB'), node('pii', 'PERSONAL_INFO', { parentId: 'store' })];
    const r = computeAttackPathExposure(ctx([threat('child', 'pii', 'High')], ns, [edge('e1', 'web', 'store')]));
    expect(r).toMatchObject({ targets: 1, onPath: 1, open: 1 });
  });

  it('攻撃者のノードがどのレイヤーにも無ければ null（評価できない）', () => {
    const r = computeAttackPathExposure(ctx([threat('web', 'web', 'High')], nodes.filter((n) => n.id !== 'atk')));
    expect(r).toBeNull();
  });

  it('攻撃者はいるが届く標的が無ければ 0 件（null ではない）', () => {
    const ns = [atk, node('web', 'FRONT_END_SERVER', { attackSurface: FIRM }), node('mid', 'DB')];
    const r = computeAttackPathExposure(ctx([threat('web', 'web', 'High')], ns, [edge('e1', 'web', 'mid')]));
    expect(r).toMatchObject({ targets: 0, exposedTargets: 0, onPath: 0, open: 0 });
  });
});
