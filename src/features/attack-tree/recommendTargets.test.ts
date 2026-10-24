import { describe, expect, it } from 'vitest';
import { aggregatePriorityDefenses, recommendTargets } from './recommendTargets';
import type { DiagramEdge, DiagramNode, NodePosture, ThreatView } from '../../core/model/types';

function node(id: string, type: string, extra: Partial<DiagramNode> = {}): DiagramNode {
  return { id, type, x: 0, y: 0, ...extra };
}

// 内部リンクの既定は VPC。網をインターネットにすると内部ノードまで侵入候補扱いになるため。
function edge(id: string, source: string, target: string): DiagramEdge {
  return { id, source, target, auth: 'None', network: 'VPC', encryption: 'Plain' };
}

function threat(nodeId: string, severity: ThreatView['severity'], extra: Partial<ThreatView> = {}): ThreatView {
  return { id: `${nodeId}-${severity}`, origin: 'detected', nodeId, framework: 'STRIDE', category: 'c', severity, description: 'd', ...extra } as ThreatView;
}

const attacker = node('atk', 'AGENTIC_ATTACKER');
const ids = (r: ReturnType<typeof recommendTargets>) => r.map((c) => c.nodeId);

describe('recommendTargets', () => {
  it('認証系と機微データ系を候補にし、認証系（枝を開く）を先に並べる', () => {
    const r = recommendTargets(
      [attacker, node('vault', 'SECRETS_VAULT'), node('db', 'DATABASE'), node('pii', 'PERSONAL_INFO', { parentId: 'db' }), node('web', 'FRONT_END_SERVER')],
      [],
      [],
      [],
      'atk',
    );
    expect(ids(r)).toEqual(['vault', 'db']); // web（公開サーバー）は標的の候補ではない
    expect(r[0]).toMatchObject({ category: 'credential', reasons: ['credentialHolder'] });
    expect(r[1]).toMatchObject({ category: 'data', reasons: ['sensitiveData'] });
  });

  it('大量件数（1M 以上）の機微データには highVolume を付け、到達性・重大度・件数で並べる', () => {
    const vol = (v: NodePosture['recordVolume']): Partial<DiagramNode> => ({ posture: { recordVolume: v } });
    const r = recommendTargets(
      [
        attacker,
        node('reached', 'DATABASE', { seq: 1 }),
        node('reachedPii', 'PERSONAL_INFO', { parentId: 'reached', ...vol('Over1M') }),
        node('isolated', 'DATABASE', { seq: 2 }),
        node('isolatedPii', 'CONFIDENTIAL_INFO', { parentId: 'isolated' }),
      ],
      [edge('e1', 'atk', 'reached')],
      [],
      [threat('reachedPii', 'High')],
      'atk',
    );
    // reached は攻撃者から到達でき、Over1M の件数。isolated はどこともつながらず到達不可で後ろ。
    expect(ids(r)).toEqual(['reached', 'isolated']);
    expect(r[0]).toMatchObject({ reachable: true, recordVolume: 'Over1M', maxSeverity: 'High', reasons: ['sensitiveData', 'highVolume'] });
    expect(r[1].reachable).toBe(false);
  });

  it('攻撃者が AI エージェント攻撃者でなければ空', () => {
    expect(recommendTargets([node('t', 'THREAT_ACTOR'), node('v', 'SECRETS_VAULT')], [], [], [], 't')).toEqual([]);
  });
});

describe('aggregatePriorityDefenses', () => {
  it('複数の推奨標的の経路に共通して現れる経由点を、通過した標的の数の多い順に集計する', () => {
    // atk --(entry: 攻撃者からの線)--> gw -> vault / gw -> db。gw が両標的の共通経由点。
    const nodes = [
      attacker,
      node('gw', 'GATEWAY'),
      node('vault', 'SECRETS_VAULT'),
      node('db', 'DATABASE'),
      node('pii', 'PERSONAL_INFO', { parentId: 'db' }),
    ];
    const edges = [edge('e0', 'atk', 'gw'), edge('e1', 'gw', 'vault'), edge('e2', 'gw', 'db')];
    const recs = recommendTargets(nodes, edges, [], [], 'atk');
    expect(ids(recs).sort()).toEqual(['db', 'vault']);

    const defenses = aggregatePriorityDefenses(nodes, edges, [], [], 'atk', recs);
    const top = defenses.find((d) => d.elementKey === 'node:gw');
    expect(top?.targetHits).toBe(2); // vault と db の両方の経路が gw を通る
    // 標的そのもの（終点）は経由点として数えない
    expect(defenses.some((d) => d.elementKey === 'node:vault' || d.elementKey === 'node:db')).toBe(false);
    // 共通経由点が先頭（最も多くの標的を 1 つの対策で守れる）
    expect(defenses[0].elementKey).toBe('node:gw');
  });

  it('到達できない標的は集計に含めない', () => {
    const nodes = [attacker, node('gw', 'GATEWAY'), node('vault', 'SECRETS_VAULT'), node('lone', 'PAM')];
    const edges = [edge('e0', 'atk', 'gw'), edge('e1', 'gw', 'vault')];
    const recs = recommendTargets(nodes, edges, [], [], 'atk');
    const defenses = aggregatePriorityDefenses(nodes, edges, [], [], 'atk', recs);
    // lone はどこともつながらず経路が無いので、集計に寄与しない（gw は vault の 1 経路のみ）
    expect(defenses.find((d) => d.elementKey === 'node:gw')?.targetHits).toBe(1);
  });
});
