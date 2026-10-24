import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { buildNavigatorLayer, navigatorLayerToJson, type NavigatorInput } from './buildNavigatorLayer';
import { analyzeProject } from '../../cli/analyze';
import { EMPTY_PROJECT_META, type DiagramEdge, type DiagramNode, type ThreatView } from '../../core/model/types';

const NOW = new Date('2026-10-20T12:00:00Z');

function threat(partial: Partial<ThreatView>): ThreatView {
  return {
    id: 't1',
    origin: 'detected',
    nodeId: 'n1',
    framework: 'STRIDE',
    category: 'c',
    severity: 'High',
    description: 'd',
    ...partial,
  } as ThreatView;
}

const base = (threats: ThreatView[]): NavigatorInput => ({
  projectMeta: EMPTY_PROJECT_META,
  nodes: [],
  edges: [],
  threats,
});

describe('buildNavigatorLayer', () => {
  it('references から ATT&CK technique を拾い、ATLAS は分離する', () => {
    const layer = buildNavigatorLayer(
      base([
        threat({
          name: 'A',
          severity: 'Critical',
          references: [{ title: 'ATT&CK T1078.004', url: 'https://attack.mitre.org/techniques/T1078/004' }],
        }),
        threat({
          id: 't2',
          name: 'B',
          severity: 'Medium',
          references: [{ title: 'MITRE ATLAS AML.T0051', url: 'https://atlas.mitre.org/techniques/AML.T0051' }],
        }),
      ]),
      NOW,
      'ja',
    );
    expect(layer.domain).toBe('enterprise-attack');
    expect(layer.techniques.map((x) => x.techniqueID)).toContain('T1078.004');
    // ATLAS の AML.T0051 は Enterprise technique に混ざらない
    expect(layer.techniques.map((x) => x.techniqueID)).not.toContain('T0051');
    expect(layer.atlasTechniques).toContain('AML.T0051');
    expect(layer.techniques.find((x) => x.techniqueID === 'T1078.004')?.score).toBe(100);
  });

  it('同じ technique は最大 severity で畳み込み、脅威名を comment に集約する', () => {
    const layer = buildNavigatorLayer(
      base([
        threat({ name: 'low one', severity: 'Low', references: [{ title: 'T1098' }] }),
        threat({ id: 't2', name: 'high one', severity: 'High', references: [{ title: 'T1098' }] }),
      ]),
      NOW,
      'ja',
    );
    const tech = layer.techniques.find((x) => x.techniqueID === 'T1098');
    expect(tech?.score).toBe(75); // High が勝つ
    expect(tech?.comment).toContain('low one');
    expect(tech?.comment).toContain('high one');
  });

  it('URL のサブ technique 表記（T1505/003）を親の T1505 と誤認しない', () => {
    const layer = buildNavigatorLayer(
      base([
        threat({
          references: [
            { title: 'MITRE ATT&CK T1505.003 Server Software Component: Web Shell', url: 'https://attack.mitre.org/techniques/T1505/003/' },
            { title: 'ATT&CK のページ', url: 'https://attack.mitre.org/techniques/T1078/004/' },
          ],
        }),
      ]),
      NOW,
      'ja',
    );
    expect(layer.techniques.map((x) => x.techniqueID).sort()).toEqual(['T1078.004', 'T1505.003']);
  });

  it('抑制した脅威と references 無しは拾わない', () => {
    const layer = buildNavigatorLayer(
      base([
        threat({ references: [{ title: 'T1195' }], suppression: { status: 'accepted' } as never }),
        threat({ id: 't2', references: undefined }),
      ]),
      NOW,
      'ja',
    );
    expect(layer.techniques).toHaveLength(0);
  });

  it('JSON は Navigator の標準フィールドのみで、内部フィールドを含まない', () => {
    const parsed = JSON.parse(
      navigatorLayerToJson(
        buildNavigatorLayer(
          base([threat({ references: [{ title: 'T1484.001', url: 'https://atlas.mitre.org/techniques/AML.T0088' }] })]),
          NOW,
          'ja',
        ),
      ),
    );
    expect(parsed.versions.layer).toBe('4.5');
    expect(parsed.techniques[0].techniqueID).toBe('T1484.001');
    expect(parsed.atlasTechniques).toBeUndefined();
    expect(parsed.scenarioCount).toBeUndefined();
    expect(parsed.description).toContain('AML.T0088');
  });

  it('sample-project でも有効な Navigator レイヤー構造を出す', () => {
    const raw = JSON.parse(readFileSync('src/cli/__fixtures__/sample-project.json', 'utf-8'));
    const layer = buildNavigatorLayer(analyzeProject(raw)[0].input, NOW, 'ja');
    expect(layer.versions.layer).toBe('4.5');
    for (const x of layer.techniques) {
      expect(x.techniqueID).toMatch(/^T\d{4}(\.\d{3})?$/);
      expect(x.score).toBeGreaterThan(0);
    }
  });
});

// ── 攻撃者 + objective を持つ手組みの図（test-plan のテストと同じ形）──
const node = (id: string, seq: number, type: string, extra: Partial<DiagramNode> = {}): DiagramNode =>
  ({ id, seq, type, x: 0, y: 0, label: id, ...extra }) as unknown as DiagramNode;
const edge = (id: string, seq: number, source: string, target: string): DiagramEdge => ({
  id,
  seq,
  source,
  target,
  auth: 'None',
  network: 'Internet',
  encryption: 'Plain',
});

function scenarioInput(): NavigatorInput {
  return {
    projectMeta: { ...EMPTY_PROJECT_META, systemName: 'Demo' },
    nodes: [
      node('a', 1, 'THREAT_ACTOR', { attackObjectiveId: 'db' }),
      node('gw', 2, 'GATEWAY'),
      node('db', 3, 'DATABASE'),
      node('other', 4, 'DATABASE'), // どの経路にも載らない
    ],
    edges: [edge('e1', 1, 'a', 'gw'), edge('e2', 2, 'gw', 'db')],
    threats: [
      threat({ id: 'on-gw', nodeId: 'gw', subject: { kind: 'node', id: 'gw' }, name: 'gw 脅威', references: [{ title: 'T1190' }] }),
      threat({ id: 'on-e2', nodeId: 'e2', subject: { kind: 'edge', id: 'e2' }, name: 'e2 脅威', references: [{ title: 'T1557' }] }),
      threat({ id: 'off', nodeId: 'other', subject: { kind: 'node', id: 'other' }, name: '経路外', references: [{ title: 'T1005' }] }),
    ],
  };
}

describe('buildNavigatorLayer（攻撃シナリオ）', () => {
  it('全体のレイヤーでは、経路上の technique にシナリオの metadata が付き、経路外には付かない', () => {
    const layer = buildNavigatorLayer(scenarioInput(), NOW, 'ja');
    expect(layer.scenarioCount).toBe(1);
    const byId = new Map(layer.techniques.map((x) => [x.techniqueID, x]));
    expect(byId.get('T1190')?.metadata?.some((m) => m.name === 'シナリオ' && m.value.includes('C1'))).toBe(true);
    expect(byId.get('T1557')?.metadata?.some((m) => m.name === 'シナリオ')).toBe(true);
    // 経路外の脅威の technique も全体レイヤーには出るが、シナリオの metadata は付かない
    expect(byId.has('T1005')).toBe(true);
    expect(byId.get('T1005')?.metadata).toBeUndefined();
  });

  it('チョークポイント上の脅威の technique にはチョークポイントの metadata が付く', () => {
    const layer = buildNavigatorLayer(scenarioInput(), NOW, 'ja');
    const gw = layer.techniques.find((x) => x.techniqueID === 'T1190');
    expect(gw?.metadata?.some((m) => m.name === 'チョークポイント' && m.value.includes('C2'))).toBe(true);
  });

  it('攻撃者を指定すると、そのシナリオの経路上の脅威だけになる', () => {
    const layer = buildNavigatorLayer(scenarioInput(), NOW, 'ja', { attackerNodeId: 'a' });
    const ids = layer.techniques.map((x) => x.techniqueID).sort();
    expect(ids).toEqual(['T1190', 'T1557']);
    expect(layer.name).toContain('C1');
    expect(layer.description).toContain('攻撃手順は含みません');
  });
});
