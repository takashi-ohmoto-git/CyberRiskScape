import { describe, expect, it } from 'vitest';
import { collectPathTechniques } from './collectPathTechniques';
import type { AttackGraphResult } from '../attack-tree/buildAttackGraph';
import type { AnalyzeGraphResult } from '../attack-tree/analyzeAttackGraph';
import type { ThreatView } from '../../core/model/types';

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

// 攻撃者 A → n1 → n2（標的）。ホップ A--n1 は e1、n1--n2 は e2。
const graph: AttackGraphResult = {
  nodeIds: ['A', 'n1', 'n2'],
  hops: new Map([
    ['A--n1', { key: 'A--n1', a: 'A', b: 'n1', edgeIds: ['e1'] }],
    ['n1--n2', { key: 'n1--n2', a: 'n1', b: 'n2', edgeIds: ['e2'] }],
  ]),
  routes: [{ nodeIds: ['A', 'n1', 'n2'], hopKeys: ['A--n1', 'n1--n2'] }],
  channelCombinations: 1,
  truncated: false,
};
const analysis = {
  routes: [{ route: graph.routes[0], cost: 1, feasible: true }],
} as unknown as AnalyzeGraphResult;

const ref = (title: string) => [{ title }];

describe('collectPathTechniques', () => {
  it('経路上のノード・エッジの脅威は onPath で歩数を持つ', () => {
    const r = collectPathTechniques(
      [
        threat({ id: 'a', nodeId: 'n1', references: ref('T1078') }),
        threat({ id: 'b', nodeId: 'e2', subject: { kind: 'edge', id: 'e2' }, references: ref('T1190') }),
      ],
      graph,
      analysis,
      'A',
    );
    expect(r.get('T1078')).toMatchObject({ onPath: true, steps: [1] });
    expect(r.get('T1190')).toMatchObject({ onPath: true, steps: [2] });
  });

  it('経路外の脅威は onPath=false で含まれる', () => {
    const r = collectPathTechniques([threat({ nodeId: 'zzz', references: ref('T1078') })], graph, analysis, 'A');
    expect(r.get('T1078')).toMatchObject({ onPath: false, steps: [] });
  });

  it('抑制済みの脅威は除外する', () => {
    const r = collectPathTechniques(
      [threat({ references: ref('T1078'), suppression: { status: 'accepted' } as ThreatView['suppression'] })],
      graph,
      analysis,
      'A',
    );
    expect(r.size).toBe(0);
  });

  it('サブテクニックは ID のまま返し、URL 形式 T1078/004 も正規化する', () => {
    const r = collectPathTechniques(
      [threat({ references: [{ title: 'x', url: 'https://attack.mitre.org/techniques/T1078/004' }] })],
      graph,
      analysis,
      'A',
    );
    expect(r.has('T1078.004')).toBe(true);
    expect(r.has('T1078')).toBe(false);
  });

  it('複数経路に載る要素は全歩数を昇順で持ち、最大 severity を取る', () => {
    const g2: AttackGraphResult = {
      ...graph,
      nodeIds: ['A', 'n1', 'n2', 'n3'],
      routes: [graph.routes[0], { nodeIds: ['A', 'n2', 'n1', 'n3'], hopKeys: ['A--n2', 'n1--n2', 'n1--n3'] }],
    };
    const a2 = {
      routes: [
        { route: g2.routes[0], cost: 1, feasible: true },
        { route: g2.routes[1], cost: 2, feasible: true },
      ],
    } as unknown as AnalyzeGraphResult;
    const r = collectPathTechniques(
      [
        threat({ id: 'a', nodeId: 'n1', severity: 'Low', references: ref('T1078') }),
        threat({ id: 'b', nodeId: 'n1', severity: 'Critical', references: ref('T1078') }),
      ],
      g2,
      a2,
      'A',
    );
    expect(r.get('T1078')?.steps).toEqual([1, 2]);
    expect(r.get('T1078')?.severity).toBe('Critical');
    expect(r.get('T1078')?.hits).toHaveLength(2);
  });

  it('ATLAS の ID とマトリクスに無い ID は含めない', () => {
    const r = collectPathTechniques(
      [threat({ references: ref('AML.T0051 and T9999') })],
      graph,
      analysis,
      'A',
    );
    expect(r.size).toBe(0);
  });

  describe('framework=f3', () => {
    const f3 = (t: Partial<ThreatView>) => collectPathTechniques([threat(t)], graph, analysis, 'A', 'f3');

    it('complianceRefs の mitre-f3 の ref を数え、歩数も持つ', () => {
      const r = f3({ complianceRefs: [{ standard: 'mitre-f3', ref: 'F1006' }] });
      expect(r.get('F1006')).toMatchObject({ onPath: true, steps: [1] });
    });

    it('別 standard の ref と、F3 に無い ID は数えない', () => {
      expect(f3({ complianceRefs: [{ standard: 'nist-csf', ref: 'F1006' }] }).size).toBe(0);
      expect(f3({ complianceRefs: [{ standard: 'mitre-f3', ref: 'F9999' }] }).size).toBe(0);
    });

    it('references の ATT&CK ID は F3 に存在するものだけ数える', () => {
      // T1110 は F3 が再利用、T1078 は F3 に無い
      const r = f3({ references: ref('T1110 and T1078') });
      expect(r.has('T1110')).toBe(true);
      expect(r.has('T1078')).toBe(false);
    });

    it('ATT&CK ビューは complianceRefs の影響を受けない', () => {
      const r = collectPathTechniques(
        [threat({ complianceRefs: [{ standard: 'mitre-f3', ref: 'F1006' }], references: ref('T1078') })],
        graph,
        analysis,
        'A',
      );
      expect([...r.keys()]).toEqual(['T1078']);
    });
  });
});
