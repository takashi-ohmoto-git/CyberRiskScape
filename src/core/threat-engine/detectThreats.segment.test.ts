import { describe, expect, it } from 'vitest';
import { detectThreats } from './detectThreats';
import type { DiagramBoundary, DiagramEdge, DiagramNode } from '../model/types';
import { ThreatRuleSchema, type ThreatRule } from '../../threat-library/schema/threatRule';

/**
 * 所属区画の軸（ノード `segment`、エッジ `sourceSegment` / `targetSegment` / `segmentRelation`）。
 *
 * 押さえる点：
 * - 区画は最内側の ROUNDED_DASHED から導出する派生値で、図に保存しない。
 * - 区画外のノードは environment / sensitiveData の条件で不成立。
 * - 区画の条件を持たないルールの挙動は不変。
 */

// 開発区画（未適用）と本番区画（適用済み・機密情報）を横に並べる。
const devSeg: DiagramBoundary = {
  id: 'dev',
  type: 'ROUNDED_DASHED',
  x: 0,
  y: 0,
  width: 400,
  height: 400,
  trustLevel: 'Internal',
  microTrust: 'Development',
  microSegmentationStatus: '未適用',
  sensitiveData: '無し',
};
const prodSeg: DiagramBoundary = {
  ...devSeg,
  id: 'prod',
  x: 600,
  microTrust: 'Production',
  microSegmentationStatus: '適用済み',
  sensitiveData: '機密情報',
};
const boundaries = [devSeg, prodSeg];

const devApp: DiagramNode = { id: 'devApp', type: 'PROCESS', x: 100, y: 100 };
const devDb: DiagramNode = { id: 'devDb', type: 'DATA_STORE', x: 100, y: 250 };
const prodDb: DiagramNode = { id: 'prodDb', type: 'DATA_STORE', x: 700, y: 100 };
const outside: DiagramNode = { id: 'outside', type: 'DATA_STORE', x: 2000, y: 2000 };
const nodes = [devApp, devDb, prodDb, outside];

function edge(id: string, source: string, target: string): DiagramEdge {
  return { id, source, target, auth: 'MFA', network: 'VPC', encryption: 'TLS' };
}
const edges = [
  edge('e-same', 'devApp', 'devDb'),
  edge('e-cross', 'devApp', 'prodDb'),
  edge('e-out', 'devApp', 'outside'),
];

function rule(appliesTo: Record<string, unknown>): ThreatRule {
  return ThreatRuleSchema.parse({
    id: 'r',
    framework: 'STRIDE',
    category: 'Elevation of Privilege',
    severity: 'Medium',
    description: 'base',
    appliesTo,
  });
}

const run = (r: ThreatRule) =>
  detectThreats({ nodes, edges, framework: 'ALL', rules: [r], boundaries });
const subjects = (r: ThreatRule) => run(r).map((t) => t.subject?.id).sort();

describe('node appliesTo.segment', () => {
  it('status で絞る', () => {
    const r = rule({ kind: 'node', nodeType: 'DATA_STORE', segment: { status: ['NotEnforced'] } });
    expect(subjects(r)).toEqual(['devDb']);
  });

  it('区画外のノードは environment / sensitiveData の条件で不成立', () => {
    const r = rule({
      kind: 'node',
      nodeType: 'DATA_STORE',
      segment: { sensitiveData: ['None', 'PersonalData', 'Confidential'] },
    });
    expect(subjects(r)).toEqual(['devDb', 'prodDb']);
  });

  it('Unsegmented は区画外のノードに当たる', () => {
    const r = rule({ kind: 'node', nodeType: 'DATA_STORE', segment: { status: ['Unsegmented'] } });
    expect(subjects(r)).toEqual(['outside']);
  });

  it('区画の条件が無いルールは境界の有無に関係なく従来どおり発火する', () => {
    const r = rule({ kind: 'node', nodeType: 'DATA_STORE' });
    expect(subjects(r)).toEqual(['devDb', 'outside', 'prodDb']);
  });

  it('conditions の segment で severity を上げる（発火の可否は変えない）', () => {
    const r = rule({
      kind: 'node',
      nodeType: 'DATA_STORE',
      conditions: [{ when: { segment: { sensitiveData: ['Confidential'] } }, severity: 'High' }],
    });
    const bySubject = new Map(run(r).map((t) => [t.subject?.id, t.severity]));
    expect(bySubject.get('prodDb')).toBe('High');
    expect(bySubject.get('devDb')).toBe('Medium');
    expect(bySubject.get('outside')).toBe('Medium');
  });
});

describe('edge の区画軸', () => {
  it('segmentRelation で同一区画・別区画を分ける', () => {
    expect(subjects(rule({ kind: 'edge', when: { segmentRelation: ['Same'] } }))).toEqual([
      'e-same',
    ]);
    expect(subjects(rule({ kind: 'edge', when: { segmentRelation: ['Cross'] } }))).toEqual([
      'e-cross',
      'e-out',
    ]);
  });

  it('開発区画 → 本番区画の通信を source / target の environment で捕まえる', () => {
    const r = rule({
      kind: 'edge',
      when: {
        sourceSegment: { environment: ['Development', 'Staging'] },
        targetSegment: { environment: ['Production'] },
      },
    });
    expect(subjects(r)).toEqual(['e-cross']);
  });

  it('targetSegment の status で絞る', () => {
    const r = rule({ kind: 'edge', when: { targetSegment: { status: ['Enforced'] } } });
    expect(subjects(r)).toEqual(['e-cross']);
  });
});

describe('schema', () => {
  it('空の segment は拒否する', () => {
    const result = ThreatRuleSchema.safeParse({
      id: 'r',
      framework: 'STRIDE',
      category: 'x',
      severity: 'Low',
      description: 'd',
      appliesTo: { kind: 'node', nodeType: 'DATA_STORE', segment: {} },
    });
    expect(result.success).toBe(false);
  });
});
