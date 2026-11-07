import { describe, expect, it } from 'vitest';
import type { LayerAnalysisResult } from './analyze';
import { evaluateSavedFindingsGate, formatGateFinding } from './findingsGate';
import { EMPTY_PROJECT_META, type DiagramNode, type Finding, type ThreatView } from '../core/model/types';

const NODES: DiagramNode[] = [{ id: 'n1', seq: 1, type: 'LLM', x: 0, y: 0, label: 'GPT' }];

const threat = (id: string, suppressed = false): ThreatView => ({
  id,
  ruleId: id,
  subject: { kind: 'node', id: 'n1' },
  nodeId: 'n1',
  framework: 'AI',
  category: '情報漏えい',
  severity: 'High',
  description: 'd',
  origin: 'detected',
  canonicalId: 'canon-a',
  ...(suppressed ? { suppression: { status: 'accepted' as const, note: '受容', at: 0 } } : {}),
});

function results(threats: ThreatView[]): LayerAnalysisResult[] {
  return [
    {
      layer: 'L1',
      threats,
      input: {
        threats,
        nodes: NODES,
        edges: [],
        boundaries: [],
        projectMeta: EMPTY_PROJECT_META,
        framework: 'ALL',
        layer: 'L1',
      },
    },
  ];
}

const finding = (over: Partial<Finding>): Finding => ({
  id: 'Prowler:f1',
  source: { format: 'ocsf', product: 'Prowler', importedAt: 't' },
  externalId: 'f1',
  identifiers: [{ scheme: 'prowler-check', value: 'chk_a' }],
  title: '指摘 A',
  severity: 'High',
  canonicalIds: ['canon-a'],
  subject: { layer: 'L1', nodeId: 'n1' },
  ...over,
});

describe('evaluateSavedFindingsGate', () => {
  it('しきい値以上の指摘だけを数える', () => {
    const list = [finding({ id: 'a', severity: 'Critical' }), finding({ id: 'b', severity: 'High' }), finding({ id: 'c', severity: 'Medium' })];
    expect(evaluateSavedFindingsGate(list, results([]), 'High').map((f) => f.id)).toEqual(['a', 'b']);
    expect(evaluateSavedFindingsGate(list, results([]), 'Critical').map((f) => f.id)).toEqual(['a']);
    expect(evaluateSavedFindingsGate(list, results([]), 'Low')).toHaveLength(3);
  });

  it('findings が無ければ常に合格', () => {
    expect(evaluateSavedFindingsGate([], results([threat('t1')]), 'Low')).toEqual([]);
  });

  it('outcome が attempted の指摘は数えない', () => {
    expect(evaluateSavedFindingsGate([finding({ outcome: 'attempted' })], results([]), 'Low')).toEqual([]);
  });

  it('outcome が unverified（要確認）の指摘は数えない', () => {
    expect(evaluateSavedFindingsGate([finding({ outcome: 'unverified' })], results([]), 'Low')).toEqual([]);
  });

  it('結び付く脅威がすべて抑制されていれば除外する', () => {
    const r = results([threat('t1', true), threat('t2', true)]);
    expect(evaluateSavedFindingsGate([finding({})], r, 'High')).toEqual([]);
  });

  it('結び付く脅威の一部だけ抑制なら数える', () => {
    const r = results([threat('t1', true), threat('t2')]);
    expect(evaluateSavedFindingsGate([finding({})], r, 'High')).toHaveLength(1);
  });

  it('結び付く脅威が無い指摘は数える（canonicalId 不一致・未結合）', () => {
    const list = [finding({ id: 'a', canonicalIds: ['other'] }), finding({ id: 'b', subject: undefined })];
    expect(evaluateSavedFindingsGate(list, results([threat('t1', true)]), 'High')).toHaveLength(2);
  });

  it('ノードが消えた指摘は数える', () => {
    const f = finding({ subject: { layer: 'L1', nodeId: 'gone' } });
    expect(evaluateSavedFindingsGate([f], results([threat('t1', true)]), 'High')).toHaveLength(1);
  });
});

describe('formatGateFinding', () => {
  it('重大度・製品・タイトル・ノードを出す', () => {
    expect(formatGateFinding(finding({}), results([]))).toBe('[High] Prowler: 指摘 A @ GPT');
  });

  it('タイトルが無ければ識別子、ノードが無ければ省く', () => {
    expect(formatGateFinding(finding({ title: undefined, subject: undefined }), results([]))).toBe('[High] Prowler: chk_a');
  });
});
