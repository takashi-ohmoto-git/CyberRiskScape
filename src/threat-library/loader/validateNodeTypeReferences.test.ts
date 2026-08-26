import { describe, expect, it } from 'vitest';
import { collectReferencedNodeTypes } from './validateNodeTypeReferences';
import type { ThreatRule } from '../schema/threatRule';

const baseRule = {
  framework: 'STRIDE' as const,
  category: 'x',
  severity: 'Low' as const,
  description: 'y',
};

describe('collectReferencedNodeTypes', () => {
  it('node ルール: nodeType を 1 件抽出する', () => {
    const rule: ThreatRule = {
      ...baseRule,
      id: 'r1',
      appliesTo: { kind: 'node', nodeType: 'LLM' },
    };
    expect(collectReferencedNodeTypes([rule])).toEqual([{ ruleId: 'r1', nodeType: 'LLM' }]);
  });

  it('node ルール: anyOf の全リーフを抽出する', () => {
    const rule: ThreatRule = {
      ...baseRule,
      id: 'r2',
      appliesTo: {
        kind: 'node',
        anyOf: [{ nodeType: 'LLM' }, { nodeType: 'AGENT' }],
      },
    };
    const refs = collectReferencedNodeTypes([rule]);
    expect(refs.map((r) => r.nodeType).sort()).toEqual(['AGENT', 'LLM']);
  });

  it('node ルール: connection.peerType を抽出する', () => {
    const rule: ThreatRule = {
      ...baseRule,
      id: 'r3',
      appliesTo: {
        kind: 'node',
        nodeType: 'LLM',
        connection: { peerType: ['USER', 'GATEWAY'] },
      },
    };
    const refs = collectReferencedNodeTypes([rule]);
    expect(refs.map((r) => r.nodeType).sort()).toEqual(['GATEWAY', 'LLM', 'USER']);
  });

  it('edge ルール: when の sourceType / targetType を抽出する', () => {
    const rule: ThreatRule = {
      ...baseRule,
      id: 'r4',
      appliesTo: {
        kind: 'edge',
        when: { sourceType: ['USER'], targetType: ['LLM', 'AGENT'] },
      },
    };
    const refs = collectReferencedNodeTypes([rule]);
    expect(refs.map((r) => r.nodeType).sort()).toEqual(['AGENT', 'LLM', 'USER']);
  });

  it('edge ルール: allOf / anyOf / conditions すべてを抽出する', () => {
    const rule: ThreatRule = {
      ...baseRule,
      id: 'r5',
      appliesTo: {
        kind: 'edge',
        anyOf: [{ targetType: ['TOOL'] }, { sourceType: ['AGENT'] }],
        conditions: [{ when: { targetType: ['DB'] }, severity: 'High' }],
      },
    };
    const refs = collectReferencedNodeTypes([rule]);
    expect(refs.map((r) => r.nodeType).sort()).toEqual(['AGENT', 'DB', 'TOOL']);
  });

  it('複数ルールをまとめて処理できる', () => {
    const rules: ThreatRule[] = [
      { ...baseRule, id: 'a', appliesTo: { kind: 'node', nodeType: 'LLM' } },
      { ...baseRule, id: 'b', appliesTo: { kind: 'node', nodeType: 'AGENT' } },
    ];
    expect(collectReferencedNodeTypes(rules)).toHaveLength(2);
  });
});
