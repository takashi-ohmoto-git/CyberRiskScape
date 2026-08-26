import { describe, expect, it } from 'vitest';
import type { ThreatRule } from '../../../threat-library/schema/threatRule';
import {
  draftToRule,
  emptyDraft,
  ruleToDraft,
  type RuleDraft,
} from './draft';

/** 代表ルール群（すべて draftToRule が出力する正規化形）。 */
const fixtures: Record<string, ThreatRule> = {
  nodeSingle: {
    id: 'node-single-001',
    framework: 'STRIDE',
    category: 'Spoofing',
    severity: 'High',
    description: 'static node {{nodeName}}',
    appliesTo: { kind: 'node', nodeType: 'AGENT' },
  },
  nodeAnyOfWithPeerSurface: {
    id: 'node-anyof-001',
    framework: 'AgenticAI',
    category: 'Elevation of Privilege',
    severity: 'Critical',
    description: 'agent or llm exposed',
    mitigation: '[Foundation] a [Enterprise] b',
    appliesTo: {
      kind: 'node',
      anyOf: [{ nodeType: 'AGENT' }, { nodeType: 'LLM' }],
      connection: {
        required: true,
        direction: 'outbound',
        peerType: ['GATEWAY'],
        peerAttackSurface: { hasGlobalIp: true },
      },
    },
  },
  nodeIntrinsic: {
    id: 'node-intrinsic-001',
    framework: 'STRIDE',
    category: 'Information Disclosure',
    severity: 'Medium',
    description: 'intrinsic threat regardless of edges',
    appliesTo: { kind: 'node', nodeType: 'DATABASE', connection: { required: false } },
  },
  nodeWithAgentAttributes: {
    id: 'node-agent-attr-001',
    framework: 'AgenticAI',
    category: 'Tampering',
    severity: 'High',
    description: 'autonomous agent',
    appliesTo: {
      kind: 'node',
      nodeType: 'AGENT',
      agentAttributes: { agency: ['Autonomous'], blastRadius: ['Tenant', 'CrossTenant'] },
    },
  },
  edgeWhen: {
    id: 'edge-when-001',
    framework: 'STRIDE',
    category: 'Tampering',
    severity: 'High',
    description: 'plaintext from {{sourceName}} to {{targetName}}',
    appliesTo: { kind: 'edge', when: { auth: ['None'], encryption: ['Plain'] } },
  },
  edgeAnyOf: {
    id: 'edge-anyof-001',
    framework: 'STRIDE',
    category: 'Spoofing',
    severity: 'Medium',
    description: 'weak edge',
    appliesTo: { kind: 'edge', anyOf: [{ auth: ['None'] }, { encryption: ['Plain'] }] },
  },
  edgeAllOfWithConditions: {
    id: 'edge-allof-cond-001',
    framework: 'AgenticAI',
    category: 'Elevation of Privilege',
    severity: 'High',
    description: 'tool invocation without auth',
    appliesTo: {
      kind: 'edge',
      allOf: [{ semantic: ['tool_invocation'] }, { auth: ['None'] }],
      conditions: [{ when: { auth: ['MFA'] }, severity: 'Low', description: 'mfa softens it' }],
    },
  },
  fullMeta: {
    id: 'full-meta-001',
    framework: 'STRIDE',
    category: 'Repudiation',
    name: '監査追跡不能',
    severity: 'Low',
    description: 'rule with every output field',
    mitigation: 'do the thing',
    mitigationTiers: { foundation: 'f', enterprise: 'e', advanced: 'a' },
    complianceRefs: [{ standard: 'nist-ai-rmf', ref: 'GOVERN 1.1' }],
    references: [{ title: 'Source', url: 'https://example.com/' }],
    appliesTo: { kind: 'node', nodeType: 'USER' },
  },
};

describe('ruleToDraft / draftToRule round-trip', () => {
  for (const [name, rule] of Object.entries(fixtures)) {
    it(`round-trips ${name} identically`, () => {
      const result = draftToRule(ruleToDraft(rule));
      expect(result.ok).toBe(true);
      if (result.ok) expect(result.rule).toEqual(rule);
    });
  }
});

describe('draftToRule normalization (non-canonical input)', () => {
  it('fills required:true + direction default for partial connection, then is idempotent', () => {
    const partial: ThreatRule = {
      id: 'partial-conn-001',
      framework: 'STRIDE',
      category: 'Spoofing',
      severity: 'Medium',
      description: 'connection without required/direction',
      // required 省略（= デフォルト true）、direction のみ指定
      appliesTo: { kind: 'node', nodeType: 'AGENT', connection: { direction: 'inbound' } },
    };
    const once = draftToRule(ruleToDraft(partial));
    expect(once.ok).toBe(true);
    if (!once.ok) return;
    // 正規化で required:true / direction:inbound に揃う
    expect(once.rule.appliesTo).toMatchObject({
      kind: 'node',
      connection: { required: true, direction: 'inbound' },
    });
    // 二度目以降は不動点
    const twice = draftToRule(ruleToDraft(once.rule));
    expect(twice.ok).toBe(true);
    if (twice.ok) expect(twice.rule).toEqual(once.rule);
  });
});

describe('draftToRule validation failures', () => {
  it('rejects an empty new draft (missing id / description / conditions)', () => {
    const result = draftToRule(emptyDraft('edge'));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.issues.length).toBeGreaterThan(0);
  });

  it('rejects node draft with neither nodeType nor anyOf (exactly-one violation)', () => {
    const draft: RuleDraft = {
      ...emptyDraft('node'),
      id: 'x-001',
      category: 'c',
      description: 'd',
      node: { ...emptyDraft('node').node, mode: 'single', nodeTypes: [] },
    };
    const result = draftToRule(draft);
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.issues.join(' ')).toMatch(/exactly one of: nodeType, anyOf/);
  });

  it('rejects edge when-leaf with no axis set (at least one condition)', () => {
    const draft: RuleDraft = {
      ...emptyDraft('edge'),
      id: 'x-002',
      category: 'c',
      description: 'd',
    };
    const result = draftToRule(draft);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.issues.join(' ')).toMatch(/at least one condition/);
  });

  it('drops empty reference / compliance rows and empty url', () => {
    const base = emptyDraft('edge');
    const draft: RuleDraft = {
      ...base,
      id: 'clean-001',
      category: 'Tampering',
      description: 'minimal',
      references: [
        { title: 'Kept', url: '' }, // 空 url は除去
        { title: '', url: 'https://x.test/' }, // タイトル空 → 行ごと除去
      ],
      complianceRefs: [
        { standard: 'nist-ai-rmf', ref: 'GOVERN 1.1' },
        { standard: '', ref: '' }, // 空行 → 除去
      ],
      edge: { ...base.edge, leaves: [{ ...base.edge.leaves[0], auth: ['None'] }] },
    };
    const result = draftToRule(draft);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.rule.references).toEqual([{ title: 'Kept' }]);
      expect(result.rule.complianceRefs).toEqual([{ standard: 'nist-ai-rmf', ref: 'GOVERN 1.1' }]);
    }
  });

  it('accepts a minimal valid edge draft', () => {
    const base = emptyDraft('edge');
    const draft: RuleDraft = {
      ...base,
      id: 'min-001',
      category: 'Tampering',
      description: 'minimal',
      edge: {
        ...base.edge,
        mode: 'when',
        leaves: [{ ...base.edge.leaves[0], auth: ['None'] }],
      },
    };
    const result = draftToRule(draft);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.rule.appliesTo).toEqual({ kind: 'edge', when: { auth: ['None'] } });
    }
  });
});
