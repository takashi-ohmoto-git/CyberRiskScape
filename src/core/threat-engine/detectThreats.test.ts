import { describe, expect, it } from 'vitest';
import { detectThreats } from './detectThreats';
import type { DiagramBoundary, DiagramEdge, DiagramNode } from '../model/types';
import type { ThreatRule } from '../../threat-library/schema/threatRule';

const nodes: DiagramNode[] = [
  { id: 'u', type: 'USER', x: 0, y: 0 },
  { id: 'g', type: 'GATEWAY', x: 0, y: 0 },
  { id: 'llm', type: 'LLM', x: 0, y: 0 },
  { id: 'tool', type: 'TOOL', x: 0, y: 0 },
];

const edges: DiagramEdge[] = [
  { id: 'e-pub', source: 'u', target: 'g', auth: 'None', network: 'Internet', encryption: 'Plain' },
  { id: 'e-mfa-tool', source: 'g', target: 'tool', auth: 'MFA', network: 'VPC', encryption: 'TLS' },
  { id: 'e-pw-tool', source: 'g', target: 'tool', auth: 'Password', network: 'VPC', encryption: 'TLS' },
];

// テスト用フィクスチャの node ルールは intrinsic（接続不問）として定義する。
// デフォルト（接続必須）の挙動は別途 'connection requirement' ブロックで検証する。
const nodeRuleLLM: ThreatRule = {
  id: 'rule-llm-evasion',
  framework: 'STRIDE',
  category: 'Tampering',
  severity: 'Medium',
  description: 'LLM 回避攻撃',
  appliesTo: { kind: 'node', nodeType: 'LLM', connection: { required: false } },
};

const nodeRuleAgentMaestro: ThreatRule = {
  id: 'rule-agent-runaway',
  framework: 'AgenticAI',
  category: 'Agent',
  severity: 'Critical',
  description: 'Agent 暴走',
  appliesTo: { kind: 'node', nodeType: 'AGENT', connection: { required: false } },
};

const edgeRulePlain: ThreatRule = {
  id: 'rule-plain',
  framework: 'STRIDE',
  category: 'Information Disclosure',
  severity: 'High',
  description: '平文通信',
  appliesTo: { kind: 'edge', when: { encryption: ['Plain'] } },
};

const edgeRuleToolUnauth: ThreatRule = {
  id: 'rule-tool-unauth',
  framework: 'AgenticAI',
  category: 'Tool',
  severity: 'High',
  description: 'ツール権限昇格',
  appliesTo: { kind: 'edge', when: { targetType: ['TOOL'], auth: ['None', 'Password'] } },
};

const edgeRuleUserInternet: ThreatRule = {
  id: 'rule-user-internet',
  framework: 'STRIDE',
  category: 'Spoofing',
  severity: 'Critical',
  description: '公衆網からの未認証アクセス',
  appliesTo: {
    kind: 'edge',
    when: { sourceType: ['USER'], network: ['Internet'], auth: ['None'] },
  },
};

describe('detectThreats', () => {
  it('node ルールは framework 一致時のみ発火する', () => {
    const out = detectThreats({
      nodes,
      edges: [],
      framework: 'STRIDE',
      rules: [nodeRuleLLM, nodeRuleAgentMaestro],
    });
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe('rule-llm-evasion-llm');
    expect(out[0].nodeId).toBe('llm');
    expect(out[0].isDynamic).toBeUndefined();
  });

  it('ルールの name（脅威名）が node / edge 双方の検出結果に伝播する', () => {
    const namedNodeRule: ThreatRule = { ...nodeRuleLLM, name: '回避攻撃' };
    const namedEdgeRule: ThreatRule = { ...edgeRulePlain, name: '平文盗聴' };
    const out = detectThreats({
      nodes,
      edges,
      framework: 'STRIDE',
      rules: [namedNodeRule, namedEdgeRule],
    });
    const node = out.find((t) => t.id === 'rule-llm-evasion-llm');
    const edge = out.find((t) => t.id === 'rule-plain-e-pub');
    expect(node?.name).toBe('回避攻撃');
    expect(edge?.name).toBe('平文盗聴');
    // name 未指定のルールは undefined のまま（category がタイトルにフォールバックされる）。
    const plain = detectThreats({ nodes, edges: [], framework: 'STRIDE', rules: [nodeRuleLLM] });
    expect(plain[0].name).toBeUndefined();
  });

  it('対象ノード型が複数あれば全件に展開される', () => {
    const llms: DiagramNode[] = [
      { id: 'a', type: 'LLM', x: 0, y: 0 },
      { id: 'b', type: 'LLM', x: 0, y: 0 },
    ];
    const out = detectThreats({
      nodes: llms,
      edges: [],
      framework: 'STRIDE',
      rules: [nodeRuleLLM],
    });
    expect(out.map((t) => t.nodeId).sort()).toEqual(['a', 'b']);
  });

  it('edge ルール: encryption 条件のみで発火する', () => {
    const out = detectThreats({
      nodes,
      edges,
      framework: 'STRIDE',
      rules: [edgeRulePlain],
    });
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe('rule-plain-e-pub');
    expect(out[0].nodeId).toBe('g'); // edge.target
    expect(out[0].isDynamic).toBe(true);
  });

  it('edge ルール: targetType + auth(複数) の AND 評価', () => {
    const out = detectThreats({
      nodes,
      edges,
      framework: 'AgenticAI',
      rules: [edgeRuleToolUnauth],
    });
    // MFA の e-mfa-tool は除外され、Password の e-pw-tool のみ
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe('rule-tool-unauth-e-pw-tool');
  });

  it('edge ルール: sourceType + network + auth の AND 評価', () => {
    const out = detectThreats({
      nodes,
      edges,
      framework: 'STRIDE',
      rules: [edgeRuleUserInternet],
    });
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe('rule-user-internet-e-pub');
  });

  it('framework が一致しない edge ルールは発火しない', () => {
    const out = detectThreats({
      nodes,
      edges,
      framework: 'STRIDE',
      rules: [edgeRuleToolUnauth], // AgenticAI 専用
    });
    expect(out).toHaveLength(0);
  });

  it("framework='ALL' は両 framework のルールを framework 問わず発火させる", () => {
    // nodeRuleLLM=STRIDE（llm に発火）, edgeRuleToolUnauth=AgenticAI（e-pw-tool に発火）。
    const out = detectThreats({
      nodes,
      edges,
      framework: 'ALL',
      rules: [nodeRuleLLM, edgeRuleToolUnauth],
    });
    const frameworks = out.map((t) => t.framework).sort();
    expect(frameworks).toEqual(['AgenticAI', 'STRIDE']);
  });

  it('参照先ノードが存在しない edge は安全にスキップされる', () => {
    const orphanEdges: DiagramEdge[] = [
      { id: 'orphan', source: 'ghost', target: 'g', auth: 'None', network: 'Internet', encryption: 'Plain' },
    ];
    const out = detectThreats({
      nodes,
      edges: orphanEdges,
      framework: 'STRIDE',
      rules: [edgeRulePlain],
    });
    expect(out).toHaveLength(0);
  });

  it('node と edge のルールを混在させても両方適用される', () => {
    const out = detectThreats({
      nodes,
      edges,
      framework: 'STRIDE',
      rules: [nodeRuleLLM, edgeRulePlain],
    });
    expect(out).toHaveLength(2);
    expect(out.some((t) => t.id === 'rule-llm-evasion-llm')).toBe(true);
    expect(out.some((t) => t.id === 'rule-plain-e-pub')).toBe(true);
  });

  it('edge ルールの description は {{sourceName}}/{{targetName}} を展開する', () => {
    const labeledNodes: DiagramNode[] = [
      { id: 'u', type: 'USER', x: 0, y: 0, label: '与信申込者' },
      { id: 'g', type: 'GATEWAY', x: 0, y: 0, label: 'WAF' },
    ];
    const labeledEdge: DiagramEdge[] = [
      { id: 'e', source: 'u', target: 'g', auth: 'None', network: 'Internet', encryption: 'Plain' },
    ];
    const rule: ThreatRule = {
      id: 'plain-tmpl',
      framework: 'STRIDE',
      category: 'Information Disclosure',
      severity: 'High',
      description: '{{sourceName}} から {{targetName}} への通信が平文です。',
      appliesTo: { kind: 'edge', when: { encryption: ['Plain'] } },
    };
    const out = detectThreats({
      nodes: labeledNodes,
      edges: labeledEdge,
      framework: 'STRIDE',
      rules: [rule],
    });
    expect(out).toHaveLength(1);
    expect(out[0].description).toBe('与信申込者 から WAF への通信が平文です。');
  });

  it('node ルールの description は {{nodeName}} を展開する', () => {
    const out = detectThreats({
      nodes: [{ id: 'llm', type: 'LLM', x: 0, y: 0, label: '与信判定モデル' }],
      edges: [],
      framework: 'STRIDE',
      rules: [
        {
          id: 'node-tmpl',
          framework: 'STRIDE',
          category: 'Tampering',
          severity: 'Medium',
          description: '{{nodeName}} に対する回避攻撃。',
          appliesTo: { kind: 'node', nodeType: 'LLM', connection: { required: false } },
        },
      ],
    });
    expect(out[0].description).toBe('与信判定モデル に対する回避攻撃。');
  });

  it('conditions: マッチしたケースで severity と description が上書きされる', () => {
    const rule: ThreatRule = {
      id: 'tool-edge',
      framework: 'AgenticAI',
      category: 'Tool',
      severity: 'High',
      description: '保護が不十分です。',
      appliesTo: {
        kind: 'edge',
        when: { targetType: ['TOOL'] },
        conditions: [
          { when: { auth: ['MFA'] }, severity: 'Low', description: 'MFA で保護されています。' },
        ],
      },
    };
    const out = detectThreats({
      nodes,
      edges,
      framework: 'AgenticAI',
      rules: [rule],
    });
    // e-mfa-tool と e-pw-tool の 2 件発火
    const mfa = out.find((t) => t.id === 'tool-edge-e-mfa-tool');
    const pw = out.find((t) => t.id === 'tool-edge-e-pw-tool');
    expect(mfa).toBeDefined();
    expect(mfa?.severity).toBe('Low');
    expect(mfa?.description).toBe('MFA で保護されています。');
    expect(pw).toBeDefined();
    expect(pw?.severity).toBe('High');
    expect(pw?.description).toBe('保護が不十分です。');
  });

  it('conditions: first-match-wins で 2 番目以降のケースは評価されない', () => {
    const rule: ThreatRule = {
      id: 'multi-cond',
      framework: 'STRIDE',
      category: 'X',
      severity: 'High',
      description: 'default',
      appliesTo: {
        kind: 'edge',
        when: { encryption: ['Plain'] },
        conditions: [
          { when: { auth: ['None'] }, severity: 'Critical', description: 'first' },
          { when: { auth: ['None'] }, severity: 'Low', description: 'second' },
        ],
      },
    };
    const out = detectThreats({
      nodes,
      edges,
      framework: 'STRIDE',
      rules: [rule],
    });
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe('Critical');
    expect(out[0].description).toBe('first');
  });

  it('node ルール: mitigation / complianceRefs / references を DetectedThreat に伝播する', () => {
    const rule: ThreatRule = {
      id: 'node-meta',
      framework: 'STRIDE',
      category: 'Tampering',
      severity: 'Medium',
      description: 'LLM 回避攻撃',
      mitigation: '入力検証・出力フィルタを実装する。',
      complianceRefs: [{ standard: 'NIST AI RMF', ref: 'GOVERN 1.1' }],
      references: [{ title: 'OWASP LLM Top 10', url: 'https://example.com/owasp-llm' }],
      appliesTo: { kind: 'node', nodeType: 'LLM', connection: { required: false } },
    };
    const out = detectThreats({
      nodes,
      edges: [],
      framework: 'STRIDE',
      rules: [rule],
    });
    expect(out).toHaveLength(1);
    expect(out[0].mitigation).toBe('入力検証・出力フィルタを実装する。');
    expect(out[0].complianceRefs).toEqual([{ standard: 'NIST AI RMF', ref: 'GOVERN 1.1' }]);
    expect(out[0].references).toEqual([
      { title: 'OWASP LLM Top 10', url: 'https://example.com/owasp-llm' },
    ]);
  });

  it('edge ルール: mitigation / complianceRefs / references を DetectedThreat に伝播する', () => {
    const rule: ThreatRule = {
      id: 'edge-meta',
      framework: 'STRIDE',
      category: 'Information Disclosure',
      severity: 'High',
      description: '平文通信',
      mitigation: 'TLS を有効化する。',
      complianceRefs: [{ standard: 'ISO/IEC 42001', ref: '8.2' }],
      references: [{ title: 'TLS Best Practices' }],
      appliesTo: { kind: 'edge', when: { encryption: ['Plain'] } },
    };
    const out = detectThreats({
      nodes,
      edges,
      framework: 'STRIDE',
      rules: [rule],
    });
    expect(out).toHaveLength(1);
    expect(out[0].mitigation).toBe('TLS を有効化する。');
    expect(out[0].complianceRefs).toEqual([{ standard: 'ISO/IEC 42001', ref: '8.2' }]);
    expect(out[0].references).toEqual([{ title: 'TLS Best Practices' }]);
  });

  it('オプションフィールド未指定のルールでは DetectedThreat 側も undefined', () => {
    const out = detectThreats({
      nodes,
      edges: [],
      framework: 'STRIDE',
      rules: [nodeRuleLLM],
    });
    expect(out[0].mitigation).toBeUndefined();
    expect(out[0].complianceRefs).toBeUndefined();
    expect(out[0].references).toBeUndefined();
  });

  // ── 組合せ条件: allOf / anyOf ────────────────────────────────
  it('edge allOf: すべてのリーフに合致した edge のみ発火する', () => {
    const rule: ThreatRule = {
      id: 'edge-allof',
      framework: 'STRIDE',
      category: 'X',
      severity: 'High',
      description: 'allOf hit',
      appliesTo: {
        kind: 'edge',
        allOf: [{ sourceType: ['USER'] }, { network: ['Internet'], auth: ['None'] }],
      },
    };
    const out = detectThreats({ nodes, edges, framework: 'STRIDE', rules: [rule] });
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe('edge-allof-e-pub');
  });

  it('edge allOf: いずれかのリーフが外れたら発火しない', () => {
    const rule: ThreatRule = {
      id: 'edge-allof-miss',
      framework: 'STRIDE',
      category: 'X',
      severity: 'High',
      description: 'allOf miss',
      appliesTo: {
        kind: 'edge',
        // sourceType=USER は e-pub のみ、encryption=TLS は e-pub には合致しない
        allOf: [{ sourceType: ['USER'] }, { encryption: ['TLS'] }],
      },
    };
    const out = detectThreats({ nodes, edges, framework: 'STRIDE', rules: [rule] });
    expect(out).toHaveLength(0);
  });

  it('edge anyOf: いずれかのリーフに合致したら発火する', () => {
    const rule: ThreatRule = {
      id: 'edge-anyof',
      framework: 'STRIDE',
      category: 'X',
      severity: 'High',
      description: 'anyOf hit',
      appliesTo: {
        kind: 'edge',
        // 公衆網 OR 平文 — e-pub のみ両方合致、他の 2 件は TLS+VPC で外れる
        anyOf: [{ network: ['Internet'] }, { encryption: ['Plain'] }],
      },
    };
    const out = detectThreats({ nodes, edges, framework: 'STRIDE', rules: [rule] });
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe('edge-anyof-e-pub');
  });

  it('edge anyOf: 1 edge が複数リーフに合致しても発火は 1 回のみ', () => {
    const rule: ThreatRule = {
      id: 'edge-anyof-dedup',
      framework: 'STRIDE',
      category: 'X',
      severity: 'High',
      description: 'dedup',
      appliesTo: {
        kind: 'edge',
        // e-pub は両方のリーフに合致するが、エンジンは edge 単位で 1 件しか発火しない
        anyOf: [{ network: ['Internet'] }, { auth: ['None'] }],
      },
    };
    const out = detectThreats({ nodes, edges, framework: 'STRIDE', rules: [rule] });
    expect(out).toHaveLength(1);
  });

  it('node anyOf: 列挙した型のいずれかに該当するノードすべてに展開する', () => {
    const rule: ThreatRule = {
      id: 'node-anyof',
      framework: 'STRIDE',
      category: 'X',
      severity: 'High',
      description: '{{nodeName}}',
      appliesTo: {
        kind: 'node',
        anyOf: [{ nodeType: 'LLM' }, { nodeType: 'TOOL' }],
        connection: { required: false },
      },
    };
    const out = detectThreats({ nodes, edges: [], framework: 'STRIDE', rules: [rule] });
    expect(out.map((t) => t.nodeId).sort()).toEqual(['llm', 'tool']);
  });

  it('node anyOf: いずれにも該当しなければ発火しない', () => {
    const rule: ThreatRule = {
      id: 'node-anyof-miss',
      framework: 'STRIDE',
      category: 'X',
      severity: 'High',
      description: 'miss',
      appliesTo: {
        kind: 'node',
        anyOf: [{ nodeType: 'DATA_STORE' }, { nodeType: 'EXTERNAL_ENTITY' }],
        connection: { required: false },
      },
    };
    const out = detectThreats({ nodes, edges: [], framework: 'STRIDE', rules: [rule] });
    expect(out).toHaveLength(0);
  });

  it('edge allOf: conditions（first-match-wins）と併用できる', () => {
    const rule: ThreatRule = {
      id: 'edge-allof-with-cond',
      framework: 'AgenticAI',
      category: 'Tool',
      severity: 'High',
      description: 'default',
      appliesTo: {
        kind: 'edge',
        allOf: [{ targetType: ['TOOL'] }, { network: ['VPC'] }],
        conditions: [{ when: { auth: ['MFA'] }, severity: 'Low', description: 'mfa-low' }],
      },
    };
    const out = detectThreats({ nodes, edges, framework: 'AgenticAI', rules: [rule] });
    const mfa = out.find((t) => t.id === 'edge-allof-with-cond-e-mfa-tool');
    const pw = out.find((t) => t.id === 'edge-allof-with-cond-e-pw-tool');
    expect(mfa?.severity).toBe('Low');
    expect(mfa?.description).toBe('mfa-low');
    expect(pw?.severity).toBe('High');
    expect(pw?.description).toBe('default');
  });

  // ── Trust Boundary 軸: sourceTrust / targetTrust ─────────────
  it('targetTrust=Partner: target ノードが Partner 境界にあるエッジで発火する', () => {
    const trustNodes: DiagramNode[] = [
      { id: 'svc', type: 'PROCESS', x: 50, y: 50 }, // 境界外 → Internet
      { id: 'partnerTool', type: 'TOOL', x: 300, y: 300 }, // partner 境界内
    ];
    const trustBoundaries: DiagramBoundary[] = [
      {
        id: 'b-partner',
        type: 'RECT',
        x: 200,
        y: 200,
        width: 200,
        height: 200,
        trustLevel: 'Partner',
      },
    ];
    const trustEdges: DiagramEdge[] = [
      {
        id: 'e-supply',
        source: 'svc',
        target: 'partnerTool',
        auth: 'Password',
        network: 'Internet',
        encryption: 'TLS',
      },
    ];
    const rule: ThreatRule = {
      id: 'supply-chain-tool',
      framework: 'AgenticAI',
      category: 'Supply Chain',
      severity: 'High',
      description: 'Partner 境界のツール連携はサプライチェーンリスクあり',
      appliesTo: { kind: 'edge', when: { targetType: ['TOOL'], targetTrust: ['Partner'] } },
    };
    const out = detectThreats({
      nodes: trustNodes,
      edges: trustEdges,
      framework: 'AgenticAI',
      rules: [rule],
      boundaries: trustBoundaries,
    });
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe('supply-chain-tool-e-supply');
  });

  it('sourceTrust=Internet: source が境界外（Internet 扱い）のエッジで発火する', () => {
    const trustNodes: DiagramNode[] = [
      { id: 'attacker', type: 'USER', x: 50, y: 50 }, // 未所属 → Internet
      { id: 'llm', type: 'LLM', x: 300, y: 300 }, // internal 境界内
    ];
    const trustBoundaries: DiagramBoundary[] = [
      {
        id: 'b-internal',
        type: 'RECT',
        x: 200,
        y: 200,
        width: 200,
        height: 200,
        trustLevel: 'Internal',
      },
    ];
    const trustEdges: DiagramEdge[] = [
      {
        id: 'e-ext',
        source: 'attacker',
        target: 'llm',
        auth: 'None',
        network: 'Internet',
        encryption: 'TLS',
      },
    ];
    const rule: ThreatRule = {
      id: 'internet-exposed-llm',
      framework: 'STRIDE',
      category: 'Spoofing',
      severity: 'Critical',
      description: 'Internet からの LLM への直接アクセスは攻撃面が大きい',
      appliesTo: { kind: 'edge', when: { targetType: ['LLM'], sourceTrust: ['Internet'] } },
    };
    const out = detectThreats({
      nodes: trustNodes,
      edges: trustEdges,
      framework: 'STRIDE',
      rules: [rule],
      boundaries: trustBoundaries,
    });
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe('internet-exposed-llm-e-ext');
  });

  it('入れ子境界: 最内側の trustLevel が判定に使われる', () => {
    // 外側 Internet × 内側 Internal —— LLM は Internal 扱いで Internet ルールは発火しない
    const trustNodes: DiagramNode[] = [
      { id: 'user', type: 'USER', x: 50, y: 50 }, // 未所属 → Internet
      { id: 'llm', type: 'LLM', x: 300, y: 300 }, // 内側 Internal
    ];
    const trustBoundaries: DiagramBoundary[] = [
      { id: 'outer', type: 'RECT', x: 0, y: 0, width: 800, height: 800, trustLevel: 'Internet' },
      { id: 'inner', type: 'RECT', x: 200, y: 200, width: 200, height: 200, trustLevel: 'Internal' },
    ];
    const trustEdges: DiagramEdge[] = [
      {
        id: 'e1',
        source: 'user',
        target: 'llm',
        auth: 'None',
        network: 'Internet',
        encryption: 'TLS',
      },
    ];
    const ruleTargetInternet: ThreatRule = {
      id: 'target-internet',
      framework: 'STRIDE',
      category: 'X',
      severity: 'High',
      description: 'target is Internet',
      appliesTo: { kind: 'edge', when: { targetTrust: ['Internet'] } },
    };
    const out = detectThreats({
      nodes: trustNodes,
      edges: trustEdges,
      framework: 'STRIDE',
      rules: [ruleTargetInternet],
      boundaries: trustBoundaries,
    });
    // LLM は最内側 Internal なので targetTrust:Internet は発火しないはず
    expect(out).toHaveLength(0);
  });

  it('boundaries 未指定: 全ノードが Internet 扱いになる', () => {
    const rule: ThreatRule = {
      id: 'all-internet',
      framework: 'STRIDE',
      category: 'X',
      severity: 'High',
      description: 'both internet',
      appliesTo: {
        kind: 'edge',
        allOf: [{ sourceTrust: ['Internet'] }, { targetTrust: ['Internet'] }],
      },
    };
    const out = detectThreats({
      nodes,
      edges,
      framework: 'STRIDE',
      rules: [rule],
    });
    // 3 件すべて発火するはず
    expect(out).toHaveLength(3);
  });

  it('conditions の when も trust 軸で分岐できる', () => {
    const trustNodes: DiagramNode[] = [
      { id: 'svc', type: 'PROCESS', x: 50, y: 50 }, // 境界外 → Internet
      { id: 'tool', type: 'TOOL', x: 300, y: 300 }, // partner
    ];
    const trustBoundaries: DiagramBoundary[] = [
      {
        id: 'b-partner',
        type: 'RECT',
        x: 200,
        y: 200,
        width: 200,
        height: 200,
        trustLevel: 'Partner',
      },
    ];
    const trustEdges: DiagramEdge[] = [
      {
        id: 'e1',
        source: 'svc',
        target: 'tool',
        auth: 'Password',
        network: 'Internet',
        encryption: 'TLS',
      },
    ];
    const rule: ThreatRule = {
      id: 'tool-with-trust-cond',
      framework: 'AgenticAI',
      category: 'Tool',
      severity: 'Medium',
      description: 'default',
      appliesTo: {
        kind: 'edge',
        when: { targetType: ['TOOL'] },
        conditions: [
          { when: { targetTrust: ['Partner'] }, severity: 'High', description: 'partner-tool' },
        ],
      },
    };
    const out = detectThreats({
      nodes: trustNodes,
      edges: trustEdges,
      framework: 'AgenticAI',
      rules: [rule],
      boundaries: trustBoundaries,
    });
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe('High');
    expect(out[0].description).toBe('partner-tool');
  });

  // ── 端末管理状態軸: sourceManagedState / targetManagedState ──
  it('sourceManagedState=Unmanaged: 未管理端末からのエッジで発火する', () => {
    const mNodes: DiagramNode[] = [
      { id: 'pc', type: 'PC', x: 0, y: 0, managedState: 'Unmanaged' },
      { id: 'llm', type: 'LLM', x: 0, y: 0 },
    ];
    const mEdges: DiagramEdge[] = [
      { id: 'e1', source: 'pc', target: 'llm', auth: 'Password', network: 'VPC', encryption: 'TLS' },
    ];
    const rule: ThreatRule = {
      id: 'unmanaged-to-llm',
      framework: 'STRIDE',
      category: 'Spoofing',
      severity: 'High',
      description: '未管理端末からの接続',
      appliesTo: {
        kind: 'edge',
        when: { sourceManagedState: ['Unmanaged'], targetType: ['LLM'] },
      },
    };
    const out = detectThreats({ nodes: mNodes, edges: mEdges, framework: 'STRIDE', rules: [rule] });
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe('unmanaged-to-llm-e1');
  });

  it('sourceManagedState=Unmanaged: Managed 端末では発火しない', () => {
    const mNodes: DiagramNode[] = [
      { id: 'pc', type: 'PC', x: 0, y: 0, managedState: 'Managed' },
      { id: 'llm', type: 'LLM', x: 0, y: 0 },
    ];
    const mEdges: DiagramEdge[] = [
      { id: 'e1', source: 'pc', target: 'llm', auth: 'Password', network: 'VPC', encryption: 'TLS' },
    ];
    const rule: ThreatRule = {
      id: 'unmanaged-to-llm',
      framework: 'STRIDE',
      category: 'Spoofing',
      severity: 'High',
      description: '未管理端末からの接続',
      appliesTo: { kind: 'edge', when: { sourceManagedState: ['Unmanaged'] } },
    };
    const out = detectThreats({ nodes: mNodes, edges: mEdges, framework: 'STRIDE', rules: [rule] });
    expect(out).toHaveLength(0);
  });

  it('managedState 未指定のノードでは managedState 軸を持つルールは発火しない', () => {
    // PC/SMARTPHONE/IOT 以外のノードは managedState を持たない（USER 等）。
    // この場合、ルールが managedState 軸を指定していれば「不明 ≠ 指定値」として除外する。
    const mNodes: DiagramNode[] = [
      { id: 'user', type: 'USER', x: 0, y: 0 }, // managedState 未指定
      { id: 'llm', type: 'LLM', x: 0, y: 0 },
    ];
    const mEdges: DiagramEdge[] = [
      { id: 'e1', source: 'user', target: 'llm', auth: 'Password', network: 'VPC', encryption: 'TLS' },
    ];
    const rule: ThreatRule = {
      id: 'unmanaged-only',
      framework: 'STRIDE',
      category: 'X',
      severity: 'High',
      description: 'unmanaged only',
      appliesTo: { kind: 'edge', when: { sourceManagedState: ['Unmanaged'] } },
    };
    const out = detectThreats({ nodes: mNodes, edges: mEdges, framework: 'STRIDE', rules: [rule] });
    expect(out).toHaveLength(0);
  });

  // ── ユーザー信頼区分軸: sourceUserTrust / targetUserTrust ──
  it('sourceUserTrust: 宣言された信頼区分に一致するエッジで発火する', () => {
    const uNodes: DiagramNode[] = [
      { id: 'user', type: 'USER', x: 0, y: 0, userTrustAttribute: 'Contractor' },
      { id: 'db', type: 'DB', x: 0, y: 0 },
    ];
    const uEdges: DiagramEdge[] = [
      { id: 'e1', source: 'user', target: 'db', auth: 'MFA', network: 'VPN', encryption: 'TLS' },
    ];
    const rule: ThreatRule = {
      id: 'external-collab-access',
      framework: 'STRIDE',
      category: 'Elevation of Privilege',
      severity: 'Medium',
      description: '外部協働者アクセス',
      appliesTo: {
        kind: 'edge',
        when: { sourceUserTrust: ['Contractor', 'Partner', 'Guest'], targetType: ['DB'] },
      },
    };
    const out = detectThreats({ nodes: uNodes, edges: uEdges, framework: 'STRIDE', rules: [rule] });
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe('external-collab-access-e1');
  });

  it('sourceUserTrust: Employee 宣言のノードでは外部協働者ルールは発火しない', () => {
    const uNodes: DiagramNode[] = [
      { id: 'user', type: 'USER', x: 0, y: 0, userTrustAttribute: 'Employee' },
      { id: 'db', type: 'DB', x: 0, y: 0 },
    ];
    const uEdges: DiagramEdge[] = [
      { id: 'e1', source: 'user', target: 'db', auth: 'MFA', network: 'VPN', encryption: 'TLS' },
    ];
    const rule: ThreatRule = {
      id: 'external-collab-access',
      framework: 'STRIDE',
      category: 'X',
      severity: 'Medium',
      description: 'x',
      appliesTo: { kind: 'edge', when: { sourceUserTrust: ['Contractor', 'Partner', 'Guest'] } },
    };
    const out = detectThreats({ nodes: uNodes, edges: uEdges, framework: 'STRIDE', rules: [rule] });
    expect(out).toHaveLength(0);
  });

  it('userTrustAttribute 未宣言のノードでは userTrust 軸を持つルールは発火しない', () => {
    // managedState と同じ「明示宣言時のみ発火」方式（最悪仮定ではない）。
    const uNodes: DiagramNode[] = [
      { id: 'user', type: 'USER', x: 0, y: 0 }, // userTrustAttribute 未宣言
      { id: 'db', type: 'DB', x: 0, y: 0 },
    ];
    const uEdges: DiagramEdge[] = [
      { id: 'e1', source: 'user', target: 'db', auth: 'MFA', network: 'VPN', encryption: 'TLS' },
    ];
    const rule: ThreatRule = {
      id: 'guest-only',
      framework: 'STRIDE',
      category: 'X',
      severity: 'Medium',
      description: 'x',
      appliesTo: { kind: 'edge', when: { sourceUserTrust: ['Guest'] } },
    };
    const out = detectThreats({ nodes: uNodes, edges: uEdges, framework: 'STRIDE', rules: [rule] });
    expect(out).toHaveLength(0);
  });

  it('conditions: targetUserTrust 軸で severity を段階分けできる', () => {
    const uNodes: DiagramNode[] = [
      { id: 'agent', type: 'AGENT', x: 0, y: 0 },
      { id: 'userA', type: 'USER', x: 0, y: 0, userTrustAttribute: 'Employee' },
      { id: 'userB', type: 'USER', x: 0, y: 0, userTrustAttribute: 'Guest' },
    ];
    const uEdges: DiagramEdge[] = [
      { id: 'ea', source: 'agent', target: 'userA', auth: 'MFA', network: 'VPC', encryption: 'TLS' },
      { id: 'eb', source: 'agent', target: 'userB', auth: 'MFA', network: 'VPC', encryption: 'TLS' },
    ];
    const rule: ThreatRule = {
      id: 'agent-to-user',
      framework: 'AgenticAI',
      category: 'X',
      severity: 'Low',
      description: 'employee default',
      appliesTo: {
        kind: 'edge',
        when: { sourceType: ['AGENT'], targetType: ['USER'] },
        conditions: [{ when: { targetUserTrust: ['Guest'] }, severity: 'High', description: 'guest' }],
      },
    };
    const out = detectThreats({ nodes: uNodes, edges: uEdges, framework: 'AgenticAI', rules: [rule] });
    const a = out.find((t) => t.id === 'agent-to-user-ea');
    const b = out.find((t) => t.id === 'agent-to-user-eb');
    expect(a?.severity).toBe('Low');
    expect(b?.severity).toBe('High');
  });

  it('conditions: managedState 軸で severity を段階分けできる', () => {
    const mNodes: DiagramNode[] = [
      { id: 'pcA', type: 'PC', x: 0, y: 0, managedState: 'Managed' },
      { id: 'pcB', type: 'PC', x: 0, y: 0, managedState: 'Unmanaged' },
      { id: 'gw', type: 'GATEWAY', x: 0, y: 0 },
    ];
    const mEdges: DiagramEdge[] = [
      { id: 'ea', source: 'pcA', target: 'gw', auth: 'Password', network: 'VPC', encryption: 'TLS' },
      { id: 'eb', source: 'pcB', target: 'gw', auth: 'Password', network: 'VPC', encryption: 'TLS' },
    ];
    const rule: ThreatRule = {
      id: 'pc-access',
      framework: 'STRIDE',
      category: 'X',
      severity: 'Low',
      description: 'managed default',
      appliesTo: {
        kind: 'edge',
        when: { sourceType: ['PC'] },
        conditions: [
          { when: { sourceManagedState: ['Unmanaged'] }, severity: 'High', description: 'unmanaged' },
        ],
      },
    };
    const out = detectThreats({ nodes: mNodes, edges: mEdges, framework: 'STRIDE', rules: [rule] });
    const a = out.find((t) => t.id === 'pc-access-ea');
    const b = out.find((t) => t.id === 'pc-access-eb');
    expect(a?.severity).toBe('Low');
    expect(b?.severity).toBe('High');
    expect(b?.description).toBe('unmanaged');
  });

  // ── Node 接続要件: connection ────────────────────────────────
  it('connection 省略時のデフォルトは「接続必須」: 孤立ノードでは発火しない', () => {
    const rule: ThreatRule = {
      id: 'requires-connection-default',
      framework: 'STRIDE',
      category: 'X',
      severity: 'Medium',
      description: 'default requires connection',
      appliesTo: { kind: 'node', nodeType: 'LLM' },
    };
    // edges に llm へのエッジは無い（u -> g, g -> tool のみ）
    const out = detectThreats({ nodes, edges, framework: 'STRIDE', rules: [rule] });
    expect(out).toHaveLength(0);
  });

  it('connection 省略時: 当該ノードに任意方向のエッジが 1 本でもあれば発火する', () => {
    const rule: ThreatRule = {
      id: 'requires-connection-tool',
      framework: 'AgenticAI',
      category: 'X',
      severity: 'High',
      description: 'tool connected',
      appliesTo: { kind: 'node', nodeType: 'TOOL' },
    };
    // edges に tool 宛のエッジが 2 本ある
    const out = detectThreats({ nodes, edges, framework: 'AgenticAI', rules: [rule] });
    expect(out).toHaveLength(1);
    expect(out[0].nodeId).toBe('tool');
  });

  it('connection.required:false: 接続が無くても発火する（intrinsic）', () => {
    const rule: ThreatRule = {
      id: 'intrinsic-llm',
      framework: 'STRIDE',
      category: 'X',
      severity: 'Medium',
      description: 'intrinsic',
      appliesTo: { kind: 'node', nodeType: 'LLM', connection: { required: false } },
    };
    const out = detectThreats({ nodes, edges: [], framework: 'STRIDE', rules: [rule] });
    expect(out).toHaveLength(1);
  });

  it('connection.direction:inbound: 入力エッジが無いと発火しない', () => {
    // u -> g -> tool。tool には inbound エッジがあるが、u には無い。
    const ruleUser: ThreatRule = {
      id: 'inbound-user',
      framework: 'STRIDE',
      category: 'X',
      severity: 'Medium',
      description: 'inbound user',
      appliesTo: { kind: 'node', nodeType: 'USER', connection: { direction: 'inbound' } },
    };
    const out = detectThreats({ nodes, edges, framework: 'STRIDE', rules: [ruleUser] });
    expect(out).toHaveLength(0);
  });

  it('connection.direction:inbound: 入力エッジを持つノードでは発火する', () => {
    const rule: ThreatRule = {
      id: 'inbound-tool',
      framework: 'AgenticAI',
      category: 'X',
      severity: 'High',
      description: 'inbound tool',
      appliesTo: { kind: 'node', nodeType: 'TOOL', connection: { direction: 'inbound' } },
    };
    const out = detectThreats({ nodes, edges, framework: 'AgenticAI', rules: [rule] });
    expect(out).toHaveLength(1);
    expect(out[0].nodeId).toBe('tool');
  });

  it('connection.direction:outbound: 出力エッジが無いと発火しない', () => {
    // tool は outbound エッジ無し
    const rule: ThreatRule = {
      id: 'outbound-tool',
      framework: 'AgenticAI',
      category: 'X',
      severity: 'High',
      description: 'outbound tool',
      appliesTo: { kind: 'node', nodeType: 'TOOL', connection: { direction: 'outbound' } },
    };
    const out = detectThreats({ nodes, edges, framework: 'AgenticAI', rules: [rule] });
    expect(out).toHaveLength(0);
  });

  it('connection.direction:outbound: 出力エッジを持つノードでは発火する', () => {
    // u は g への outbound エッジを持つ
    const rule: ThreatRule = {
      id: 'outbound-user',
      framework: 'STRIDE',
      category: 'X',
      severity: 'Medium',
      description: 'outbound user',
      appliesTo: { kind: 'node', nodeType: 'USER', connection: { direction: 'outbound' } },
    };
    const out = detectThreats({ nodes, edges, framework: 'STRIDE', rules: [rule] });
    expect(out).toHaveLength(1);
    expect(out[0].nodeId).toBe('u');
  });

  it('connection.peerType: 接続先型が一致するエッジがあれば発火する', () => {
    // g（GATEWAY）は u（USER）からの inbound と tool への outbound を持つ。
    // peerType=[USER] で direction=any なら成立。
    const rule: ThreatRule = {
      id: 'peer-user',
      framework: 'STRIDE',
      category: 'X',
      severity: 'High',
      description: 'has user peer',
      appliesTo: {
        kind: 'node',
        nodeType: 'GATEWAY',
        connection: { peerType: ['USER'] },
      },
    };
    const out = detectThreats({ nodes, edges, framework: 'STRIDE', rules: [rule] });
    expect(out).toHaveLength(1);
    expect(out[0].nodeId).toBe('g');
  });

  it('connection.peerType: 接続先型が一致しなければ発火しない', () => {
    // tool は g（GATEWAY）からの inbound のみ。peerType=[LLM] では一致しない。
    const rule: ThreatRule = {
      id: 'peer-llm',
      framework: 'AgenticAI',
      category: 'X',
      severity: 'High',
      description: 'has llm peer',
      appliesTo: {
        kind: 'node',
        nodeType: 'TOOL',
        connection: { peerType: ['LLM'] },
      },
    };
    const out = detectThreats({ nodes, edges, framework: 'AgenticAI', rules: [rule] });
    expect(out).toHaveLength(0);
  });

  it('connection.direction + peerType: AND 評価される', () => {
    // tool は GATEWAY からの inbound を持つ。direction=inbound × peerType=[GATEWAY] で発火。
    const rule: ThreatRule = {
      id: 'inbound-from-gw',
      framework: 'AgenticAI',
      category: 'X',
      severity: 'High',
      description: 'inbound from gateway',
      appliesTo: {
        kind: 'node',
        nodeType: 'TOOL',
        connection: { direction: 'inbound', peerType: ['GATEWAY'] },
      },
    };
    const out = detectThreats({ nodes, edges, framework: 'AgenticAI', rules: [rule] });
    expect(out).toHaveLength(1);

    // direction=outbound × peerType=[GATEWAY] では tool に該当エッジ無し
    const ruleMiss: ThreatRule = {
      ...rule,
      id: 'outbound-from-gw',
      appliesTo: {
        kind: 'node',
        nodeType: 'TOOL',
        connection: { direction: 'outbound', peerType: ['GATEWAY'] },
      },
    };
    const out2 = detectThreats({ nodes, edges, framework: 'AgenticAI', rules: [ruleMiss] });
    expect(out2).toHaveLength(0);
  });

  it('connection.peerType: 複数 edge が条件に合致しても発火は 1 件のみ', () => {
    // tool に GATEWAY からのエッジが 2 本（e-mfa-tool / e-pw-tool）。出力は 1 件に重複排除される。
    const rule: ThreatRule = {
      id: 'peer-gw-dedup',
      framework: 'AgenticAI',
      category: 'X',
      severity: 'High',
      description: 'dedup',
      appliesTo: {
        kind: 'node',
        nodeType: 'TOOL',
        connection: { peerType: ['GATEWAY'] },
      },
    };
    const out = detectThreats({ nodes, edges, framework: 'AgenticAI', rules: [rule] });
    expect(out).toHaveLength(1);
  });

  // ── Node 接続要件: peerAttackSurface（ピア属性条件） ──────────
  // 例：AGENT が Global IP 有効な GATEWAY に接続している場合に AGENT 側へ発火。
  const agentNodes: DiagramNode[] = [
    { id: 'a', type: 'AGENT', x: 0, y: 0 },
    { id: 'gw', type: 'GATEWAY', x: 0, y: 0, attackSurface: { hasGlobalIp: true } },
  ];
  const agentEdges: DiagramEdge[] = [
    { id: 'e', source: 'a', target: 'gw', auth: 'None', network: 'Internet', encryption: 'TLS' },
  ];
  const agentToPublicGw: ThreatRule = {
    id: 'agent-to-public-gw',
    framework: 'AgenticAI',
    category: 'Agent',
    severity: 'High',
    description: 'Agent が Global IP 有効な Gateway に接続',
    appliesTo: {
      kind: 'node',
      nodeType: 'AGENT',
      connection: { direction: 'outbound', peerType: ['GATEWAY'], peerAttackSurface: { hasGlobalIp: true } },
    },
  };

  it('connection.peerAttackSurface: 接続先の攻撃面が条件を満たすと発火する', () => {
    const out = detectThreats({
      nodes: agentNodes,
      edges: agentEdges,
      framework: 'AgenticAI',
      rules: [agentToPublicGw],
    });
    expect(out).toHaveLength(1);
    expect(out[0].nodeId).toBe('a');
  });

  it('connection.peerAttackSurface: 接続先の攻撃面が条件を満たさないと発火しない', () => {
    const safeNodes: DiagramNode[] = [
      { id: 'a', type: 'AGENT', x: 0, y: 0 },
      { id: 'gw', type: 'GATEWAY', x: 0, y: 0, attackSurface: { hasGlobalIp: false } },
    ];
    const out = detectThreats({
      nodes: safeNodes,
      edges: agentEdges,
      framework: 'AgenticAI',
      rules: [agentToPublicGw],
    });
    expect(out).toHaveLength(0);
  });

  it('connection.peerAttackSurface: ピア未設定は insecure baseline（hasGlobalIp:true）として一致する', () => {
    const baselineNodes: DiagramNode[] = [
      { id: 'a', type: 'AGENT', x: 0, y: 0 },
      { id: 'gw', type: 'GATEWAY', x: 0, y: 0 }, // attackSurface 未設定
    ];
    const out = detectThreats({
      nodes: baselineNodes,
      edges: agentEdges,
      framework: 'AgenticAI',
      rules: [agentToPublicGw],
    });
    expect(out).toHaveLength(1);
  });

  it('connection.peerAttackSurface: peerType 不一致なら攻撃面が合っても発火しない', () => {
    // ピアが LLM（GATEWAY でない）。peerType=[GATEWAY] と不一致。
    const llmNodes: DiagramNode[] = [
      { id: 'a', type: 'AGENT', x: 0, y: 0 },
      { id: 'llm', type: 'LLM', x: 0, y: 0, attackSurface: { hasGlobalIp: true } },
    ];
    const llmEdges: DiagramEdge[] = [
      { id: 'e', source: 'a', target: 'llm', auth: 'None', network: 'Internet', encryption: 'TLS' },
    ];
    const out = detectThreats({
      nodes: llmNodes,
      edges: llmEdges,
      framework: 'AgenticAI',
      rules: [agentToPublicGw],
    });
    expect(out).toHaveLength(0);
  });

  it('conditions: description のみ上書きするケースは severity を維持する', () => {
    const rule: ThreatRule = {
      id: 'desc-only',
      framework: 'STRIDE',
      category: 'X',
      severity: 'High',
      description: 'default',
      appliesTo: {
        kind: 'edge',
        when: { encryption: ['Plain'] },
        conditions: [{ when: { auth: ['None'] }, description: 'overridden' }],
      },
    };
    const out = detectThreats({
      nodes,
      edges,
      framework: 'STRIDE',
      rules: [rule],
    });
    expect(out[0].severity).toBe('High');
    expect(out[0].description).toBe('overridden');
  });
});

// ─── §2.22 1.6c: agentAttributes 条件によるルール絞り込み ───────────
describe('detectThreats - agentAttributes 条件 (1.6c)', () => {
  const ruleAgencyAutonomous: ThreatRule = {
    id: 'rule-agency-autonomous',
    framework: 'AgenticAI',
    category: 'Agent',
    severity: 'Critical',
    description: '権限過剰（Autonomous 限定）',
    appliesTo: {
      kind: 'node',
      nodeType: 'AGENT',
      connection: { required: false },
      agentAttributes: { agency: ['Autonomous'] },
    },
  };

  const ruleIdentityLabelOnly: ThreatRule = {
    id: 'rule-identity-labelonly',
    framework: 'AgenticAI',
    category: 'Identity',
    severity: 'High',
    description: 'アイデンティティ不在（LabelOnly 限定）',
    appliesTo: {
      kind: 'node',
      nodeType: 'AGENT',
      connection: { required: false },
      agentAttributes: { identityTier: ['LabelOnly'] },
    },
  };

  const ruleBlastBig: ThreatRule = {
    id: 'rule-blast-big',
    framework: 'AgenticAI',
    category: 'Agent',
    severity: 'Critical',
    description: '広域影響（CrossTenant/Admin）',
    appliesTo: {
      kind: 'node',
      nodeType: 'AGENT',
      connection: { required: false },
      agentAttributes: { blastRadius: ['CrossTenant', 'Admin'] },
    },
  };

  it('属性未指定ノードはベースライン（最悪を仮定）で発火する', () => {
    const ns: DiagramNode[] = [{ id: 'a', type: 'AGENT', x: 0, y: 0 }];
    const out = detectThreats({
      nodes: ns,
      edges: [],
      framework: 'AgenticAI',
      rules: [ruleAgencyAutonomous, ruleIdentityLabelOnly, ruleBlastBig],
    });
    expect(out.map((t) => t.ruleId).sort()).toEqual([
      'rule-agency-autonomous',
      'rule-blast-big',
      'rule-identity-labelonly',
    ]);
    // 最悪仮定で発火した検出には assumptionFlags が付く
    for (const t of out) {
      expect(t.assumptionFlags).toContain('agentAttributes');
    }
  });

  it('agentAttributes を明示したノードの検出には assumptionFlags が付かない', () => {
    const ns: DiagramNode[] = [
      {
        id: 'a',
        type: 'AGENT',
        x: 0,
        y: 0,
        agentAttributes: { agency: 'Autonomous', blastRadius: 'Admin', identityTier: 'LabelOnly' },
      },
    ];
    const out = detectThreats({
      nodes: ns,
      edges: [],
      framework: 'AgenticAI',
      rules: [ruleAgencyAutonomous, ruleIdentityLabelOnly, ruleBlastBig],
    });
    expect(out).toHaveLength(3);
    for (const t of out) {
      expect(t.assumptionFlags).toBeUndefined();
    }
  });

  it('agency: Bounded 明示宣言で agency 系ルールは抑制される', () => {
    const ns: DiagramNode[] = [
      { id: 'a', type: 'AGENT', x: 0, y: 0, agentAttributes: { agency: 'Bounded' } },
    ];
    const out = detectThreats({
      nodes: ns,
      edges: [],
      framework: 'AgenticAI',
      rules: [ruleAgencyAutonomous],
    });
    expect(out).toHaveLength(0);
  });

  it('identityTier: Cryptographic 明示宣言で identity 系ルールは抑制される', () => {
    const ns: DiagramNode[] = [
      { id: 'a', type: 'AGENT', x: 0, y: 0, agentAttributes: { identityTier: 'Cryptographic' } },
    ];
    const out = detectThreats({
      nodes: ns,
      edges: [],
      framework: 'AgenticAI',
      rules: [ruleIdentityLabelOnly],
    });
    expect(out).toHaveLength(0);
  });

  it('blastRadius: Self 明示宣言で blast 系ルールは抑制される', () => {
    const ns: DiagramNode[] = [
      { id: 'a', type: 'AGENT', x: 0, y: 0, agentAttributes: { blastRadius: 'Self' } },
    ];
    const out = detectThreats({
      nodes: ns,
      edges: [],
      framework: 'AgenticAI',
      rules: [ruleBlastBig],
    });
    expect(out).toHaveLength(0);
  });

  it('blastRadius: Admin 明示宣言は配列に含まれるため発火する', () => {
    const ns: DiagramNode[] = [
      { id: 'a', type: 'AGENT', x: 0, y: 0, agentAttributes: { blastRadius: 'Admin' } },
    ];
    const out = detectThreats({
      nodes: ns,
      edges: [],
      framework: 'AgenticAI',
      rules: [ruleBlastBig],
    });
    expect(out).toHaveLength(1);
  });

  it('複数フィールド指定（agency + identityTier）は AND 評価', () => {
    const ruleCombined: ThreatRule = {
      id: 'rule-combined',
      framework: 'AgenticAI',
      category: 'Agent',
      severity: 'Critical',
      description: 'agency=Autonomous AND identityTier=LabelOnly',
      appliesTo: {
        kind: 'node',
        nodeType: 'AGENT',
        connection: { required: false },
        agentAttributes: {
          agency: ['Autonomous'],
          identityTier: ['LabelOnly'],
        },
      },
    };
    // ケース1: 両方 baseline → 発火
    const out1 = detectThreats({
      nodes: [{ id: 'a', type: 'AGENT', x: 0, y: 0 }],
      edges: [],
      framework: 'AgenticAI',
      rules: [ruleCombined],
    });
    expect(out1).toHaveLength(1);

    // ケース2: agency 一致 / identityTier 不一致 → 抑制
    const out2 = detectThreats({
      nodes: [
        {
          id: 'a',
          type: 'AGENT',
          x: 0,
          y: 0,
          agentAttributes: { agency: 'Autonomous', identityTier: 'HardwareBound' },
        },
      ],
      edges: [],
      framework: 'AgenticAI',
      rules: [ruleCombined],
    });
    expect(out2).toHaveLength(0);

    // ケース3: agency 不一致 / identityTier 一致 → 抑制
    const out3 = detectThreats({
      nodes: [
        {
          id: 'a',
          type: 'AGENT',
          x: 0,
          y: 0,
          agentAttributes: { agency: 'None', identityTier: 'LabelOnly' },
        },
      ],
      edges: [],
      framework: 'AgenticAI',
      rules: [ruleCombined],
    });
    expect(out3).toHaveLength(0);
  });

  it('agentAttributes 条件と attackSurface 条件が併用された場合は AND 評価', () => {
    const ruleAttrAndSurface: ThreatRule = {
      id: 'rule-attr-surface',
      framework: 'STRIDE',
      category: 'Spoofing',
      severity: 'High',
      description: '攻撃面 + agency',
      appliesTo: {
        kind: 'node',
        nodeType: 'GATEWAY',
        connection: { required: false },
        attackSurface: { hasGlobalIp: true },
        // GATEWAY は agency 適用外だが、エンジンとしては型を問わず評価できる
        // （baseline = Autonomous なので未指定なら matches）
        agentAttributes: { agency: ['Autonomous'] },
      },
    };
    const ns: DiagramNode[] = [
      { id: 'g', type: 'GATEWAY', x: 0, y: 0 }, // 未指定: 両 baseline で発火
    ];
    const out = detectThreats({
      nodes: ns,
      edges: [],
      framework: 'STRIDE',
      rules: [ruleAttrAndSurface],
    });
    expect(out).toHaveLength(1);
  });

  it('agentAttributes 条件なしのルールは agent 属性に関係なく発火する（既存挙動）', () => {
    const ruleNoAttrs: ThreatRule = {
      id: 'rule-no-attrs',
      framework: 'AgenticAI',
      category: 'Agent',
      severity: 'Low',
      description: '従来のルール',
      appliesTo: { kind: 'node', nodeType: 'AGENT', connection: { required: false } },
    };
    const ns: DiagramNode[] = [
      {
        id: 'a',
        type: 'AGENT',
        x: 0,
        y: 0,
        agentAttributes: { agency: 'None', identityTier: 'HardwareBound', blastRadius: 'ReadOnly' },
      },
    ];
    const out = detectThreats({
      nodes: ns,
      edges: [],
      framework: 'AgenticAI',
      rules: [ruleNoAttrs],
    });
    expect(out).toHaveLength(1);
  });
});

// ─── §2.22 1.6d: edge.semantic 条件によるルール絞り込み ───────────
describe('detectThreats - semantic 条件 (1.6d)', () => {
  const twoAgents: DiagramNode[] = [
    { id: 'a1', type: 'AGENT', x: 0, y: 0 },
    { id: 'a2', type: 'AGENT', x: 0, y: 0 },
  ];

  const ruleDelegationPlain: ThreatRule = {
    id: 'rule-delegation-plain',
    framework: 'AgenticAI',
    category: 'Identity',
    severity: 'High',
    description: '委譲が平文',
    appliesTo: {
      kind: 'edge',
      when: { semantic: ['delegation'], encryption: ['Plain'] },
    },
  };

  it('semantic 未指定エッジは `data_flow` 既定で評価される（delegation ルールは発火しない）', () => {
    const es: DiagramEdge[] = [
      // semantic 未指定（=data_flow として扱われる）
      { id: 'e1', source: 'a1', target: 'a2', auth: 'None', network: 'VPC', encryption: 'Plain' },
    ];
    const out = detectThreats({
      nodes: twoAgents,
      edges: es,
      framework: 'AgenticAI',
      rules: [ruleDelegationPlain],
    });
    expect(out).toHaveLength(0);
  });

  it('semantic=delegation 明示マーク + 平文 → 発火', () => {
    const es: DiagramEdge[] = [
      {
        id: 'e1',
        source: 'a1',
        target: 'a2',
        auth: 'None',
        network: 'VPC',
        encryption: 'Plain',
        semantic: 'delegation',
      },
    ];
    const out = detectThreats({
      nodes: twoAgents,
      edges: es,
      framework: 'AgenticAI',
      rules: [ruleDelegationPlain],
    });
    expect(out).toHaveLength(1);
    expect(out[0].ruleId).toBe('rule-delegation-plain');
  });

  it('semantic=delegation 明示 + TLS → 発火しない（他条件不一致）', () => {
    const es: DiagramEdge[] = [
      {
        id: 'e1',
        source: 'a1',
        target: 'a2',
        auth: 'None',
        network: 'VPC',
        encryption: 'TLS',
        semantic: 'delegation',
      },
    ];
    const out = detectThreats({
      nodes: twoAgents,
      edges: es,
      framework: 'AgenticAI',
      rules: [ruleDelegationPlain],
    });
    expect(out).toHaveLength(0);
  });

  it('semantic=tool_invocation マーク → delegation ルールは発火しない', () => {
    const es: DiagramEdge[] = [
      {
        id: 'e1',
        source: 'a1',
        target: 'a2',
        auth: 'None',
        network: 'VPC',
        encryption: 'Plain',
        semantic: 'tool_invocation',
      },
    ];
    const out = detectThreats({
      nodes: twoAgents,
      edges: es,
      framework: 'AgenticAI',
      rules: [ruleDelegationPlain],
    });
    expect(out).toHaveLength(0);
  });

  it('anyOf: semantic [delegation] AND (auth:None OR encryption:Plain) パターン', () => {
    const ruleAnyOf: ThreatRule = {
      id: 'rule-deleg-anyof',
      framework: 'AgenticAI',
      category: 'Identity',
      severity: 'High',
      description: 'delegation 整合性',
      appliesTo: {
        kind: 'edge',
        anyOf: [
          { semantic: ['delegation'], auth: ['None'] },
          { semantic: ['delegation'], encryption: ['Plain'] },
        ],
      },
    };
    // ケース1: delegation + auth None + TLS → 発火（1 つ目のリーフ一致）
    const out1 = detectThreats({
      nodes: twoAgents,
      edges: [
        {
          id: 'e',
          source: 'a1',
          target: 'a2',
          auth: 'None',
          network: 'VPC',
          encryption: 'TLS',
          semantic: 'delegation',
        },
      ],
      framework: 'AgenticAI',
      rules: [ruleAnyOf],
    });
    expect(out1).toHaveLength(1);

    // ケース2: delegation + auth MFA + Plain → 発火（2 つ目のリーフ一致）
    const out2 = detectThreats({
      nodes: twoAgents,
      edges: [
        {
          id: 'e',
          source: 'a1',
          target: 'a2',
          auth: 'MFA',
          network: 'VPC',
          encryption: 'Plain',
          semantic: 'delegation',
        },
      ],
      framework: 'AgenticAI',
      rules: [ruleAnyOf],
    });
    expect(out2).toHaveLength(1);

    // ケース3: delegation + MFA + TLS → 発火しない
    const out3 = detectThreats({
      nodes: twoAgents,
      edges: [
        {
          id: 'e',
          source: 'a1',
          target: 'a2',
          auth: 'MFA',
          network: 'VPC',
          encryption: 'TLS',
          semantic: 'delegation',
        },
      ],
      framework: 'AgenticAI',
      rules: [ruleAnyOf],
    });
    expect(out3).toHaveLength(0);

    // ケース4: semantic 未指定（=data_flow）+ 平文 → 発火しない
    const out4 = detectThreats({
      nodes: twoAgents,
      edges: [
        { id: 'e', source: 'a1', target: 'a2', auth: 'None', network: 'VPC', encryption: 'Plain' },
      ],
      framework: 'AgenticAI',
      rules: [ruleAnyOf],
    });
    expect(out4).toHaveLength(0);
  });

  it('semantic 条件なしのルールは semantic 値に関係なく発火する（既存挙動）', () => {
    const ruleNoSemantic: ThreatRule = {
      id: 'rule-no-semantic',
      framework: 'AgenticAI',
      category: 'Information Disclosure',
      severity: 'High',
      description: '平文通信',
      appliesTo: { kind: 'edge', when: { encryption: ['Plain'] } },
    };
    const es: DiagramEdge[] = [
      {
        id: 'e',
        source: 'a1',
        target: 'a2',
        auth: 'None',
        network: 'VPC',
        encryption: 'Plain',
        semantic: 'delegation',
      },
    ];
    const out = detectThreats({
      nodes: twoAgents,
      edges: es,
      framework: 'AgenticAI',
      rules: [ruleNoSemantic],
    });
    expect(out).toHaveLength(1);
  });

  it('semantic: [data_flow] と明示しても未マーク edge は既定で一致する', () => {
    const ruleDataFlowOnly: ThreatRule = {
      id: 'rule-data-flow-only',
      framework: 'STRIDE',
      category: 'Spoofing',
      severity: 'Medium',
      description: 'data_flow only',
      appliesTo: { kind: 'edge', when: { semantic: ['data_flow'], auth: ['None'] } },
    };
    const out = detectThreats({
      nodes: twoAgents,
      edges: [
        { id: 'e', source: 'a1', target: 'a2', auth: 'None', network: 'VPC', encryption: 'TLS' },
      ],
      framework: 'STRIDE',
      rules: [ruleDataFlowOnly],
    });
    expect(out).toHaveLength(1);
  });
});

// ─── subject（ElementalID 集約用の対象要素参照、[[plan]] §2.26 Step 4） ──────────
describe('detectThreats - subject', () => {
  it('node ルールの subject は対象ノードを指す', () => {
    const out = detectThreats({
      nodes,
      edges: [],
      framework: 'STRIDE',
      rules: [nodeRuleLLM],
    });
    expect(out).toHaveLength(1);
    expect(out[0].subject).toEqual({ kind: 'node', id: 'llm' });
  });

  it('edge ルールの subject はエッジ自身を指す（nodeId はターゲットノードのまま）', () => {
    const out = detectThreats({
      nodes,
      edges,
      framework: 'STRIDE',
      rules: [edgeRulePlain],
    });
    const t = out.find((x) => x.id.startsWith('rule-plain'));
    expect(t?.subject).toEqual({ kind: 'edge', id: 'e-pub' });
    expect(t?.nodeId).toBe('g'); // 既存 UI 互換：ターゲットノード
  });
});
