import { describe, expect, it } from 'vitest';
import { buildThreatViews } from './buildThreatViews';
import type { DetectedThreat, DiagramNode, ManualThreat } from '../model/types';

const NODES: DiagramNode[] = [
  { id: 'n1', type: 'LLM', x: 0, y: 0 },
  { id: 'n2', type: 'LLM', x: 0, y: 0 },
  { id: 'n3', type: 'DB', x: 0, y: 0 },
];

const detected: DetectedThreat[] = [
  {
    id: 'rule-a-n1',
    nodeId: 'n1',
    framework: 'STRIDE',
    category: '平文通信',
    severity: 'High',
    description: 'TLS 未使用。',
  },
  {
    id: 'rule-b-n2',
    nodeId: 'n2',
    framework: 'STRIDE',
    category: '認証なし',
    severity: 'Medium',
    description: '認証が無い。',
  },
];

const manual: ManualThreat[] = [
  {
    id: 'mt1',
    framework: 'STRIDE',
    nodeId: 'n2',
    category: '内部不正',
    severity: 'Critical',
    description: '管理者によるデータ持ち出し。',
    mitigation: '職務分掌',
  },
  {
    id: 'mt2',
    framework: 'AgenticAI',
    category: 'プロンプト注入',
    severity: 'High',
    description: 'ツール引数の注入。',
  },
];

describe('buildThreatViews', () => {
  it('検出脅威に origin=detected を付与する', () => {
    const views = buildThreatViews({
      detected,
      manualThreats: [],
      nodes: NODES,
      framework: 'STRIDE',
      suppressions: {},
    });
    expect(views).toHaveLength(2);
    expect(views.every((v) => v.origin === 'detected')).toBe(true);
  });

  it('dreadScores を最終 id キーで検出・手動の両方に付与する', () => {
    const score = {
      damage: 3,
      reproducibility: 2,
      exploitability: 1,
      affectedUsers: 2,
      discoverability: 1,
      at: 0,
    } as const;
    const views = buildThreatViews({
      detected,
      manualThreats: manual,
      nodes: NODES,
      framework: 'STRIDE',
      suppressions: {},
      dreadScores: { 'rule-a-n1': score, mt1: score },
    });
    expect(views.find((v) => v.id === 'rule-a-n1')?.dread).toEqual(score);
    expect(views.find((v) => v.id === 'mt1')?.dread).toEqual(score);
    expect(views.find((v) => v.id === 'rule-b-n2')?.dread).toBeUndefined();
  });

  it('controlStatuses を最終 id キーで検出・手動の両方に付与する', () => {
    const impl = { status: 'implemented' as const, note: 'WAF', at: 0 };
    const req = { status: 'required' as const, at: 0 };
    const views = buildThreatViews({
      detected,
      manualThreats: manual,
      nodes: NODES,
      framework: 'STRIDE',
      suppressions: {},
      controlStatuses: { 'rule-a-n1': impl, mt1: req },
    });
    expect(views.find((v) => v.id === 'rule-a-n1')?.controlStatus).toEqual(impl);
    expect(views.find((v) => v.id === 'mt1')?.controlStatus).toEqual(req);
    expect(views.find((v) => v.id === 'rule-b-n2')?.controlStatus).toBeUndefined();
  });

  it('手動脅威は作成時 framework がアクティブなときだけ含める', () => {
    const stride = buildThreatViews({
      detected: [],
      manualThreats: manual,
      nodes: NODES,
      framework: 'STRIDE',
      suppressions: {},
    });
    expect(stride.map((v) => v.manualId)).toEqual(['mt1']); // mt2 は AgenticAI なので除外

    const maestro = buildThreatViews({
      detected: [],
      manualThreats: manual,
      nodes: NODES,
      framework: 'AgenticAI',
      suppressions: {},
    });
    expect(maestro.map((v) => v.manualId)).toEqual(['mt2']);
  });

  it("framework='ALL' は framework を問わず全ての手動脅威を含める", () => {
    const all = buildThreatViews({
      detected: [],
      manualThreats: manual,
      nodes: NODES,
      framework: 'ALL',
      suppressions: {},
    });
    expect(all.map((v) => v.manualId).sort()).toEqual(['mt1', 'mt2']);
  });

  it('nodeId 未指定の手動脅威は nodeId="" にマップする', () => {
    const views = buildThreatViews({
      detected: [],
      manualThreats: manual,
      nodes: NODES,
      framework: 'AgenticAI',
      suppressions: {},
    });
    expect(views[0].nodeId).toBe('');
    expect(views[0].origin).toBe('manual');
  });

  it('手動脅威を検出脅威より先頭に並べる', () => {
    const views = buildThreatViews({
      detected,
      manualThreats: manual,
      nodes: NODES,
      framework: 'STRIDE',
      suppressions: {},
    });
    expect(views[0].origin).toBe('manual');
    expect(views[0].manualId).toBe('mt1');
    expect(views.slice(1).every((v) => v.origin === 'detected')).toBe(true);
  });

  it('抑制注記は検出脅威にのみ id 一致で付与する', () => {
    const views = buildThreatViews({
      detected,
      manualThreats: manual,
      nodes: NODES,
      framework: 'STRIDE',
      suppressions: {
        'rule-a-n1': { status: 'accepted', note: '受容', at: 1 },
      },
    });
    const a = views.find((v) => v.id === 'rule-a-n1');
    const b = views.find((v) => v.id === 'rule-b-n2');
    const m = views.find((v) => v.id === 'mt1');
    expect(a?.suppression?.status).toBe('accepted');
    expect(b?.suppression).toBeUndefined();
    expect(m?.suppression).toBeUndefined();
  });

  it('customRuleIds に含まれる ruleId の検出脅威に isCustom=true を付与する', () => {
    const det: DetectedThreat[] = [
      { id: 'custom-x-n1', ruleId: 'custom-x', nodeId: 'n1', framework: 'STRIDE', category: 'C', severity: 'High', description: 'd' },
      { id: 'bundled-y-n1', ruleId: 'bundled-y', nodeId: 'n1', framework: 'STRIDE', category: 'C', severity: 'Low', description: 'd' },
    ];
    const views = buildThreatViews({
      detected: det,
      manualThreats: [],
      nodes: NODES,
      framework: 'STRIDE',
      suppressions: {},
      customRuleIds: new Set(['custom-x']),
    });
    expect(views.find((v) => v.id === 'custom-x-n1')?.isCustom).toBe(true);
    expect(views.find((v) => v.id === 'bundled-y-n1')?.isCustom).toBe(false);
  });

  // ─── 型ターゲティング（プロジェクトローカルなカスタム node ルール） ───
  it('targetType を該当ノード全てに 1 件ずつ展開する', () => {
    const typeRule: ManualThreat = {
      id: 'mt-type',
      framework: 'STRIDE',
      targetType: 'LLM',
      category: 'LLM 共通リスク',
      severity: 'High',
      description: '全 LLM への共通脅威。',
    };
    const views = buildThreatViews({
      detected: [],
      manualThreats: [typeRule],
      nodes: NODES,
      framework: 'STRIDE',
      suppressions: {},
    });
    // LLM ノードは n1 / n2 の 2 つ
    expect(views).toHaveLength(2);
    expect(views.map((v) => v.nodeId).sort()).toEqual(['n1', 'n2']);
    expect(views.every((v) => v.manualId === 'mt-type')).toBe(true);
    expect(views.every((v) => v.manualTargetType === 'LLM')).toBe(true);
    // 各インスタンスの id は manualId-nodeId で一意
    expect(views.map((v) => v.id).sort()).toEqual(['mt-type-n1', 'mt-type-n2']);
  });

  it('targetType に該当ノードが無ければ管理用に 1 件（nodeId="")を出す', () => {
    const typeRule: ManualThreat = {
      id: 'mt-type',
      framework: 'STRIDE',
      targetType: 'AGENT',
      category: 'Agent リスク',
      severity: 'Medium',
      description: 'Agent 共通。',
    };
    const views = buildThreatViews({
      detected: [],
      manualThreats: [typeRule],
      nodes: NODES,
      framework: 'STRIDE',
      suppressions: {},
    });
    expect(views).toHaveLength(1);
    expect(views[0].nodeId).toBe('');
    expect(views[0].manualTargetType).toBe('AGENT');
    expect(views[0].manualId).toBe('mt-type');
  });

  // ─── subject（ElementalID 集約用、[[plan]] §2.26 Step 4） ───
  it('検出脅威の subject はそのまま素通しされる', () => {
    const det: DetectedThreat[] = [
      {
        id: 'rule-e-edge1',
        nodeId: 'n2',
        subject: { kind: 'edge', id: 'edge1' },
        framework: 'STRIDE',
        category: 'C',
        severity: 'High',
        description: 'd',
      },
    ];
    const views = buildThreatViews({
      detected: det,
      manualThreats: [],
      nodes: NODES,
      framework: 'STRIDE',
      suppressions: {},
    });
    expect(views[0].subject).toEqual({ kind: 'edge', id: 'edge1' });
  });

  it('nodeId 指定の手動脅威は subject を node に導出する', () => {
    const views = buildThreatViews({
      detected: [],
      manualThreats: manual,
      nodes: NODES,
      framework: 'STRIDE',
      suppressions: {},
    });
    expect(views[0].subject).toEqual({ kind: 'node', id: 'n2' }); // mt1
  });

  it('targetType 展開した手動脅威は各ノードを subject にする', () => {
    const typeRule: ManualThreat = {
      id: 'mt-type',
      framework: 'STRIDE',
      targetType: 'LLM',
      category: 'LLM 共通リスク',
      severity: 'High',
      description: '全 LLM への共通脅威。',
    };
    const views = buildThreatViews({
      detected: [],
      manualThreats: [typeRule],
      nodes: NODES,
      framework: 'STRIDE',
      suppressions: {},
    });
    expect(views.map((v) => v.subject).sort((a, b) => (a!.id < b!.id ? -1 : 1))).toEqual([
      { kind: 'node', id: 'n1' },
      { kind: 'node', id: 'n2' },
    ]);
  });

  it('全体スコープ（nodeId/targetType 未指定）の手動脅威は subject 未設定', () => {
    const views = buildThreatViews({
      detected: [],
      manualThreats: manual,
      nodes: NODES,
      framework: 'AgenticAI',
      suppressions: {},
    });
    expect(views[0].subject).toBeUndefined(); // mt2
  });

  // ─── canonicalId によるクロスソース畳み込み ───
  const canonical: DetectedThreat[] = [
    {
      id: 'atlas-supply-n1',
      ruleId: 'atlas-supply',
      canonicalId: 'supply-chain-model',
      nodeId: 'n1',
      subject: { kind: 'node', id: 'n1' },
      framework: 'AI',
      category: 'Supply Chain',
      name: 'モデル供給網侵害',
      severity: 'Critical',
      description: 'ATLAS 版の説明。',
      references: [{ title: 'MITRE ATLAS T0010.003' }],
    },
    {
      id: 'owasp-supply-n1',
      ruleId: 'owasp-supply',
      canonicalId: 'supply-chain-model',
      nodeId: 'n1',
      subject: { kind: 'node', id: 'n1' },
      framework: 'AI',
      category: 'Supply Chain',
      name: 'モデル・依存関係の供給網',
      severity: 'High',
      description: 'OWASP 版の説明。',
      references: [{ title: 'OWASP LLM03' }],
    },
  ];

  it('同一 canonicalId + 同一 subject は 1 枚に畳み込む', () => {
    const views = buildThreatViews({
      detected: canonical,
      manualThreats: [],
      nodes: NODES,
      framework: 'ALL',
      suppressions: {},
    });
    expect(views).toHaveLength(1);
    const v = views[0];
    // severity は最大値（Critical）
    expect(v.severity).toBe('Critical');
    // 代表は最大 severity メンバー（ATLAS 版）
    expect(v.name).toBe('モデル供給網侵害');
    // 決定的な id
    expect(v.id).toBe('supply-chain-model::node:n1');
    // 両ソースの出典が束ねられる
    expect(v.references?.map((r) => r.title).sort()).toEqual(['MITRE ATLAS T0010.003', 'OWASP LLM03']);
    // 裏付け情報
    expect(v.corroboration?.ruleIds.sort()).toEqual(['atlas-supply-n1', 'owasp-supply-n1']);
  });

  it('同一 canonicalId でも subject が異なれば畳み込まない', () => {
    const views = buildThreatViews({
      detected: [canonical[0], { ...canonical[1], id: 'owasp-supply-n2', nodeId: 'n2', subject: { kind: 'node', id: 'n2' } }],
      manualThreats: [],
      nodes: NODES,
      framework: 'ALL',
      suppressions: {},
    });
    expect(views).toHaveLength(2);
    expect(views.every((v) => v.corroboration === undefined)).toBe(true);
  });

  it('canonicalId が無い検出脅威は従来どおり独立表示（corroboration 無し）', () => {
    const views = buildThreatViews({
      detected,
      manualThreats: [],
      nodes: NODES,
      framework: 'STRIDE',
      suppressions: {},
    });
    expect(views).toHaveLength(2);
    expect(views.every((v) => v.corroboration === undefined)).toBe(true);
  });

  it('畳み込みビューの抑制は決定的 id で付与される', () => {
    const views = buildThreatViews({
      detected: canonical,
      manualThreats: [],
      nodes: NODES,
      framework: 'ALL',
      suppressions: {
        'supply-chain-model::node:n1': { status: 'accepted', note: '受容', at: 1 },
      },
    });
    expect(views[0].suppression?.status).toBe('accepted');
  });
});
