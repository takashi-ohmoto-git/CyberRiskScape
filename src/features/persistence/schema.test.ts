import { describe, expect, it } from 'vitest';
import {
  PERSISTED_PROJECT_SCHEMA_VERSION,
  PersistedProjectSchema,
} from './schema';

const VALID_PROJECT = {
  schemaVersion: PERSISTED_PROJECT_SCHEMA_VERSION,
  nodes: [{ id: 'n1', type: 'USER', x: 10, y: 20 }],
  edges: [
    {
      id: 'e1',
      source: 'n1',
      target: 'n2',
      auth: 'None',
      network: 'Internet',
      encryption: 'Plain',
    },
  ],
  boundaries: [
    {
      id: 'b1',
      type: 'ROUNDED_DASHED',
      x: 0,
      y: 0,
      width: 100,
      height: 80,
      trustLevel: 'Internal',
    },
  ],
  activeFramework: 'STRIDE',
  updatedAt: 1_700_000_000_000,
};

describe('PersistedProjectSchema', () => {
  it('正常なプロジェクトレコードを受理する', () => {
    const r = PersistedProjectSchema.safeParse(VALID_PROJECT);
    expect(r.success).toBe(true);
  });

  it('schemaVersion が未来バージョンの場合は拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      schemaVersion: 999,
    });
    expect(r.success).toBe(false);
  });

  it('未知の activeFramework を拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      activeFramework: 'PASTA',
    });
    expect(r.success).toBe(false);
  });

  it("activeFramework='ALL'（ビュー専用値）を受理する", () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      activeFramework: 'ALL',
    });
    expect(r.success).toBe(true);
  });

  it('境界の label は 64 文字まで受理し、超えると拒否する', () => {
    const withLabel = (label: string) =>
      PersistedProjectSchema.safeParse({
        ...VALID_PROJECT,
        boundaries: [{ ...VALID_PROJECT.boundaries[0], label }],
      });
    const ok = withLabel('基幹システム区画');
    expect(ok.success).toBe(true);
    if (ok.success) expect(ok.data.boundaries?.[0]?.label).toBe('基幹システム区画');
    expect(withLabel('a'.repeat(64)).success).toBe(true);
    expect(withLabel('a'.repeat(65)).success).toBe(false);
  });

  it('境界の width が 0 以下なら拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      boundaries: [{ ...VALID_PROJECT.boundaries[0], width: 0 }],
    });
    expect(r.success).toBe(false);
  });

  it('node 型は open string ID を受理する（カスタムライブラリ対応）', () => {
    // 旧仕様（closed enum）では UNKNOWN_KIND を拒否していたが、
    // §2.16 の string ID 化以降は形式が合えば受理する。実在性は ComponentRegistry で別途検証。
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ id: 'x', type: 'MCP_SERVER', x: 0, y: 0 }],
    });
    expect(r.success).toBe(true);
  });

  it('node 型: 小文字始まりなど形式違反は拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ id: 'x', type: 'invalid-format', x: 0, y: 0 }],
    });
    expect(r.success).toBe(false);
  });

  it('id が空文字なら拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ id: '', type: 'USER', x: 0, y: 0 }],
    });
    expect(r.success).toBe(false);
  });

  it('オプショナルな label / description / managedState を許容する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [
        {
          id: 'n1',
          type: 'PC',
          x: 0,
          y: 0,
          label: '営業 PC',
          description: 'BYOD',
          managedState: 'Unmanaged',
        },
      ],
    });
    expect(r.success).toBe(true);
  });

  it('USER ノードの userTrustAttribute を許容する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [
        { id: 'u1', type: 'USER', x: 0, y: 0, userTrustAttribute: 'Guest' },
        { id: 'u2', type: 'USER', x: 0, y: 0, userTrustAttribute: 'Employee' },
        { id: 'u3', type: 'USER', x: 0, y: 0, userTrustAttribute: 'Contractor' },
        { id: 'u4', type: 'USER', x: 0, y: 0, userTrustAttribute: 'Partner' },
      ],
    });
    expect(r.success).toBe(true);
  });

  it('未知の userTrustAttribute を拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ id: 'u1', type: 'USER', x: 0, y: 0, userTrustAttribute: 'Admin' }],
    });
    expect(r.success).toBe(false);
  });

  // ─── クラウド属性（SAAS/IAAS/PAAS） ──────────
  it('クラウドノードの cloudSanction / cloudOwnership を許容する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [
        { id: 'c1', type: 'SAAS', x: 0, y: 0, cloudSanction: 'Sanctioned', cloudOwnership: 'Company' },
        { id: 'c2', type: 'IAAS', x: 0, y: 0, cloudSanction: 'Unsanctioned', cloudOwnership: 'ThirdParty' },
        { id: 'c3', type: 'PAAS', x: 0, y: 0, cloudOwnership: 'Personal' },
      ],
    });
    expect(r.success).toBe(true);
  });

  it('未知の cloudSanction 値を拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ id: 'c1', type: 'SAAS', x: 0, y: 0, cloudSanction: 'Approved' }],
    });
    expect(r.success).toBe(false);
  });

  it('未知の cloudOwnership 値を拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ id: 'c1', type: 'SAAS', x: 0, y: 0, cloudOwnership: 'Government' }],
    });
    expect(r.success).toBe(false);
  });

  // ─── 攻撃者属性（THREAT_ACTOR / INSIDER_THREAT / AGENTIC_ATTACKER） ──────────
  it('攻撃者ノードの threatActorType / attackObjectiveId を許容する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [
        { id: 'a1', type: 'THREAT_ACTOR', x: 0, y: 0, threatActorType: 'CyberCriminals', attackObjectiveId: 'n1' },
        { id: 'a2', type: 'INSIDER_THREAT', x: 0, y: 0, attackObjectiveId: 'n1' },
        { id: 'a3', type: 'AGENTIC_ATTACKER', x: 0, y: 0 },
        { id: 'n1', type: 'DATA_STORE', x: 0, y: 0 },
      ],
    });
    expect(r.success).toBe(true);
  });

  it('全ての threatActorType 値を受理する', () => {
    for (const val of [
      'CyberCriminals',
      'NationStateActors',
      'FinanciallyMotivatedActors',
      'Hacktivists',
      'ScriptKiddies',
    ]) {
      const r = PersistedProjectSchema.safeParse({
        ...VALID_PROJECT,
        nodes: [{ id: 'a1', type: 'THREAT_ACTOR', x: 0, y: 0, threatActorType: val }],
      });
      expect(r.success).toBe(true);
    }
  });

  it('未知の threatActorType 値を拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ id: 'a1', type: 'THREAT_ACTOR', x: 0, y: 0, threatActorType: 'APT' }],
    });
    expect(r.success).toBe(false);
  });

  it('空文字の attackObjectiveId を拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ id: 'a1', type: 'THREAT_ACTOR', x: 0, y: 0, attackObjectiveId: '' }],
    });
    expect(r.success).toBe(false);
  });

  // ─── projectMeta（Project Edit 機能の永続化） ──────────────────
  it('projectMeta を省略しても受理する（後方互換）', () => {
    const r = PersistedProjectSchema.safeParse(VALID_PROJECT);
    expect(r.success).toBe(true);
  });

  it('projectMeta 4 フィールド完備を受理する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      projectMeta: {
        name: 'ProjectIT',
        systemName: 'CreditScoringAPI',
        purpose: '与信判定',
        businessImpact: '停止時に営業停止',
      },
    });
    expect(r.success).toBe(true);
  });

  it('projectMeta は全フィールド空文字も受理する（初期状態の保存）', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      projectMeta: { name: '', systemName: '', purpose: '', businessImpact: '' },
    });
    expect(r.success).toBe(true);
  });

  it('projectMeta.name が 200 文字超で拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      projectMeta: {
        name: 'a'.repeat(201),
        systemName: '',
        purpose: '',
        businessImpact: '',
      },
    });
    expect(r.success).toBe(false);
  });

  it('projectMeta.purpose が 2000 文字超で拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      projectMeta: {
        name: '',
        systemName: '',
        purpose: 'p'.repeat(2001),
        businessImpact: '',
      },
    });
    expect(r.success).toBe(false);
  });

  it('projectMeta のフィールドが string でない場合は拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      projectMeta: { name: 123, systemName: '', purpose: '', businessImpact: '' },
    });
    expect(r.success).toBe(false);
  });

  // ─── 深度レイヤー（layers / activeLayer の永続化） ─────────
  it('layers + activeLayer を完備した形を受理する', () => {
    const emptyLayer = { nodes: [], edges: [], boundaries: [] };
    const r = PersistedProjectSchema.safeParse({
      schemaVersion: PERSISTED_PROJECT_SCHEMA_VERSION,
      layers: {
        L0: emptyLayer,
        L1: VALID_PROJECT,
        L2: emptyLayer,
        L3: emptyLayer,
      },
      activeLayer: 'L1',
      activeFramework: 'STRIDE',
      updatedAt: 1_700_000_000_000,
    });
    expect(r.success).toBe(true);
  });

  it('layers にレイヤーキーが欠けていれば拒否する', () => {
    const emptyLayer = { nodes: [], edges: [], boundaries: [] };
    const r = PersistedProjectSchema.safeParse({
      schemaVersion: PERSISTED_PROJECT_SCHEMA_VERSION,
      // L3 を欠落させる
      layers: { L0: emptyLayer, L1: emptyLayer, L2: emptyLayer },
      activeLayer: 'L0',
      activeFramework: 'STRIDE',
      updatedAt: 0,
    });
    expect(r.success).toBe(false);
  });

  it('activeLayer に不正値が来たら拒否する', () => {
    const emptyLayer = { nodes: [], edges: [], boundaries: [] };
    const r = PersistedProjectSchema.safeParse({
      schemaVersion: PERSISTED_PROJECT_SCHEMA_VERSION,
      layers: { L0: emptyLayer, L1: emptyLayer, L2: emptyLayer, L3: emptyLayer },
      activeLayer: 'L4', // 存在しないレイヤー
      activeFramework: 'STRIDE',
      updatedAt: 0,
    });
    expect(r.success).toBe(false);
  });

  it('旧形式（layers 無し / トップレベル nodes/edges/boundaries）も受理する', () => {
    const r = PersistedProjectSchema.safeParse(VALID_PROJECT);
    expect(r.success).toBe(true);
  });

  it('layers も旧トップレベルフィールドも無い最小形を受理する（マイグレ時の初期化用）', () => {
    const r = PersistedProjectSchema.safeParse({
      schemaVersion: PERSISTED_PROJECT_SCHEMA_VERSION,
      activeFramework: 'STRIDE',
      updatedAt: 0,
    });
    expect(r.success).toBe(true);
  });

  // ─── manualThreats（手動脅威シナリオ） ──────────────────
  it('manualThreats を省略しても受理する（後方互換）', () => {
    expect(PersistedProjectSchema.safeParse(VALID_PROJECT).success).toBe(true);
  });

  it('全レイヤー分の manualThreats を受理する（nodeId 省略 / 付与 両方）', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      manualThreats: {
        L0: [],
        L1: [
          {
            id: 'mt1',
            framework: 'STRIDE',
            category: '内部不正による顧客データ持ち出し',
            severity: 'High',
            description: '特権 DB 管理者がエクスポート権限を悪用する。',
            mitigation: '職務分掌と DLP 監視',
          },
          {
            id: 'mt2',
            framework: 'AgenticAI',
            nodeId: 'n2',
            category: 'プロンプト経由の権限昇格',
            severity: 'Critical',
            description: 'ツール呼び出しの引数注入。',
          },
        ],
        L2: [],
        L3: [],
      },
    });
    expect(r.success).toBe(true);
  });

  it('manualThreats: targetType（カスタム型ルール）を受理する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      manualThreats: {
        L0: [],
        L1: [
          {
            id: 'mt-type',
            framework: 'STRIDE',
            targetType: 'LLM',
            category: 'LLM 共通リスク',
            severity: 'High',
            description: '全 LLM への共通脅威。',
          },
        ],
        L2: [],
        L3: [],
      },
    });
    expect(r.success).toBe(true);
  });

  it('manualThreats: レイヤーキー欠落は拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      manualThreats: { L0: [], L1: [], L2: [] },
    });
    expect(r.success).toBe(false);
  });

  it('manualThreats: 未知の severity / framework / 空 category を拒否する', () => {
    const base = { id: 'mt1', framework: 'STRIDE', severity: 'High', description: 'x' };
    const make = (over: Record<string, unknown>) =>
      PersistedProjectSchema.safeParse({
        ...VALID_PROJECT,
        manualThreats: { L0: [], L1: [{ ...base, category: 'c', ...over }], L2: [], L3: [] },
      }).success;
    expect(make({ severity: 'Catastrophic' })).toBe(false);
    expect(make({ framework: 'PASTA' })).toBe(false);
    expect(make({ category: '' })).toBe(false);
  });

  // ─── suppressions（検出脅威の抑制注記） ──────────────────
  it('suppressions を受理する（accepted / false-positive、note 省略可）', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      suppressions: {
        'rule-a-n1': { status: 'accepted', note: '残留リスクとして受容', at: 1_700_000_000_000 },
        'rule-b-e1': { status: 'false-positive', at: 1_700_000_000_000 },
      },
    });
    expect(r.success).toBe(true);
  });

  it('suppressions: 未知の status を拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      suppressions: { 'rule-a-n1': { status: 'ignored', at: 0 } },
    });
    expect(r.success).toBe(false);
  });

  // ─── posture ──────────
  it('posture: 全フィールド指定を受理する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [
        {
          ...VALID_PROJECT.nodes[0],
          posture: {
            logCollection: 'Collected',
            logRetention: 'OneYearOrMore',
            logReviewer: 'Both',
            encryptionAtRest: 'ProviderManagedKey',
            patchStatus: 'Missing',
            accountReview: 'Irregular',
            dataNecessity: 'UnderReview',
            recordVolume: 'Over1M',
            lastReviewedAt: '2026-02-28',
            reviewNote: 'メモ',
          },
        },
      ],
    });
    expect(r.success).toBe(true);
  });

  it('posture: 未知の列挙値を拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ ...VALID_PROJECT.nodes[0], posture: { logRetention: 'Forever' } }],
    });
    expect(r.success).toBe(false);
  });

  it.each(['2026-13-01', '2026-02-30', '2026/10/10', '20261010', ''])(
    'posture: 不正な lastReviewedAt %s を拒否する',
    (bad) => {
      const r = PersistedProjectSchema.safeParse({
        ...VALID_PROJECT,
        nodes: [{ ...VALID_PROJECT.nodes[0], posture: { lastReviewedAt: bad } }],
      });
      expect(r.success).toBe(false);
    },
  );

  // ─── agentAttributes ──────────
  it('agentAttributes: 3 フィールド全指定を受理する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [
        {
          ...VALID_PROJECT.nodes[0],
          agentAttributes: {
            agency: 'Bounded',
            blastRadius: 'Tenant',
            identityTier: 'Cryptographic',
          },
        },
      ],
    });
    expect(r.success).toBe(true);
  });

  it('agentAttributes: 全フィールド未指定の空オブジェクトも受理する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ ...VALID_PROJECT.nodes[0], agentAttributes: {} }],
    });
    expect(r.success).toBe(true);
  });

  it('agentAttributes: 未知の agency 値を拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ ...VALID_PROJECT.nodes[0], agentAttributes: { agency: 'Superhuman' } }],
    });
    expect(r.success).toBe(false);
  });

  it('agentAttributes: 未知の blastRadius 値を拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ ...VALID_PROJECT.nodes[0], agentAttributes: { blastRadius: 'Galaxy' } }],
    });
    expect(r.success).toBe(false);
  });

  it('agentAttributes: 未知の identityTier 値を拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ ...VALID_PROJECT.nodes[0], agentAttributes: { identityTier: 'Magic' } }],
    });
    expect(r.success).toBe(false);
  });

  it('agentAttributes 未設定の旧データを受理する（後方互換）', () => {
    const r = PersistedProjectSchema.safeParse(VALID_PROJECT);
    expect(r.success).toBe(true);
  });

  // ─── edge.semantic ──────────
  it('edge.semantic: 全ての有効値を受理する', () => {
    const semantics = [
      'data_flow',
      'tool_invocation',
      'delegation',
      'memory_read',
      'memory_write',
      'rag_retrieval',
      'directory_sync',
    ];
    for (const sem of semantics) {
      const r = PersistedProjectSchema.safeParse({
        ...VALID_PROJECT,
        edges: [{ ...VALID_PROJECT.edges[0], semantic: sem }],
      });
      expect(r.success, `semantic "${sem}" should be valid`).toBe(true);
    }
  });

  it('edge.semantic: 未知の値を拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      edges: [{ ...VALID_PROJECT.edges[0], semantic: 'mind_meld' }],
    });
    expect(r.success).toBe(false);
  });

  it('edge.semantic 未設定の旧データを受理する（後方互換）', () => {
    const r = PersistedProjectSchema.safeParse(VALID_PROJECT);
    expect(r.success).toBe(true);
  });

  // ─── node.identityProviderKind ──────────
  it('node.identityProviderKind: 全ての有効値を受理する', () => {
    for (const kind of ['IDaaS', 'Directory', 'Hybrid', 'Social', 'Custom']) {
      const r = PersistedProjectSchema.safeParse({
        ...VALID_PROJECT,
        nodes: [{ ...VALID_PROJECT.nodes[0], identityProviderKind: kind }],
      });
      expect(r.success, `kind "${kind}" should be valid`).toBe(true);
    }
  });

  it('node.identityProviderKind: 未知の値を拒否する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ ...VALID_PROJECT.nodes[0], identityProviderKind: 'Kerberos' }],
    });
    expect(r.success).toBe(false);
  });

  // ─── edge.authProviderId ──────────
  it('edge.authProviderId: ノード id 文字列を受理する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      edges: [{ ...VALID_PROJECT.edges[0], authProviderId: 'n-idp-1' }],
    });
    expect(r.success).toBe(true);
  });

  it('edge.authProviderId: 空文字を拒否する（未設定は省略で表す）', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      edges: [{ ...VALID_PROJECT.edges[0], authProviderId: '' }],
    });
    expect(r.success).toBe(false);
  });

  it('edge.authProviderId 未設定の旧データを受理する（後方互換）', () => {
    const r = PersistedProjectSchema.safeParse(VALID_PROJECT);
    expect(r.success).toBe(true);
  });

  // ─── node.authProviderId ──────────
  it('node.authProviderId: ノード id 文字列を受理する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ ...VALID_PROJECT.nodes[0], authProviderId: 'n-idp-1' }],
    });
    expect(r.success).toBe(true);
  });

  it('node.authProviderId: 空文字を拒否する（未設定は省略で表す）', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ ...VALID_PROJECT.nodes[0], authProviderId: '' }],
    });
    expect(r.success).toBe(false);
  });

  // ─── node.logSinkId ──────────
  it('node.logSinkId: ノード id 文字列を受理する', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ ...VALID_PROJECT.nodes[0], logSinkId: 'n-siem-1' }],
    });
    expect(r.success).toBe(true);
  });

  it('node.logSinkId: 空文字を拒否する（未設定は省略で表す）', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ ...VALID_PROJECT.nodes[0], logSinkId: '' }],
    });
    expect(r.success).toBe(false);
  });

  // ─── layer.annotations（キャンバス注釈） ──────────
  it('layer.annotations: label / callout（targetNodeId 有り）を受理する', () => {
    const emptyLayer = { nodes: [], edges: [], boundaries: [] };
    const r = PersistedProjectSchema.safeParse({
      schemaVersion: PERSISTED_PROJECT_SCHEMA_VERSION,
      layers: {
        L0: emptyLayer,
        L1: {
          ...emptyLayer,
          annotations: [
            { id: 'ann1', kind: 'label', x: 0, y: 0, text: 'この部分は決済フロー' },
            { id: 'ann2', kind: 'callout', x: 100, y: 100, text: '要注意', targetNodeId: 'n1' },
          ],
        },
        L2: emptyLayer,
        L3: emptyLayer,
      },
      activeLayer: 'L1',
      activeFramework: 'STRIDE',
      updatedAt: 0,
    });
    expect(r.success).toBe(true);
  });

  it('layer.annotations を省略しても受理する（後方互換、旧データは注釈なし）', () => {
    const emptyLayer = { nodes: [], edges: [], boundaries: [] };
    const r = PersistedProjectSchema.safeParse({
      schemaVersion: PERSISTED_PROJECT_SCHEMA_VERSION,
      layers: { L0: emptyLayer, L1: emptyLayer, L2: emptyLayer, L3: emptyLayer },
      activeLayer: 'L1',
      activeFramework: 'STRIDE',
      updatedAt: 0,
    });
    expect(r.success).toBe(true);
  });

  it('layer.annotations: リサイズ後の width/height を受理し、0 以下は拒否する', () => {
    const emptyLayer = { nodes: [], edges: [], boundaries: [] };
    const parse = (width: number) =>
      PersistedProjectSchema.safeParse({
        schemaVersion: PERSISTED_PROJECT_SCHEMA_VERSION,
        layers: {
          L0: emptyLayer,
          L1: {
            ...emptyLayer,
            annotations: [{ id: 'ann1', kind: 'callout', x: 0, y: 0, text: 'x', width, height: 80 }],
          },
          L2: emptyLayer,
          L3: emptyLayer,
        },
        activeLayer: 'L1',
        activeFramework: 'STRIDE',
        updatedAt: 0,
      });
    expect(parse(300).success).toBe(true);
    expect(parse(0).success).toBe(false);
  });

  it('layer.annotations: 未知の kind を拒否する', () => {
    const emptyLayer = { nodes: [], edges: [], boundaries: [] };
    const r = PersistedProjectSchema.safeParse({
      schemaVersion: PERSISTED_PROJECT_SCHEMA_VERSION,
      layers: {
        L0: emptyLayer,
        L1: { ...emptyLayer, annotations: [{ id: 'ann1', kind: 'sticky-note', x: 0, y: 0, text: 'x' }] },
        L2: emptyLayer,
        L3: emptyLayer,
      },
      activeLayer: 'L1',
      activeFramework: 'STRIDE',
      updatedAt: 0,
    });
    expect(r.success).toBe(false);
  });

  it('layer.annotations: targetNodeId の空文字を拒否する（未リンクは省略で表す）', () => {
    const emptyLayer = { nodes: [], edges: [], boundaries: [] };
    const r = PersistedProjectSchema.safeParse({
      schemaVersion: PERSISTED_PROJECT_SCHEMA_VERSION,
      layers: {
        L0: emptyLayer,
        L1: {
          ...emptyLayer,
          annotations: [{ id: 'ann1', kind: 'callout', x: 0, y: 0, text: 'x', targetNodeId: '' }],
        },
        L2: emptyLayer,
        L3: emptyLayer,
      },
      activeLayer: 'L1',
      activeFramework: 'STRIDE',
      updatedAt: 0,
    });
    expect(r.success).toBe(false);
  });

  it('attackSurface に hasResponseCache が無い旧データも受理する（後方互換）', () => {
    const r = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ id: 'n1', type: 'REVERSE_PROXY', x: 0, y: 0, attackSurface: { hasGlobalIp: true } }],
    });
    expect(r.success).toBe(true);
    const r2 = PersistedProjectSchema.safeParse({
      ...VALID_PROJECT,
      nodes: [{ id: 'n1', type: 'REVERSE_PROXY', x: 0, y: 0, attackSurface: { hasResponseCache: false } }],
    });
    expect(r2.success).toBe(true);
  });

  describe('ノードのインベントリ', () => {
    const NPM = {
      kind: 'npm',
      source: 'package-lock.json',
      collectedAt: '2026-10-29T00:00:00.000Z',
      items: [{ name: 'left-pad', version: '1.3.0', pinned: true, hasIntegrity: true }],
    };
    const ENV = {
      kind: 'env',
      source: '.env',
      collectedAt: '2026-10-29T00:00:00.000Z',
      template: false,
      gitIgnored: true,
      items: [{ name: 'API_KEY', valueKind: 'secret-like', length: 32 }],
    };
    const withInventory = (inventory: unknown) => ({
      ...VALID_PROJECT,
      nodes: [{ ...VALID_PROJECT.nodes[0], inventory }],
    });

    it('npm / env のインベントリが読込で保たれる', () => {
      for (const inv of [NPM, ENV]) {
        const r = PersistedProjectSchema.safeParse(withInventory(inv));
        expect(r.success).toBe(true);
        if (r.success) expect(r.data.nodes![0].inventory).toEqual(inv);
      }
    });

    it('インベントリ無しの既存データがそのまま読める', () => {
      const r = PersistedProjectSchema.safeParse(VALID_PROJECT);
      expect(r.success).toBe(true);
      if (r.success) expect(r.data.nodes![0].inventory).toBeUndefined();
    });

    it('env 項目に value が紛れても読込時に捨てられる', () => {
      const dirty = { ...ENV, items: [{ ...ENV.items[0], value: 'sk-secret' }] };
      const r = PersistedProjectSchema.safeParse(withInventory(dirty));
      expect(r.success).toBe(true);
      if (r.success) {
        expect(JSON.stringify(r.data)).not.toContain('sk-secret');
        expect(r.data.nodes![0].inventory?.items[0]).not.toHaveProperty('value');
      }
    });

    it('未知の kind は拒否する', () => {
      expect(PersistedProjectSchema.safeParse(withInventory({ ...NPM, kind: 'gem' })).success).toBe(false);
    });
  });
});
