import { describe, expect, it } from 'vitest';
import {
  deserializeProject,
  resolveIdCounters,
  resolveLayers,
  serializeProject,
  type SerializableState,
} from './serialize';
import { PERSISTED_PROJECT_SCHEMA_VERSION } from './schema';
import { EMPTY_LAYER, type LayerData, type LayerKey } from '../../core/model/types';

const L1_DATA: LayerData = {
  nodes: [
    { id: 'n1', type: 'USER', x: 10, y: 20 },
    { id: 'n2', type: 'LLM', x: 100, y: 200, label: 'GPT' },
  ],
  edges: [
    {
      id: 'e1',
      source: 'n1',
      target: 'n2',
      auth: 'Password',
      network: 'VPC',
      encryption: 'TLS',
    },
  ],
  boundaries: [
    {
      id: 'b1',
      type: 'ROUNDED_DASHED',
      x: 0,
      y: 0,
      width: 300,
      height: 200,
      trustLevel: 'Partner',
    },
  ],
};

const STATE: SerializableState = {
  layers: { L0: EMPTY_LAYER, L1: L1_DATA, L2: EMPTY_LAYER, L3: EMPTY_LAYER },
  activeLayer: 'L1',
  activeFramework: 'AgenticAI',
};

describe('serializeProject / deserializeProject', () => {
  it('serialize は schemaVersion と updatedAt を付与する', () => {
    const before = Date.now();
    const out = serializeProject(STATE);
    const after = Date.now();
    expect(out.schemaVersion).toBe(PERSISTED_PROJECT_SCHEMA_VERSION);
    expect(out.updatedAt).toBeGreaterThanOrEqual(before);
    expect(out.updatedAt).toBeLessThanOrEqual(after);
  });

  it('round-trip でレイヤー構造が保持される', () => {
    const persisted = serializeProject(STATE);
    const restored = deserializeProject(persisted);
    expect(restored).not.toBeNull();
    expect(restored?.layers?.L1).toEqual(L1_DATA);
    expect(restored?.layers?.L0).toEqual(EMPTY_LAYER);
    expect(restored?.activeLayer).toBe('L1');
    expect(restored?.activeFramework).toBe(STATE.activeFramework);
  });

  it('dreadScores を round-trip で保持し、空なら出力しない', () => {
    const score = {
      damage: 3,
      reproducibility: 2,
      exploitability: 2,
      affectedUsers: 3,
      discoverability: 1,
      at: 123,
    } as const;
    const persisted = serializeProject({ ...STATE, dreadScores: { 'rule-x-n1': score } });
    const restored = deserializeProject(persisted);
    expect(restored?.dreadScores).toEqual({ 'rule-x-n1': score });
    // 評価なしならフィールド自体を出力しない（旧データとの差分を抑える）
    expect('dreadScores' in serializeProject(STATE)).toBe(false);
    expect('dreadScores' in serializeProject({ ...STATE, dreadScores: {} })).toBe(false);
  });

  it('未来バージョンは null を返す（壊れたデータを書き戻さない）', () => {
    const future = { ...serializeProject(STATE), schemaVersion: 999 };
    expect(deserializeProject(future)).toBeNull();
  });

  it('不正な形（undefined / number / 欠損キー）は null を返す', () => {
    expect(deserializeProject(undefined)).toBeNull();
    expect(deserializeProject(42)).toBeNull();
    expect(deserializeProject({ schemaVersion: 1 })).toBeNull();
  });

  it('入力のミューテーションを行わない（純粋関数）', () => {
    const snapshot = JSON.parse(JSON.stringify(STATE));
    serializeProject(STATE);
    expect(STATE).toEqual(snapshot);
  });

  it('disabledLibraryIds: Set を受け取って配列で保存する', () => {
    const withDisabled: SerializableState = {
      ...STATE,
      disabledLibraryIds: new Set(['my-mcp', 'other-pack']),
    };
    const out = serializeProject(withDisabled);
    expect(out.disabledLibraryIds).toBeDefined();
    expect(new Set(out.disabledLibraryIds)).toEqual(new Set(['my-mcp', 'other-pack']));
    const restored = deserializeProject(out);
    expect(restored?.disabledLibraryIds).toBeDefined();
    expect(new Set(restored?.disabledLibraryIds ?? [])).toEqual(
      new Set(['my-mcp', 'other-pack']),
    );
  });

  it('disabledLibraryIds が空の場合は省略される（schemaVersion 据え置きの後方互換）', () => {
    const out = serializeProject(STATE);
    expect(out.disabledLibraryIds).toBeUndefined();
  });

  // ─── projectMeta（Project Edit 機能） ──────────────────
  it('projectMeta: 全フィールド空のときは省略される（後方互換）', () => {
    const out = serializeProject({
      ...STATE,
      projectMeta: {
        name: '',
        systemName: '',
        purpose: '',
        businessImpact: '',
        securityObjectives: '',
      },
    });
    expect(out.projectMeta).toBeUndefined();
  });

  it('projectMeta: 1 フィールドでも入っていれば保存される', () => {
    const out = serializeProject({
      ...STATE,
      projectMeta: {
        name: 'ProjectIT',
        systemName: '',
        purpose: '',
        businessImpact: '',
        securityObjectives: '',
      },
    });
    expect(out.projectMeta).toEqual({
      name: 'ProjectIT',
      systemName: '',
      purpose: '',
      businessImpact: '',
      securityObjectives: '',
    });
  });

  it('projectMeta: securityObjectives のみでも保存される', () => {
    const out = serializeProject({
      ...STATE,
      projectMeta: {
        name: '',
        systemName: '',
        purpose: '',
        businessImpact: '',
        securityObjectives: '機密データの漏洩ゼロ',
      },
    });
    expect(out.projectMeta?.securityObjectives).toBe('機密データの漏洩ゼロ');
  });

  it('projectMeta: round-trip でデータ保持される', () => {
    const meta = {
      name: 'ProjectIT',
      systemName: 'CreditScoringAPI',
      purpose: '与信判定 API',
      businessImpact: '停止時に営業停止',
      securityObjectives: '個人情報の機密性確保 / 与信判定の完全性',
    };
    const out = serializeProject({ ...STATE, projectMeta: meta });
    const restored = deserializeProject(out);
    expect(restored?.projectMeta).toEqual(meta);
  });

  it('projectMeta: 旧データ（securityObjectives 欠落）は空文字で補完される（後方互換）', () => {
    const legacy = {
      ...serializeProject(STATE),
      projectMeta: {
        name: 'Legacy',
        systemName: '',
        purpose: '',
        businessImpact: '',
      },
    };
    const restored = deserializeProject(legacy);
    expect(restored?.projectMeta?.securityObjectives).toBe('');
    expect(restored?.projectMeta?.name).toBe('Legacy');
  });

  // ─── manualThreats / suppressions（手動脅威・抑制） ──────────────────
  it('manualThreats: 全レイヤー空のときは省略される（後方互換）', () => {
    const out = serializeProject({
      ...STATE,
      manualThreats: { L0: [], L1: [], L2: [], L3: [] },
    });
    expect(out.manualThreats).toBeUndefined();
  });

  it('manualThreats: 1 件でもあれば保存し round-trip で保持される', () => {
    const mt = {
      id: 'mt1',
      framework: 'AgenticAI' as const,
      nodeId: 'n2',
      category: 'プロンプト注入',
      severity: 'Critical' as const,
      description: 'ツール引数の注入。',
    };
    const out = serializeProject({
      ...STATE,
      manualThreats: { L0: [], L1: [mt], L2: [], L3: [] },
    });
    expect(out.manualThreats?.L1).toEqual([mt]);
    const restored = deserializeProject(out);
    expect(restored?.manualThreats?.L1).toEqual([mt]);
  });

  it('manualThreats: targetType（カスタム型ルール）が round-trip で保持される', () => {
    const mt = {
      id: 'mt-type',
      framework: 'STRIDE' as const,
      targetType: 'LLM',
      category: 'LLM 共通リスク',
      severity: 'High' as const,
      description: '全 LLM への共通脅威。',
    };
    const out = serializeProject({
      ...STATE,
      manualThreats: { L0: [], L1: [mt], L2: [], L3: [] },
    });
    const restored = deserializeProject(out);
    expect(restored?.manualThreats?.L1).toEqual([mt]);
  });

  it('suppressions: 空のときは省略される（後方互換）', () => {
    expect(serializeProject({ ...STATE, suppressions: {} }).suppressions).toBeUndefined();
  });

  it('suppressions: round-trip で保持される', () => {
    const suppressions = {
      'rule-a-n1': { status: 'accepted' as const, note: '受容', at: 1_700_000_000_000 },
    };
    const out = serializeProject({ ...STATE, suppressions });
    const restored = deserializeProject(out);
    expect(restored?.suppressions).toEqual(suppressions);
  });

  // ─── controlStatuses（対策実装状況） ──────────────────
  it('controlStatuses: 空のときは省略される（後方互換）', () => {
    expect('controlStatuses' in serializeProject(STATE)).toBe(false);
    expect('controlStatuses' in serializeProject({ ...STATE, controlStatuses: {} })).toBe(false);
  });

  it('controlStatuses: round-trip で保持される', () => {
    const controlStatuses = {
      'rule-a-n1': { status: 'implemented' as const, note: 'WAF で対処', at: 1_700_000_000_000 },
      'rule-b-n2': { status: 'required' as const, at: 1_700_000_000_001 },
    };
    const out = serializeProject({ ...STATE, controlStatuses });
    const restored = deserializeProject(out);
    expect(restored?.controlStatuses).toEqual(controlStatuses);
  });
});

// ─── resolveLayers（深度レイヤー導入時のマイグレーション） ──
describe('resolveLayers', () => {
  it('layers と activeLayer が揃っていればそのまま使う', () => {
    const persisted = serializeProject(STATE);
    const loaded = deserializeProject(persisted)!;
    const { layers, activeLayer } = resolveLayers(loaded);
    expect(activeLayer).toBe('L1');
    expect(layers.L1).toEqual(L1_DATA);
    expect(layers.L0).toEqual(EMPTY_LAYER);
  });

  it('旧形式（layers 無し + トップレベル nodes/edges/boundaries あり）は L1 へマイグレート', () => {
    const legacyRaw = {
      schemaVersion: PERSISTED_PROJECT_SCHEMA_VERSION,
      nodes: L1_DATA.nodes,
      edges: L1_DATA.edges,
      boundaries: L1_DATA.boundaries,
      activeFramework: 'STRIDE+AI',
      updatedAt: Date.now(),
    };
    const loaded = deserializeProject(legacyRaw);
    expect(loaded).not.toBeNull();
    const { layers, activeLayer } = resolveLayers(loaded!);
    expect(activeLayer).toBe('L1');
    expect(layers.L1.nodes).toEqual(L1_DATA.nodes);
    expect(layers.L1.edges).toEqual(L1_DATA.edges);
    expect(layers.L1.boundaries).toEqual(L1_DATA.boundaries);
    // L0/L2/L3 は空レイヤー
    (['L0', 'L2', 'L3'] as LayerKey[]).forEach((key) => {
      expect(layers[key]).toEqual(EMPTY_LAYER);
    });
  });

  it('layers も旧フィールドも欠ければ全レイヤー空で起動', () => {
    const minimalRaw = {
      schemaVersion: PERSISTED_PROJECT_SCHEMA_VERSION,
      activeFramework: 'STRIDE+AI',
      updatedAt: Date.now(),
    };
    const loaded = deserializeProject(minimalRaw);
    expect(loaded).not.toBeNull();
    const { layers, activeLayer } = resolveLayers(loaded!);
    expect(activeLayer).toBe('L1');
    (['L0', 'L1', 'L2', 'L3'] as LayerKey[]).forEach((key) => {
      expect(layers[key]).toEqual(EMPTY_LAYER);
    });
  });

  it('旧 framework 値 STRIDE+AI は STRIDE へマイグレートされる（[[plan]] §2.29）', () => {
    const legacyRaw = {
      schemaVersion: PERSISTED_PROJECT_SCHEMA_VERSION,
      activeFramework: 'STRIDE+AI',
      manualThreats: {
        L0: [],
        L1: [
          {
            id: 'mt-legacy',
            framework: 'STRIDE+AI',
            category: '旧脅威',
            severity: 'High',
            description: '旧バージョンで作成された手動脅威。',
          },
        ],
        L2: [],
        L3: [],
      },
      updatedAt: Date.now(),
    };
    const loaded = deserializeProject(legacyRaw);
    expect(loaded).not.toBeNull();
    expect(loaded!.activeFramework).toBe('STRIDE');
    expect(loaded!.manualThreats?.L1[0].framework).toBe('STRIDE');
  });

  it('旧 framework 値 MAESTRO は AgenticAI へマイグレートされる（[[plan]] §2.29）', () => {
    const legacyRaw = {
      schemaVersion: PERSISTED_PROJECT_SCHEMA_VERSION,
      activeFramework: 'MAESTRO',
      manualThreats: {
        L0: [],
        L1: [
          {
            id: 'mt-legacy-maestro',
            framework: 'MAESTRO',
            category: '旧エージェント脅威',
            severity: 'High',
            description: 'MAESTRO タグ時代に作成された手動脅威。',
          },
        ],
        L2: [],
        L3: [],
      },
      updatedAt: Date.now(),
    };
    const loaded = deserializeProject(legacyRaw);
    expect(loaded).not.toBeNull();
    expect(loaded!.activeFramework).toBe('AgenticAI');
    expect(loaded!.manualThreats?.L1[0].framework).toBe('AgenticAI');
  });

  // ─── agentAttributes round-trip（[[plan]] §2.22 1.6b） ──────────
  it('agentAttributes が round-trip で保持される', () => {
    const STATE_WITH_ATTRS: SerializableState = {
      layers: {
        L0: EMPTY_LAYER,
        L1: {
          nodes: [
            {
              id: 'a1',
              type: 'AGENT',
              x: 0,
              y: 0,
              agentAttributes: {
                agency: 'Bounded',
                blastRadius: 'Tenant',
                identityTier: 'Cryptographic',
              },
            },
          ],
          edges: [],
          boundaries: [],
        },
        L2: EMPTY_LAYER,
        L3: EMPTY_LAYER,
      },
      activeLayer: 'L1',
      activeFramework: 'AgenticAI',
    };
    const persisted = serializeProject(STATE_WITH_ATTRS);
    const restored = deserializeProject(persisted);
    expect(restored?.layers?.L1.nodes[0].agentAttributes).toEqual({
      agency: 'Bounded',
      blastRadius: 'Tenant',
      identityTier: 'Cryptographic',
    });
  });

  it('agentAttributes 一部のみ指定でも round-trip で保持される', () => {
    const STATE_PARTIAL: SerializableState = {
      layers: {
        L0: EMPTY_LAYER,
        L1: {
          nodes: [
            {
              id: 'a1',
              type: 'AGENT',
              x: 0,
              y: 0,
              agentAttributes: { blastRadius: 'Admin' },
            },
          ],
          edges: [],
          boundaries: [],
        },
        L2: EMPTY_LAYER,
        L3: EMPTY_LAYER,
      },
      activeLayer: 'L1',
      activeFramework: 'AgenticAI',
    };
    const restored = deserializeProject(serializeProject(STATE_PARTIAL));
    expect(restored?.layers?.L1.nodes[0].agentAttributes).toEqual({ blastRadius: 'Admin' });
  });
});

// ─── ElementalID 採番の永続化（[[plan]] §2.26 Step 3） ──────────
describe('seq / idCounters の永続化', () => {
  const STATE_WITH_SEQ: SerializableState = {
    layers: {
      L0: EMPTY_LAYER,
      L1: {
        nodes: [
          { id: 'n1', seq: 1, type: 'USER', x: 0, y: 0 },
          { id: 'n2', seq: 2, type: 'LLM', x: 10, y: 10 },
        ],
        edges: [{ id: 'e1', seq: 1, source: 'n1', target: 'n2', auth: 'None', network: 'VPC', encryption: 'TLS' }],
        boundaries: [],
      },
      L2: EMPTY_LAYER,
      L3: EMPTY_LAYER,
    },
    activeLayer: 'L1',
    activeFramework: 'AgenticAI',
    idCounters: {
      L0: { node: 0, edge: 0, boundary: 0 },
      L1: { node: 5, edge: 1, boundary: 0 },
      L2: { node: 0, edge: 0, boundary: 0 },
      L3: { node: 0, edge: 0, boundary: 0 },
    },
  };

  it('seq と idCounters が round-trip で保持される', () => {
    const restored = deserializeProject(serializeProject(STATE_WITH_SEQ));
    expect(restored?.layers?.L1.nodes.map((n) => n.seq)).toEqual([1, 2]);
    expect(restored?.layers?.L1.edges[0].seq).toBe(1);
    // L1 はノードを 1 つ削除済みの想定（counter=5 > 最大 seq 2）
    expect(restored?.idCounters?.L1).toEqual({ node: 5, edge: 1, boundary: 0 });
  });

  it('idCounters 省略時は serialize 出力に含めない（旧テスト互換）', () => {
    const out = serializeProject(STATE);
    expect(out.idCounters).toBeUndefined();
  });
});

// ─── resolveIdCounters（seq 補完 + カウンタ復元） ──────────
describe('resolveIdCounters', () => {
  const legacyLayers = {
    L0: EMPTY_LAYER,
    L1: {
      nodes: [
        { id: 'n1', type: 'USER', x: 0, y: 0 },
        { id: 'n2', type: 'LLM', x: 0, y: 0 },
        { id: 'n3', type: 'DB', x: 0, y: 0 },
      ],
      edges: [{ id: 'e1', source: 'n1', target: 'n2', auth: 'None', network: 'VPC', encryption: 'TLS' }],
      boundaries: [{ id: 'b1', type: 'RECT', x: 0, y: 0, width: 100, height: 100, trustLevel: 'Internal' }],
    } as LayerData,
    L2: EMPTY_LAYER,
    L3: EMPTY_LAYER,
  };

  it('seq 未設定の旧データは要素順で連番を補完しカウンタを揃える', () => {
    const { layers, idCounters } = resolveIdCounters(legacyLayers);
    expect(layers.L1.nodes.map((n) => n.seq)).toEqual([1, 2, 3]);
    expect(layers.L1.edges[0].seq).toBe(1);
    expect(layers.L1.boundaries[0].seq).toBe(1);
    expect(idCounters.L1).toEqual({ node: 3, edge: 1, boundary: 1 });
    expect(idCounters.L0).toEqual({ node: 0, edge: 0, boundary: 0 });
  });

  it('保存済みカウンタがあれば最大 seq を超える値を維持する（番号非再利用）', () => {
    const persisted = {
      L0: { node: 0, edge: 0, boundary: 0 },
      L1: { node: 9, edge: 4, boundary: 2 },
      L2: { node: 0, edge: 0, boundary: 0 },
      L3: { node: 0, edge: 0, boundary: 0 },
    };
    const withSeq = {
      ...legacyLayers,
      L1: {
        nodes: [{ id: 'n1', seq: 1, type: 'USER', x: 0, y: 0 }],
        edges: [],
        boundaries: [],
      } as LayerData,
    };
    const { idCounters } = resolveIdCounters(withSeq, persisted);
    expect(idCounters.L1.node).toBe(9);
  });

  it('全要素が seq 済みなら入力レイヤー参照をそのまま返す', () => {
    const allSeq = {
      ...legacyLayers,
      L1: {
        nodes: [{ id: 'n1', seq: 1, type: 'USER', x: 0, y: 0 }],
        edges: [],
        boundaries: [],
      } as LayerData,
    };
    const { layers } = resolveIdCounters(allSeq);
    expect(layers.L1).toBe(allSeq.L1);
  });
});
