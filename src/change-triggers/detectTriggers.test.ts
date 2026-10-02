import { describe, expect, it } from 'vitest';
import { detectTriggers, manualCheckTriggers } from './detectTriggers';
import { EMPTY_LAYER, type LayerData, type LayerKey } from '../core/model/types';
import type { ChangeTrigger } from './schema/trigger';

function layers(l1: LayerData): Record<LayerKey, LayerData> {
  return { L0: EMPTY_LAYER, L1: l1, L2: EMPTY_LAYER, L3: EMPTY_LAYER };
}

function trigger(id: string, detect: ChangeTrigger['detect']): ChangeTrigger {
  return { id, title: `title-${id}`, checkpoint: `checkpoint-${id}`, detect };
}

describe('detectTriggers', () => {
  it('node-added: nodeTypes フィルタに一致するノード追加のみ検出する', () => {
    const base = layers({ nodes: [], edges: [], boundaries: [], annotations: [] });
    const head = layers({
      nodes: [
        { id: 'n1', type: 'AGENT', x: 0, y: 0 },
        { id: 'n2', type: 'LLM', x: 0, y: 0 },
      ],
      edges: [],
      boundaries: [],
      annotations: [],
    });
    const hits = detectTriggers(base, head, [trigger('T7', [{ kind: 'node-added', nodeTypes: ['AGENT'] }])]);
    expect(hits).toHaveLength(1);
    expect(hits[0].evidence).toHaveLength(1);
    expect(hits[0].evidence[0].element).toEqual({ kind: 'node', id: 'n1', label: 'n1 AGENT' });
  });

  it('node-added: categories フィルタ（ComponentRegistry 経由でカテゴリ解決）', () => {
    const base = layers({ nodes: [], edges: [], boundaries: [], annotations: [] });
    const head = layers({
      nodes: [{ id: 'n1', type: 'PERSONAL_INFO', x: 0, y: 0 }],
      edges: [],
      boundaries: [],
      annotations: [],
    });
    const hits = detectTriggers(base, head, [
      trigger('T5', [{ kind: 'node-added', categories: ['DOCUMENTS'] }]),
    ]);
    expect(hits).toHaveLength(1);
  });

  it('node-added: フィルタ無し指定はどのノード型でも検出する', () => {
    const base = layers({ nodes: [], edges: [], boundaries: [], annotations: [] });
    const head = layers({
      nodes: [{ id: 'n1', type: 'USER', x: 0, y: 0 }],
      edges: [],
      boundaries: [],
      annotations: [],
    });
    const hits = detectTriggers(base, head, [trigger('Tx', [{ kind: 'node-added' }])]);
    expect(hits).toHaveLength(1);
  });

  it('node-changed: 同一 id で指定フィールドが変化したときのみ検出する', () => {
    const base = layers({
      nodes: [{ id: 'n1', type: 'FRONT_END_SERVER', x: 0, y: 0, attackSurface: { hasGlobalIp: false } }],
      edges: [],
      boundaries: [],
      annotations: [],
    });
    const head = layers({
      nodes: [{ id: 'n1', type: 'FRONT_END_SERVER', x: 0, y: 0, attackSurface: { hasGlobalIp: true } }],
      edges: [],
      boundaries: [],
      annotations: [],
    });
    const hits = detectTriggers(base, head, [
      trigger('T2', [{ kind: 'node-changed', fields: ['attackSurface'] }]),
    ]);
    expect(hits).toHaveLength(1);
    expect(hits[0].evidence[0].detail).toBe('attackSurface');
  });

  it('node-changed: 指定フィールドが変化しなければ検出しない', () => {
    const node = { id: 'n1', type: 'LLM', x: 0, y: 0, label: 'A' };
    const base = layers({ nodes: [node], edges: [], boundaries: [], annotations: [] });
    const head = layers({ nodes: [{ ...node, x: 100 }], edges: [], boundaries: [], annotations: [] });
    const hits = detectTriggers(base, head, [
      trigger('T8', [{ kind: 'node-changed', fields: ['label'] }]),
    ]);
    expect(hits).toEqual([]);
  });

  it('edge-added: semantic フィルタ（未指定エッジは data_flow として評価）', () => {
    const base = layers({ nodes: [], edges: [], boundaries: [], annotations: [] });
    const head = layers({
      nodes: [],
      edges: [
        { id: 'e1', source: 'a', target: 'b', auth: 'None', network: 'VPC', encryption: 'TLS' },
        {
          id: 'e2',
          source: 'a',
          target: 'b',
          auth: 'None',
          network: 'VPC',
          encryption: 'TLS',
          semantic: 'tool_invocation',
        },
      ],
      boundaries: [],
      annotations: [],
    });
    const hits = detectTriggers(base, head, [
      trigger('T7', [{ kind: 'edge-added', semantic: ['tool_invocation'] }]),
    ]);
    expect(hits).toHaveLength(1);
    expect(hits[0].evidence.map((e) => e.element.id)).toEqual(['e2']);
  });

  it('edge-added: crossesTrust は両端の解決済み信頼レベルが異なるときのみ検出する', () => {
    const base = layers({ nodes: [], edges: [], boundaries: [], annotations: [] });
    const boundary = {
      id: 'b1',
      type: 'RECT' as const,
      x: 0,
      y: 0,
      width: 100,
      height: 100,
      trustLevel: 'Internal' as const,
    };
    const head = layers({
      nodes: [
        { id: 'inside', type: 'USER', x: 10, y: 10 }, // 境界内 → Internal
        { id: 'outside', type: 'USER', x: 500, y: 500 }, // 境界外 → Internet
      ],
      edges: [{ id: 'e1', source: 'inside', target: 'outside', auth: 'None', network: 'Internet', encryption: 'TLS' }],
      boundaries: [boundary],
      annotations: [],
    });
    const hits = detectTriggers(base, head, [trigger('T1', [{ kind: 'edge-added', crossesTrust: true }])]);
    expect(hits).toHaveLength(1);
  });

  it('edge-added: crossesTrust は両端が同じ信頼レベルなら検出しない', () => {
    const base = layers({ nodes: [], edges: [], boundaries: [], annotations: [] });
    const head = layers({
      nodes: [
        { id: 'a', type: 'USER', x: 0, y: 0 },
        { id: 'b', type: 'USER', x: 1, y: 1 },
      ],
      edges: [{ id: 'e1', source: 'a', target: 'b', auth: 'None', network: 'Internet', encryption: 'TLS' }],
      boundaries: [],
      annotations: [],
    });
    const hits = detectTriggers(base, head, [trigger('T1', [{ kind: 'edge-added', crossesTrust: true }])]);
    expect(hits).toEqual([]);
  });

  it('edge-added: peerTrust はどちらかの端が一致すれば検出する（境界なし＝Internet）', () => {
    const base = layers({ nodes: [], edges: [], boundaries: [], annotations: [] });
    const head = layers({
      nodes: [
        { id: 'a', type: 'USER', x: 0, y: 0 },
        { id: 'b', type: 'EXTERNAL_ENTITY', x: 1, y: 1 },
      ],
      edges: [{ id: 'e1', source: 'a', target: 'b', auth: 'None', network: 'Internet', encryption: 'TLS' }],
      boundaries: [],
      annotations: [],
    });
    const hits = detectTriggers(base, head, [
      trigger('T2', [{ kind: 'edge-added', peerTrust: ['Internet'] }]),
    ]);
    expect(hits).toHaveLength(1);
  });

  it('edge-added: 既存エッジ（base に同一 id）は追加として数えない', () => {
    const edge = { id: 'e1', source: 'a', target: 'b', auth: 'None' as const, network: 'Internet' as const, encryption: 'TLS' as const };
    const base = layers({ nodes: [], edges: [edge], boundaries: [], annotations: [] });
    const head = layers({ nodes: [], edges: [edge], boundaries: [], annotations: [] });
    const hits = detectTriggers(base, head, [trigger('T2', [{ kind: 'edge-added', peerTrust: ['Internet'] }])]);
    expect(hits).toEqual([]);
  });

  it('edge-changed: 指定フィールドが変化したときのみ検出する', () => {
    const base = layers({
      nodes: [],
      edges: [{ id: 'e1', source: 'a', target: 'b', auth: 'Password', network: 'Internet', encryption: 'TLS' }],
      boundaries: [],
      annotations: [],
    });
    const head = layers({
      nodes: [],
      edges: [{ id: 'e1', source: 'a', target: 'b', auth: 'MFA', network: 'Internet', encryption: 'TLS' }],
      boundaries: [],
      annotations: [],
    });
    const hits = detectTriggers(base, head, [
      trigger('T3', [{ kind: 'edge-changed', fields: ['auth', 'authProviderId'] }]),
    ]);
    expect(hits).toHaveLength(1);
    expect(hits[0].evidence[0].detail).toBe('auth');
  });

  it('boundary-added / boundary-changed を検出する', () => {
    const b1 = { id: 'b1', type: 'RECT' as const, x: 0, y: 0, width: 10, height: 10, trustLevel: 'Internal' as const };
    const base = layers({ nodes: [], edges: [], boundaries: [], annotations: [] });
    const head = layers({ nodes: [], edges: [], boundaries: [b1], annotations: [] });
    const added = detectTriggers(base, head, [trigger('T1', [{ kind: 'boundary-added' }])]);
    expect(added).toHaveLength(1);

    const headChanged = layers({ nodes: [], edges: [], boundaries: [{ ...b1, trustLevel: 'Partner' }], annotations: [] });
    const baseWithB1 = layers({ nodes: [], edges: [], boundaries: [b1], annotations: [] });
    const changed = detectTriggers(baseWithB1, headChanged, [
      trigger('T1', [{ kind: 'boundary-changed', fields: ['trustLevel'] }]),
    ]);
    expect(changed).toHaveLength(1);
    expect(changed[0].evidence[0].detail).toBe('trustLevel');
  });

  it('node-trust-changed: 既存ノードが境界の外へ出ると信頼レベルの変化を検出する', () => {
    const boundary = {
      id: 'b1',
      type: 'RECT' as const,
      x: 0,
      y: 0,
      width: 400,
      height: 400,
      trustLevel: 'Internal' as const,
    };
    const base = layers({
      nodes: [{ id: 'n1', type: 'DB', x: 10, y: 10 }],
      edges: [],
      boundaries: [boundary],
      annotations: [],
    });
    const moved = layers({
      nodes: [{ id: 'n1', type: 'DB', x: 1000, y: 1000 }],
      edges: [],
      boundaries: [boundary],
      annotations: [],
    });
    const t = [trigger('T1', [{ kind: 'node-trust-changed' }])];
    const hits = detectTriggers(base, moved, t);
    expect(hits).toHaveLength(1);
    expect(hits[0].evidence[0].detail).toBe('Internal → Internet');
    // 境界内での移動（信頼レベル不変）は拾わない
    const nudged = layers({
      nodes: [{ id: 'n1', type: 'DB', x: 50, y: 50 }],
      edges: [],
      boundaries: [boundary],
      annotations: [],
    });
    expect(detectTriggers(base, nudged, t)).toHaveLength(0);
  });

  it('根拠が 0 件のトリガーは結果に含めない', () => {
    const base = layers({ nodes: [], edges: [], boundaries: [], annotations: [] });
    const head = layers({ nodes: [], edges: [], boundaries: [], annotations: [] });
    const hits = detectTriggers(base, head, [trigger('T1', [{ kind: 'boundary-added' }])]);
    expect(hits).toEqual([]);
  });

  it('複数レイヤーにまたがる変更を 1 つのトリガーに集約する', () => {
    const base = {
      L0: EMPTY_LAYER,
      L1: EMPTY_LAYER,
      L2: EMPTY_LAYER,
      L3: EMPTY_LAYER,
    };
    const head = {
      L0: { nodes: [{ id: 'n1', type: 'AGENT', x: 0, y: 0 }], edges: [], boundaries: [], annotations: [] },
      L1: { nodes: [{ id: 'n2', type: 'TOOL', x: 0, y: 0 }], edges: [], boundaries: [], annotations: [] },
      L2: EMPTY_LAYER,
      L3: EMPTY_LAYER,
    };
    const hits = detectTriggers(base, head, [
      trigger('T7', [{ kind: 'node-added', nodeTypes: ['AGENT', 'TOOL'] }]),
    ]);
    expect(hits).toHaveLength(1);
    expect(hits[0].evidence).toHaveLength(2);
    expect(hits[0].evidence.map((e) => e.layer).sort()).toEqual(['L0', 'L1']);
  });
});

describe('manualCheckTriggers', () => {
  it('detect: [] のトリガーのみを返す', () => {
    const t4 = trigger('T4', []);
    const t1 = trigger('T1', [{ kind: 'boundary-added' }]);
    expect(manualCheckTriggers([t1, t4])).toEqual([t4]);
  });
});
