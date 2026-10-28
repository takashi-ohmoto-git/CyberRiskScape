import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseTemplateFromJson, serializeTemplateToJson } from './io';
import type { LayerData } from '../../core/model/types';

const LAYER: LayerData = {
  nodes: [
    { id: 'n1', seq: 1, type: 'USER', x: 50, y: 250 },
    { id: 'n2', seq: 2, type: 'GATEWAY', x: 250, y: 250 },
  ],
  edges: [
    {
      id: 'e1',
      seq: 1,
      source: 'n1',
      target: 'n2',
      auth: 'None',
      network: 'Internet',
      encryption: 'Plain',
      dataFlow: 'outbound',
    },
  ],
  boundaries: [
    { id: 'b1', seq: 1, type: 'ROUNDED_DASHED', x: 0, y: 0, width: 600, height: 250, trustLevel: 'Internal' },
  ],
  annotations: [],
};

describe('serializeTemplateToJson', () => {
  it('可搬形式（schemaVersion/kind/name/layer）で出力し、各要素の seq は除去する', () => {
    const json = JSON.parse(serializeTemplateToJson('My Template', LAYER));
    expect(json.schemaVersion).toBe(1);
    expect(json.kind).toBe('cyberriskscape-template');
    expect(json.name).toBe('My Template');
    expect(json.layer.nodes).toHaveLength(2);
    for (const n of json.layer.nodes) expect(n.seq).toBeUndefined();
    for (const e of json.layer.edges) expect(e.seq).toBeUndefined();
    for (const b of json.layer.boundaries) expect(b.seq).toBeUndefined();
    // ノード参照（id / source / target）は保持する。
    expect(json.layer.edges[0].source).toBe('n1');
    expect(json.layer.edges[0].target).toBe('n2');
  });
});

describe('parseTemplateFromJson', () => {
  it('round-trip：export した JSON を取り込めて name/layer が一致する', () => {
    const result = parseTemplateFromJson(serializeTemplateToJson('My Template', LAYER));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.name).toBe('My Template');
    expect(result.layer.nodes).toHaveLength(2);
    expect(result.layer.edges).toHaveLength(1);
    expect(result.layer.boundaries).toHaveLength(1);
  });

  it('kind マーカーが無くても受理する（手書き JSON 許容）', () => {
    const result = parseTemplateFromJson(
      JSON.stringify({ schemaVersion: 1, name: 'No Kind', layer: { nodes: [], edges: [], boundaries: [] } }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.name).toBe('No Kind');
  });

  it('JSON 構文エラーはエラーを返す（throw しない）', () => {
    const result = parseTemplateFromJson('{ not json');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain('JSON 構文エラー');
  });

  it('スキーマ違反（name 欠落）は検証エラーを返す', () => {
    const result = parseTemplateFromJson(
      JSON.stringify({ schemaVersion: 1, layer: { nodes: [], edges: [], boundaries: [] } }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain('検証エラー');
  });
});

describe('parseTemplateFromJson（CLI 出力のプロジェクト JSON）', () => {
  const project = (over: Record<string, unknown>) => {
    const base = JSON.parse(
      readFileSync('src/cli/__fixtures__/sample-project.json', 'utf-8'),
    );
    return JSON.stringify({ ...base, ...over });
  };

  it('プロジェクト JSON から activeLayer を取り出し、seq を落とし、projectMeta.name を使う', () => {
    const r = parseTemplateFromJson(project({}), 'file');
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.name).toBe('CLIスモークテスト用サンプル');
    expect(r.layer.nodes.length).toBeGreaterThan(0);
    for (const n of r.layer.nodes) expect(n.seq).toBeUndefined();
  });

  it('activeLayer が空なら要素のある最初のレイヤーを使う', () => {
    const base = JSON.parse(project({}));
    const empty = { nodes: [], edges: [], boundaries: [] };
    const layers = { L0: empty, L1: empty, L2: base.layers.L1, L3: empty };
    const r = parseTemplateFromJson(project({ layers, activeLayer: 'L1' }), 'file');
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.layer.nodes).toHaveLength(base.layers.L1.nodes.length);
  });

  it('projectMeta が無ければファイル名を使う', () => {
    const r = parseTemplateFromJson(project({ projectMeta: undefined }), 'my-file');
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.name).toBe('my-file');
  });

  it('全レイヤーが空ならエラー', () => {
    const empty = { nodes: [], edges: [], boundaries: [] };
    const r = parseTemplateFromJson(project({ layers: { L0: empty, L1: empty, L2: empty, L3: empty } }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('要素がありません');
  });

  it('どちらにも合わない JSON は従来の検証エラー', () => {
    const r = parseTemplateFromJson('{"foo":1}');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('検証エラー');
  });
});
