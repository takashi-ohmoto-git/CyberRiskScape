/* eslint-disable @typescript-eslint/no-explicit-any -- 戻り値は Record<string, unknown> のため、テストでは any で辿る */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  analyzeThreats,
  diffModels,
  getModel,
  getThreat,
  listChangeTriggers,
  listComponentTypes,
  lookupThreatRules,
} from './tools';
import { resolveProject } from '../cli/analyze';
import { resolveNodeBoundaries } from '../core/canvas/boundaryCrossing';
import { BUNDLED_CHANGE_TRIGGERS } from '../change-triggers/loader/bundledChangeTriggers';

function fixture(name: string): Record<string, any> {
  return JSON.parse(
    readFileSync(new URL(`../cli/__fixtures__/${name}`, import.meta.url), 'utf-8'),
  ) as Record<string, any>;
}

const BASE = (): Record<string, any> => fixture('sample-project.json');
const CHANGED = (): Record<string, any> => fixture('sample-project-changed.json');

/** L1 に LLM と DB を内包する Internal 境界、さらに LLM だけを内包する小境界を足したモデル。 */
function withBoundaries(): Record<string, any> {
  const raw = BASE();
  raw.layers.L1.boundaries = [
    { id: 'b-outer', seq: 1, type: 'RECT', x: 200, y: -100, width: 600, height: 300, trustLevel: 'Internal' },
    { id: 'b-inner', seq: 2, type: 'RECT_DASHED', x: 210, y: -50, width: 200, height: 200, trustLevel: 'Partner' },
  ];
  raw.layers.L1.annotations = [{ id: 'a1', kind: 'callout', x: 5, y: 5, text: '注記', targetNodeId: 'n-db' }];
  return raw;
}

describe('getModel', () => {
  it('ノードのあるレイヤーだけを返し、座標を含まない', () => {
    const out = getModel(BASE());
    const layers = out.layers as Array<Record<string, any>>;
    expect(layers.map((l) => l.layer)).toEqual(['L1']);
    expect(layers[0].nodes).toHaveLength(3);
    expect(layers[0].nodes[0]).toMatchObject({ id: 'n-user', elementalId: 'C1', type: 'USER', label: '利用者' });
    const json = JSON.stringify(out);
    expect(json).not.toMatch(/"(x|y|width|height)"/);
  });

  it('エッジの属性を返す', () => {
    const l1 = (getModel(BASE(), { layer: 'L1' }).layers as Array<Record<string, any>>)[0];
    expect(l1.edges[0]).toMatchObject({
      id: 'e-user-llm',
      elementalId: 'DF1',
      source: 'n-user',
      target: 'n-llm',
      auth: 'Password',
      network: 'Internet',
      encryption: 'TLS',
    });
  });

  it('所属境界が resolveNodeBoundaries と一致する（最内側から）', () => {
    const raw = withBoundaries();
    const l1 = (getModel(raw, { layer: 'L1' }).layers as Array<Record<string, any>>)[0];
    const data = resolveProject(raw).layers.L1;
    const expected = resolveNodeBoundaries(data.nodes, data.boundaries);
    for (const n of l1.nodes) {
      expect(n.boundaryIds).toEqual((expected.get(n.id) ?? []).map((b) => b.id));
    }
    expect(l1.nodes.find((n: any) => n.id === 'n-llm').boundaryIds).toEqual(['b-inner', 'b-outer']);
    expect(l1.nodes.find((n: any) => n.id === 'n-user').boundaryIds).toEqual([]);
    expect(l1.boundaries[0]).toMatchObject({ id: 'b-outer', type: 'RECT', trustLevel: 'Internal' });
    expect(l1.annotations).toEqual([{ id: 'a1', kind: 'callout', text: '注記', targetNodeId: 'n-db' }]);
  });

  it('長すぎる説明を切り詰める', () => {
    const raw = BASE();
    raw.layers.L1.nodes[0].description = 'a'.repeat(5000);
    const l1 = (getModel(raw).layers as Array<Record<string, any>>)[0];
    expect(l1.nodes[0].description.length).toBeLessThanOrEqual(2001);
  });

  it('不正な layer / 入力は Error', () => {
    expect(() => getModel(BASE(), { layer: 'L9' as never })).toThrow(/layer/);
    expect(() => getModel({ foo: 1 })).toThrow(/プロジェクト JSON/);
  });
});

describe('analyzeThreats', () => {
  it('要約一覧を重大度の降順で返す', () => {
    const out = analyzeThreats(BASE(), { locale: 'ja' }) as any;
    expect(out.total).toBeGreaterThan(0);
    expect(out.returned).toBe(out.threats.length);
    const t = out.threats[0];
    expect(t).toMatchObject({ layer: 'L1' });
    expect(t.id).toMatch(/^L1:/);
    expect(t.element).toHaveProperty('kind');
    expect(t).toHaveProperty('effectiveSeverity');
    expect(t).toHaveProperty('ruleSeverity');
    const rank = { Low: 0, Medium: 1, High: 2, Critical: 3 } as Record<string, number>;
    const ranks = out.threats.map((x: any) => rank[x.effectiveSeverity]);
    expect([...ranks].sort((a, b) => b - a)).toEqual(ranks);
    for (const x of out.threats) {
      expect((x.mitigationDigest ?? '').length).toBeLessThanOrEqual(201);
    }
  });

  it('minSeverity / framework / elementId でフィルタできる', () => {
    const all = analyzeThreats(BASE(), { locale: 'ja' }) as any;
    const high = analyzeThreats(BASE(), { locale: 'ja', minSeverity: 'High' }) as any;
    expect(high.total).toBeLessThanOrEqual(all.total);
    expect(high.threats.every((t: any) => ['High', 'Critical'].includes(t.effectiveSeverity))).toBe(true);

    const stride = analyzeThreats(BASE(), { locale: 'ja', framework: 'STRIDE' }) as any;
    expect(stride.threats.every((t: any) => t.framework === 'STRIDE')).toBe(true);

    const byId = analyzeThreats(BASE(), { locale: 'ja', elementId: 'n-llm' }) as any;
    const byElemental = analyzeThreats(BASE(), { locale: 'ja', elementId: 'C2' }) as any;
    expect(byId.total).toBeGreaterThan(0);
    expect(byId.total).toBe(byElemental.total);
    expect(byId.threats.every((t: any) => t.element.id === 'n-llm')).toBe(true);
  });

  it('抑制された脅威は既定で除外し、includeSuppressed で含める', () => {
    const raw = BASE();
    const first = (analyzeThreats(raw, { locale: 'ja' }) as any).threats[0];
    raw.suppressions = { [first.id.replace(/^L1:/, '')]: { status: 'accepted', note: '受容', at: 1 } };
    const hidden = analyzeThreats(raw, { locale: 'ja' }) as any;
    const shown = analyzeThreats(raw, { locale: 'ja', includeSuppressed: true }) as any;
    expect(hidden.threats.find((t: any) => t.id === first.id)).toBeUndefined();
    expect(shown.threats.find((t: any) => t.id === first.id)?.suppression).toBe('accepted');
    expect(shown.total).toBe(hidden.total + 1);
  });

  it('上限を超える場合は truncated になる', () => {
    const raw = BASE();
    const nodes: unknown[] = [];
    for (let i = 0; i < 40; i++) {
      nodes.push({ id: `a${i}`, seq: i + 1, type: 'AGENT', x: i * 10, y: 0, label: `Agent${i}` });
    }
    raw.layers.L1.nodes = nodes;
    raw.layers.L1.edges = [];
    const out = analyzeThreats(raw, { locale: 'ja', includeSuppressed: true }) as any;
    expect(out.total).toBeGreaterThan(200);
    expect(out.returned).toBe(200);
    expect(out.truncated).toBe(true);
  });

  it('存在しない layer / elementId / 不正な値は Error', () => {
    expect(() => analyzeThreats(BASE(), { locale: 'ja', layer: 'X' as never })).toThrow(/layer/);
    expect(() => analyzeThreats(BASE(), { locale: 'ja', elementId: 'nope' })).toThrow(/elementId/);
    expect(() => analyzeThreats(BASE(), { locale: 'ja', framework: 'X' as never })).toThrow(/framework/);
    expect(() => analyzeThreats(BASE(), { locale: 'ja', minSeverity: 'X' as never })).toThrow(/minSeverity/);
    expect(() => analyzeThreats({}, { locale: 'ja' })).toThrow(/プロジェクト JSON/);
  });

  it('locale で本文が切り替わる', () => {
    const ja = analyzeThreats(BASE(), { locale: 'ja' }) as any;
    const en = analyzeThreats(BASE(), { locale: 'en' }) as any;
    expect(ja.total).toBe(en.total);
    expect(JSON.stringify(ja.threats)).not.toBe(JSON.stringify(en.threats));
  });
});

describe('getThreat', () => {
  it('1 件の詳細を返す', () => {
    const raw = BASE();
    const first = (analyzeThreats(raw, { locale: 'ja' }) as any).threats[0];
    const t = getThreat(raw, { threatId: first.id, locale: 'ja' }) as any;
    expect(t.id).toBe(first.id);
    expect(t.description).toBeTruthy();
    expect(t).toHaveProperty('mitigationTiers');
    expect(t).toHaveProperty('references');
    expect(t).toHaveProperty('complianceRefs');
    expect(t.assumptionFlags).toBeInstanceOf(Array);
    expect(t.suppression).toBeNull();
    expect(t.riskScore).toBeNull();
    expect(t.controlStatus).toBeNull();
  });

  it('suppression と note・riskScore を含める', () => {
    const raw = BASE();
    const first = (analyzeThreats(raw, { locale: 'ja' }) as any).threats[0];
    const bare = first.id.replace(/^L1:/, '');
    raw.suppressions = { [bare]: { status: 'reduce', note: '対応中', at: 1 } };
    raw.riskScores = { [bare]: { damage: 3, affectedUsers: 3, reproducibility: 3, exploitability: 3, at: 1 } };
    const t = getThreat(raw, { threatId: bare, locale: 'ja' }) as any;
    expect(t.suppression).toEqual({ status: 'reduce', note: '対応中' });
    expect(t.riskScore).toMatchObject({ damage: 3 });
    expect(t.effectiveSeverity).toBe('Critical');
  });

  it('見つからなければ Error', () => {
    expect(() => getThreat(BASE(), { threatId: 'L1:nope', locale: 'ja' })).toThrow(/threatId/);
  });
});

describe('diffModels', () => {
  it('diffToJsonObject と同じ形で差分を返す', () => {
    const out = diffModels(BASE(), CHANGED(), {
      triggers: BUNDLED_CHANGE_TRIGGERS.triggers,
      locale: 'ja',
    }) as any;
    expect(out.kind).toBeTruthy();
    expect(out.added.length).toBeGreaterThan(0);
    expect(() => JSON.stringify(out)).not.toThrow();
  });

  it('不正な入力は Error', () => {
    expect(() => diffModels({}, BASE(), { triggers: [], locale: 'ja' })).toThrow(/プロジェクト JSON/);
  });
});

describe('listComponentTypes', () => {
  it('型 id・ラベル・カテゴリ・canContain・属性を返す', () => {
    const out = listComponentTypes() as any;
    expect(out.total).toBe(out.types.length);
    const agent = out.types.find((t: any) => t.id === 'AGENT');
    expect(agent).toBeTruthy();
    expect(agent.attributes).toContain('agentAttributes.agency');
    const user = out.types.find((t: any) => t.id === 'USER');
    expect(user.attributes).toContain('userTrustAttribute');
    expect(user.attributes).not.toContain('agentAttributes.agency');
    expect(agent.categoryLabel).toBeTruthy();
    expect(agent.canContain).toBeInstanceOf(Array);
    const idp = out.types.find((t: any) => t.id === 'IDENTITY_PROVIDER');
    expect(idp.canBeAuthProvider).toBe(true);
    expect(idp.attributes).toContain('identityProviderKind');
  });
});

describe('lookupThreatRules', () => {
  it('nodeType でノードルールを絞る', () => {
    const out = lookupThreatRules({ nodeType: 'LLM', locale: 'ja' }) as any;
    expect(out.total).toBeGreaterThan(0);
    expect(out.rules.length).toBeLessThanOrEqual(50);
    for (const r of out.rules) {
      expect(r.appliesTo.kind).toBe('node');
      expect(r.appliesTo.nodeTypes).toContain('LLM');
    }
  });

  it('framework と query（大文字小文字無視）でフィルタできる', () => {
    const fw = lookupThreatRules({ framework: 'AgenticAI', locale: 'ja' }) as any;
    expect(fw.rules.every((r: any) => r.framework === 'AgenticAI')).toBe(true);
    const first = fw.rules[0];
    const q = lookupThreatRules({ query: first.id.toUpperCase(), locale: 'ja' }) as any;
    expect(q.rules.some((r: any) => r.id === first.id)).toBe(true);
    const none = lookupThreatRules({ query: 'zzzz-no-such-rule-zzzz', locale: 'ja' }) as any;
    expect(none).toMatchObject({ total: 0, returned: 0, truncated: false });
  });

  it('上限 50 件と総数を返す', () => {
    const out = lookupThreatRules({ locale: 'ja' }) as any;
    expect(out.total).toBeGreaterThan(50);
    expect(out.returned).toBe(50);
    expect(out.truncated).toBe(true);
  });
});

describe('listChangeTriggers', () => {
  it('triggersToJsonObject と同じ形を返す', () => {
    const out = listChangeTriggers({ triggers: BUNDLED_CHANGE_TRIGGERS.triggers, locale: 'ja' }) as any;
    expect(out.kind).toBe('cyberriskscape-change-triggers');
    expect(out.triggers.map((t: any) => t.id)).toContain('T1');
  });
});
