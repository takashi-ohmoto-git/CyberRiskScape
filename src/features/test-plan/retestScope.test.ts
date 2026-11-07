import { describe, expect, it } from 'vitest';
import { computeRetestScope } from './retestScope';
import { buildTestPlan } from './buildTestPlan';
import { testPlanToMarkdown } from './testPlanOutput';
import { analyzeResolvedProject, resolveProject } from '../../cli/analyze';
import { serializeProject } from '../persistence/serialize';
import { detectTriggers } from '../../change-triggers/detectTriggers';
import { getChangeTriggers } from '../../change-triggers/loader/bundledChangeTriggers';
import {
  EMPTY_LAYER,
  type AuthType,
  type DiagramEdge,
  type DiagramNode,
  type LayerData,
  type LayerKey,
} from '../../core/model/types';

const NOW = new Date('2026-11-07T12:00:00Z');
const triggers = getChangeTriggers('ja').triggers;

const node = (id: string, seq: number, type: string, extra: Partial<DiagramNode> = {}): DiagramNode =>
  ({ id, seq, type, x: seq * 100, y: 0, label: id, ...extra }) as DiagramNode;
const edge = (id: string, seq: number, source: string, target: string, auth: AuthType): DiagramEdge => ({
  id,
  seq,
  source,
  target,
  auth,
  network: 'Internet',
  encryption: 'Plain',
});

/** 攻撃者 a → LLM w → DB d（標的）と、無関係な x → y を持つ架空のモデル。 */
function layers(opts: { auth: AuthType; addNode?: boolean }): Record<LayerKey, LayerData> {
  const nodes = [
    node('a', 1, 'THREAT_ACTOR', { attackObjectiveId: 'd' }),
    node('w', 2, 'LLM'),
    node('d', 3, 'DB'),
    node('x', 4, 'LLM'),
    node('y', 5, 'DB'),
    ...(opts.addNode ? [node('z', 6, 'DB')] : []),
  ];
  const edges = [
    edge('e1', 1, 'a', 'w', 'None'),
    edge('e2', 2, 'w', 'd', opts.auth),
    edge('e3', 3, 'x', 'y', 'None'),
  ];
  return {
    L0: EMPTY_LAYER,
    L1: { nodes, edges, boundaries: [], annotations: [] },
    L2: EMPTY_LAYER,
    L3: EMPTY_LAYER,
    PQC: EMPTY_LAYER,
  };
}

const resolved = (l: Record<LayerKey, LayerData>) =>
  resolveProject(serializeProject({ layers: l, activeLayer: 'L1', activeFramework: 'ALL' }));

function plan(oldL: Record<LayerKey, LayerData>, newL: Record<LayerKey, LayerData>, scoped: boolean) {
  const base = resolved(oldL);
  const head = resolved(newL);
  const input = analyzeResolvedProject(head, { layer: 'L1' })[0].input;
  const hits = detectTriggers(base.layers, head.layers, triggers);
  const scope = computeRetestScope('L1', base.layers.L1, head.layers.L1, hits);
  return { scope, plan: buildTestPlan(input, NOW, 'ja', scoped ? scope : undefined) };
}

describe('computeRetestScope', () => {
  it('エッジの認証変更 → 両端ノードが範囲に入り、無関係なノードは入らない', () => {
    const { scope } = plan(layers({ auth: 'None' }), layers({ auth: 'Password' }), true);
    expect(scope.hits.map((h) => h.triggerId)).toContain('T3');
    expect([...scope.nodeIds].sort()).toEqual(['d', 'w']);
    expect(scope.edgeIds.has('e2')).toBe(true);
  });

  it('追加されたノードはトリガーが無くても範囲に入る', () => {
    const { scope } = plan(layers({ auth: 'None' }), layers({ auth: 'None', addNode: true }), true);
    expect([...scope.nodeIds]).toContain('z');
  });

  it('変更が無ければ範囲は空', () => {
    const { scope } = plan(layers({ auth: 'None' }), layers({ auth: 'None' }), true);
    expect(scope.hits).toEqual([]);
    expect(scope.nodeIds.size).toBe(0);
  });
});

describe('buildTestPlan (retest)', () => {
  const oldL = layers({ auth: 'None' });
  const newL = layers({ auth: 'Password' });

  it('範囲未指定なら従来どおり全件（retest も付かない）', () => {
    const p = plan(oldL, newL, false).plan;
    expect(p.retest).toBeUndefined();
    expect(p.focusGroups.some((g) => g.target.label === 'x')).toBe(true);
  });

  it('範囲指定時は範囲外のノード・入口・シナリオを除く', () => {
    const all = plan(oldL, newL, false).plan;
    const p = plan(oldL, newL, true).plan;
    expect(p.focusGroups.length).toBeLessThan(all.focusGroups.length);
    // 範囲内のノード（C2 = w, C3 = d）か、その間のエッジだけ
    for (const g of p.focusGroups) expect(['C2', 'C3', 'DF2']).toContain(g.target.id);
    expect(p.focusGroups.some((g) => g.target.label === 'x' || g.target.label === 'y')).toBe(false);
    expect(p.entryPoints.map((e) => e.node.label)).not.toContain('y');
    // 攻撃者 → 標的の経路は w, d を通るので残る
    expect(p.scenarios.length).toBe(1);
    expect(p.retest?.nodes.map((n) => n.label).sort()).toEqual(['d', 'w']);
  });

  it('Markdown の先頭付近に再診断の範囲が出る。変更なしは空の範囲を明記する', () => {
    const md = testPlanToMarkdown(plan(oldL, newL, true).plan);
    expect(md).toContain('## 再診断の範囲（前回のモデルからの変更）');
    expect(md).toContain('T3');
    expect(md.indexOf('再診断の範囲')).toBeLessThan(md.indexOf('## 1. 概要と前提'));

    const empty = plan(oldL, oldL, true).plan;
    expect(empty.focusGroups).toEqual([]);
    expect(empty.entryPoints).toEqual([]);
    expect(testPlanToMarkdown(empty)).toContain('範囲は空です');
  });
});
