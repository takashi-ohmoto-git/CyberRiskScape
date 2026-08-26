import { describe, expect, it } from 'vitest';
import { buildAttackGraph } from './buildAttackGraph';
import { analyzeAttackGraph } from './analyzeAttackGraph';
import { NEUTRAL_EVIDENCE, edgeElementKey, nodeElementKey, type HopEvidence, type HopEvidenceProvider } from './hopEvidence';
import type { DiagramEdge, DiagramNode } from '../../core/model/types';

function node(id: string, type = 'PROCESS'): DiagramNode {
  return { id, type, x: 0, y: 0 };
}

function edge(id: string, source: string, target: string): DiagramEdge {
  return { id, source, target, auth: 'None', network: 'Internet', encryption: 'Plain' };
}

/** 要素キー→HopEvidence のテーブルからプロバイダを作る。未登録は中立既定。 */
function provider(table: Record<string, Partial<HopEvidence>>): HopEvidenceProvider {
  return (key: string): HopEvidence => {
    const override = table[key];
    return override ? { ...NEUTRAL_EVIDENCE, ...override } : NEUTRAL_EVIDENCE;
  };
}

describe('analyzeAttackGraph', () => {
  it('コスト同点時は evidenceScore が高い経路を先に並べる', () => {
    // atk → mid → t と atk → t の2経路。両方中立コストでも mid に High 脅威がある経路を優先。
    // ただしコストが異なる（3 ノード vs 2 ノード）ため、同コストに揃えるため
    // atk-a-t / atk-b-t の対称経路を使う。
    const nodes = [node('atk'), node('a'), node('b'), node('t')];
    const edges = [
      edge('e-atk-a', 'atk', 'a'),
      edge('e-a-t', 'a', 't'),
      edge('e-atk-b', 'atk', 'b'),
      edge('e-b-t', 'b', 't'),
    ];
    const graph = buildAttackGraph(nodes, edges, 'atk', 't');
    const result = analyzeAttackGraph(
      graph,
      provider({
        [nodeElementKey('a')]: {
          difficulty: 2,
          threats: [{ threatId: 'high', name: 'H', severity: 'Critical' }],
        },
        [nodeElementKey('b')]: {
          difficulty: 2,
          threats: [{ threatId: 'low', name: 'L', severity: 'Low' }],
        },
      }),
    );
    expect(result.routes).toHaveLength(2);
    expect(result.routes[0].cost).toBe(result.routes[1].cost);
    expect(result.routes[0].route.nodeIds).toContain('a');
    expect(result.routes[0].evidenceScore).toBeGreaterThan(result.routes[1].evidenceScore);
  });

  it('コスト算出: 単一チャネル一本鎖（重みなし）は中立既定の合計になる', () => {
    // 全要素が中立既定（difficulty 2, coverage none）。
    // step0(atk)=2 / step1(a)=diff(a)2+diff(e1)2=4 / step2(t)=diff(t)2+diff(e2)2=4 → 計 10。
    const nodes = [node('atk'), node('a'), node('t')];
    const edges = [edge('e1', 'atk', 'a'), edge('e2', 'a', 't')];

    const graph = buildAttackGraph(nodes, edges, 'atk', 't');
    const graphResult = analyzeAttackGraph(graph, () => NEUTRAL_EVIDENCE);

    expect(graphResult.minCost).toBe(10);
  });

  it('コスト算出: 単一チャネル一本鎖（重みあり）は coverage ペナルティ込みの合計になる', () => {
    // step0(atk)=2 / step1(a)=diff(a)1+diff(e1)2+partial(+1)=4 /
    // step2(b)=diff(b)0+diff(e2)3+full(+8)=11 / step3(t)=diff(t)2+diff(e3)2=4 → 計 21。
    const nodes = [node('atk'), node('a'), node('b'), node('t')];
    const edges = [edge('e1', 'atk', 'a'), edge('e2', 'a', 'b'), edge('e3', 'b', 't')];

    const evidenceTable: Record<string, Partial<HopEvidence>> = {
      [nodeElementKey('a')]: { difficulty: 1, coverage: 'partial' },
      [edgeElementKey('e2')]: { difficulty: 3, coverage: 'none' },
      [nodeElementKey('b')]: { difficulty: 0, coverage: 'full' },
    };

    const graph = buildAttackGraph(nodes, edges, 'atk', 't');
    const graphResult = analyzeAttackGraph(graph, provider(evidenceTable));

    expect(graphResult.minCost).toBe(21);
  });

  it('チャネル選択: difficulty が安い方の並行エッジが採用される', () => {
    const nodes = [node('atk'), node('a'), node('t')];
    const edges = [edge('cheap', 'a', 't'), edge('expensive', 'a', 't'), edge('e0', 'atk', 'a')];

    const graph = buildAttackGraph(nodes, edges, 'atk', 't');
    const result = analyzeAttackGraph(
      graph,
      provider({
        [edgeElementKey('cheap')]: { difficulty: 1, coverage: 'none' },
        [edgeElementKey('expensive')]: { difficulty: 5, coverage: 'none' },
      }),
    );

    const hopKey = graph.hops.get('a--t')?.key ?? '';
    expect(result.routes[0].chosenChannels.get(hopKey)).toBe('cheap');
  });

  it('チャネル選択はペナルティ込みステップコストで判定される（安い難易度でも full 被覆なら不利）', () => {
    const nodes = [node('atk'), node('a'), node('t')];
    const edges = [edge('a-covered', 'a', 't'), edge('b-open', 'a', 't'), edge('e0', 'atk', 'a')];

    const graph = buildAttackGraph(nodes, edges, 'atk', 't');
    const table: Record<string, Partial<HopEvidence>> = {
      [edgeElementKey('a-covered')]: { difficulty: 1, coverage: 'full' },
      [edgeElementKey('b-open')]: { difficulty: 3, coverage: 'none' },
    };
    const hopKey = graph.hops.get('a--t')?.key ?? '';

    // 既定モード: a-covered = t(2) + 1 + 8(full) = 11、b-open = t(2) + 3 + 0 = 5 → b-open 採用
    const normal = analyzeAttackGraph(graph, provider(table));
    expect(normal.routes[0].chosenChannels.get(hopKey)).toBe('b-open');

    // 残存経路モード: a-covered は Infinity → b-open のみ選択可能
    const residual = analyzeAttackGraph(graph, provider(table), true);
    expect(residual.routes[0].chosenChannels.get(hopKey)).toBe('b-open');
    expect(residual.feasible).toBe(true);
  });

  it('残存経路モード: 唯一のホップの全チャネルが full なら遮断、片方のみ full なら通行可', () => {
    const nodes = [node('atk'), node('t')];
    const edges = [edge('e1', 'atk', 't'), edge('e2', 'atk', 't')];
    const graph = buildAttackGraph(nodes, edges, 'atk', 't');

    // 両方 full → 遮断
    const bothFull = analyzeAttackGraph(
      graph,
      provider({
        [edgeElementKey('e1')]: { coverage: 'full' },
        [edgeElementKey('e2')]: { coverage: 'full' },
      }),
      true,
    );
    expect(bothFull.feasible).toBe(false);
    expect(bothFull.routes[0].cost).toBe(Infinity);

    // 片方のみ full → 他方で通行可
    const oneFull = analyzeAttackGraph(
      graph,
      provider({
        [edgeElementKey('e1')]: { coverage: 'full' },
        [edgeElementKey('e2')]: { coverage: 'none' },
      }),
      true,
    );
    expect(oneFull.feasible).toBe(true);
  });

  it('routes がコスト昇順にソートされる', () => {
    const nodes = [node('atk'), node('a'), node('b'), node('t')];
    const edges = [
      edge('e1', 'atk', 'a'),
      edge('e2', 'a', 't'),
      edge('e3', 'atk', 'b'),
      edge('e4', 'b', 't'),
    ];
    const graph = buildAttackGraph(nodes, edges, 'atk', 't');

    const result = analyzeAttackGraph(
      graph,
      provider({
        [nodeElementKey('a')]: { difficulty: 3 },
        [nodeElementKey('b')]: { difficulty: 0 },
      }),
    );

    expect(result.routes).toHaveLength(2);
    expect(result.routes[0].cost).toBeLessThanOrEqual(result.routes[1].cost);
    expect(result.routes[0].route.nodeIds).toEqual(['atk', 'b', 't']);
    expect(result.minCost).toBe(result.routes[0].cost);
  });

  it('chokePoints: 共有中間ノードが routeHits 最大で先頭、攻撃者/標的は含まれず、ホップも対象になる', () => {
    // atk → shared → a → t / atk → shared → b → t
    const nodes = [node('atk'), node('shared'), node('a'), node('b'), node('t')];
    const edges = [
      edge('e1', 'atk', 'shared'),
      edge('e2', 'shared', 'a'),
      edge('e3', 'a', 't'),
      edge('e4', 'shared', 'b'),
      edge('e5', 'b', 't'),
    ];
    const graph = buildAttackGraph(nodes, edges, 'atk', 't');
    const result = analyzeAttackGraph(graph, () => NEUTRAL_EVIDENCE);

    expect(result.chokePoints[0].elementKey).toBe('node:shared');
    expect(result.chokePoints[0].routeHits).toBe(2);
    expect(result.chokePoints.some((c) => c.elementKey === 'node:atk')).toBe(false);
    expect(result.chokePoints.some((c) => c.elementKey === 'node:t')).toBe(false);
    expect(result.chokePoints.some((c) => c.elementKey.startsWith('hop:'))).toBe(true);
  });

  it('allUnevaluated: 全要素未評価なら true、1 要素でも DREAD 入力ありなら false', () => {
    const nodes = [node('atk'), node('a'), node('t')];
    const edges = [edge('e1', 'atk', 'a'), edge('e2', 'a', 't')];
    const graph = buildAttackGraph(nodes, edges, 'atk', 't');

    expect(analyzeAttackGraph(graph, () => NEUTRAL_EVIDENCE).allUnevaluated).toBe(true);

    const partiallyEvaluated = analyzeAttackGraph(
      graph,
      provider({ [nodeElementKey('a')]: { evaluated: true } }),
    );
    expect(partiallyEvaluated.allUnevaluated).toBe(false);
  });

  it('weakestHopKey が経路中で最も低コストなホップを指す', () => {
    const nodes = [node('atk'), node('a'), node('b'), node('t')];
    const edges = [edge('e1', 'atk', 'a'), edge('e2', 'a', 'b'), edge('e3', 'b', 't')];
    const graph = buildAttackGraph(nodes, edges, 'atk', 't');

    const result = analyzeAttackGraph(
      graph,
      provider({
        [nodeElementKey('a')]: { difficulty: 3 },
        [nodeElementKey('b')]: { difficulty: 0 },
      }),
    );

    expect(result.routes[0].weakestHopKey).toBe('a--b');
  });
});
