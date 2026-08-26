import { describe, expect, it } from 'vitest';
import { buildElementAnalytics } from './buildElementAnalytics';
import type {
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  ThreatView,
} from '../../core/model/types';

const nodes: DiagramNode[] = [
  { id: 'n1', seq: 1, type: 'USER', x: 0, y: 0 },
  { id: 'n2', seq: 2, type: 'LLM', x: 0, y: 0 },
];
const edges: DiagramEdge[] = [
  { id: 'e1', seq: 1, source: 'n1', target: 'n2', auth: 'None', network: 'VPC', encryption: 'TLS' },
];
const boundaries: DiagramBoundary[] = [
  { id: 'b1', seq: 1, type: 'RECT', x: 0, y: 0, width: 10, height: 10, trustLevel: 'Internal' },
];

const tv = (over: Partial<ThreatView>): ThreatView => ({
  id: 'x',
  nodeId: '',
  framework: 'STRIDE',
  category: 'C',
  severity: 'Low',
  description: 'd',
  origin: 'detected',
  ...over,
});

describe('buildElementAnalytics', () => {
  it('全要素を ElementalID 付きで行に展開する（C/DF/Z 順）', () => {
    const { rows } = buildElementAnalytics({ nodes, edges, boundaries, threats: [] });
    expect(rows.map((r) => r.elementalId)).toEqual(['C1', 'C2', 'DF1', 'Z1']);
    expect(rows.every((r) => r.threats.length === 0 && r.maxSeverity === null)).toBe(true);
  });

  it('subject で脅威を要素ごとに集約する', () => {
    const threats = [
      tv({ id: 't1', subject: { kind: 'node', id: 'n2' }, severity: 'High' }),
      tv({ id: 't2', subject: { kind: 'edge', id: 'e1' }, severity: 'Medium' }),
    ];
    const { rows } = buildElementAnalytics({ nodes, edges, boundaries, threats });
    const c2 = rows.find((r) => r.elementalId === 'C2')!;
    const df1 = rows.find((r) => r.elementalId === 'DF1')!;
    expect(c2.threats.map((t) => t.id)).toEqual(['t1']);
    expect(df1.threats.map((t) => t.id)).toEqual(['t2']);
  });

  it('maxSeverity は要素内の最大リスクを返す', () => {
    const threats = [
      tv({ id: 't1', subject: { kind: 'node', id: 'n2' }, severity: 'Medium' }),
      tv({ id: 't2', subject: { kind: 'node', id: 'n2' }, severity: 'Critical' }),
      tv({ id: 't3', subject: { kind: 'node', id: 'n2' }, severity: 'Low' }),
    ];
    const { rows } = buildElementAnalytics({ nodes, edges, boundaries, threats });
    expect(rows.find((r) => r.elementalId === 'C2')!.maxSeverity).toBe('Critical');
  });

  it('maxSeverity は DREAD 評価済み脅威の評価由来ランクを優先する（上書き方式）', () => {
    // severity=Critical だが DREAD 合計 5（=Low）→ 要素の最大リスクは他方の Medium になる
    const lowDread = {
      damage: 1,
      reproducibility: 1,
      exploitability: 1,
      affectedUsers: 1,
      discoverability: 1,
      at: 0,
    } as const;
    const threats = [
      tv({ id: 't1', subject: { kind: 'node', id: 'n2' }, severity: 'Critical', dread: lowDread }),
      tv({ id: 't2', subject: { kind: 'node', id: 'n2' }, severity: 'Medium' }),
    ];
    const { rows } = buildElementAnalytics({ nodes, edges, boundaries, threats });
    expect(rows.find((r) => r.elementalId === 'C2')!.maxSeverity).toBe('Medium');
  });

  it('subject 未設定 / 不在要素参照は unassigned に振り分ける', () => {
    const threats = [
      tv({ id: 'whole' }), // subject なし
      tv({ id: 'ghost', subject: { kind: 'node', id: 'deleted' } }), // 不在要素
      tv({ id: 'ok', subject: { kind: 'node', id: 'n1' } }),
    ];
    const { rows, unassigned } = buildElementAnalytics({ nodes, edges, boundaries, threats });
    expect(unassigned.map((t) => t.id).sort()).toEqual(['ghost', 'whole']);
    expect(rows.find((r) => r.elementalId === 'C1')!.threats.map((t) => t.id)).toEqual(['ok']);
  });

  it('seq 欠落要素は内部 ID にフォールバックする', () => {
    const { rows } = buildElementAnalytics({
      nodes: [{ id: 'legacy', type: 'DB', x: 0, y: 0 }],
      edges: [],
      boundaries: [],
      threats: [],
    });
    expect(rows[0].elementalId).toBe('legacy');
  });
});
