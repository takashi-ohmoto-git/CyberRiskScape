import { describe, expect, it } from 'vitest';
import {
  aggregateLogicalHopEvidence,
  buildHopEvidence,
  edgeElementKey,
  nodeElementKey,
  NEUTRAL_EVIDENCE,
  resolveDifficulty,
  threatEvidenceScore,
} from './hopEvidence';
import type { ControlStatusValue, DreadValue, ThreatView } from '../../core/model/types';
import type { LogicalHop } from './buildAttackGraph';

function threat(
  id: string,
  opts: {
    nodeId?: string;
    subject?: { kind: 'node' | 'edge' | 'boundary'; id: string };
    name?: string;
    severity?: ThreatView['severity'];
    exploitability?: DreadValue;
    control?: ControlStatusValue;
  } = {},
): ThreatView {
  return {
    id,
    nodeId: opts.nodeId ?? 'n1',
    subject: opts.subject,
    framework: 'STRIDE',
    category: 'Tampering',
    name: opts.name,
    severity: opts.severity ?? 'Medium',
    description: '',
    origin: 'detected',
    dread: opts.exploitability
      ? { damage: 1, reproducibility: 1, exploitability: opts.exploitability, affectedUsers: 1, discoverability: 1, at: 0 }
      : undefined,
    controlStatus: opts.control ? { status: opts.control, at: 0 } : undefined,
  } as ThreatView;
}

describe('resolveDifficulty', () => {
  it('DREAD ありは 4-maxE / dread / evaluated', () => {
    expect(resolveDifficulty(3, [{ threatId: 't', name: 'x', severity: 'Low' }])).toEqual({
      difficulty: 1,
      evaluated: true,
      difficultyBasis: 'dread',
    });
  });

  it('脅威なしは中立 2 / neutral', () => {
    expect(resolveDifficulty(0, [])).toEqual({
      difficulty: 2,
      evaluated: false,
      difficultyBasis: 'neutral',
    });
  });

  it('脅威あり・DREAD なしは severity 転用 / severity-soft / 未評価', () => {
    expect(
      resolveDifficulty(0, [
        { threatId: 't1', name: 'a', severity: 'Low' },
        { threatId: 't2', name: 'b', severity: 'Critical' },
      ]),
    ).toEqual({ difficulty: 1, evaluated: false, difficultyBasis: 'severity-soft' });
    expect(resolveDifficulty(0, [{ threatId: 't', name: 'a', severity: 'Medium' }])).toEqual({
      difficulty: 2,
      evaluated: false,
      difficultyBasis: 'severity-soft',
    });
    expect(resolveDifficulty(0, [{ threatId: 't', name: 'a', severity: 'Low' }])).toEqual({
      difficulty: 3,
      evaluated: false,
      difficultyBasis: 'severity-soft',
    });
  });
});

describe('buildHopEvidence', () => {
  it('difficulty=4-maxExploitability / coverage 判定を要素キー単位で集約する', () => {
    const threats: ThreatView[] = [
      threat('t1', { nodeId: 'n1', exploitability: 1, control: 'implemented' }),
      threat('t2', { nodeId: 'n1', exploitability: 3 }),
      threat('t3', { subject: { kind: 'edge', id: 'e1' }, exploitability: 2, control: 'not-applicable' }),
      threat('t4', { subject: { kind: 'edge', id: 'e1' }, control: 'required' }),
      threat('t5', { nodeId: 'n2', severity: 'Medium' }),
      threat('t6', { subject: { kind: 'boundary', id: 'b1' }, exploitability: 3 }),
    ];

    const evidence = buildHopEvidence(threats);

    // boundary(b1) は無視されるので 3 要素（node:n1 / edge:e1 / node:n2）。
    expect(evidence.size).toBe(3);
    // n1: maxExpl=3 → diff 1、2 件中 1 件被覆 → partial。
    expect(evidence.get(nodeElementKey('n1'))).toMatchObject({
      difficulty: 1,
      coverage: 'partial',
      difficultyBasis: 'dread',
      evaluated: true,
    });
    // e1: maxExpl=2 → diff 2、2 件中 1 件被覆(not-applicable) → partial。
    expect(evidence.get(edgeElementKey('e1'))).toMatchObject({
      difficulty: 2,
      coverage: 'partial',
      difficultyBasis: 'dread',
    });
    // n2: DREAD 未評価・Medium 脅威 → soft diff 2、被覆なし → none。
    expect(evidence.get(nodeElementKey('n2'))).toMatchObject({
      difficulty: 2,
      coverage: 'none',
      difficultyBasis: 'severity-soft',
      evaluated: false,
    });
  });

  it('High severity 脅威のみ（DREAD なし）は暫定難易度 1', () => {
    const evidence = buildHopEvidence([threat('t1', { nodeId: 'n1', severity: 'High' })]);
    expect(evidence.get(nodeElementKey('n1'))).toMatchObject({
      difficulty: 1,
      evaluated: false,
      difficultyBasis: 'severity-soft',
    });
  });

  it('evaluated: DREAD 入力ありの要素は true、脅威はあるが未入力は false', () => {
    const evidence = buildHopEvidence([
      threat('t1', { nodeId: 'n1', exploitability: 2 }),
      threat('t2', { nodeId: 'n2' }),
    ]);
    expect(evidence.get(nodeElementKey('n1'))?.evaluated).toBe(true);
    expect(evidence.get(nodeElementKey('n2'))?.evaluated).toBe(false);
  });

  it('threats 内訳: threatId/name(フォールバック含む)/severity/exploitability/controlStatus を正しく写像する', () => {
    const evidence = buildHopEvidence([
      threat('t1', { nodeId: 'n1', name: 'SQL Injection', severity: 'High', exploitability: 3, control: 'implemented' }),
      threat('t2', { nodeId: 'n1', severity: 'Low' }),
    ]);
    const refs = evidence.get(nodeElementKey('n1'))?.threats;
    expect(refs).toHaveLength(2);
    expect(refs![0]).toEqual({
      threatId: 't1',
      name: 'SQL Injection',
      severity: 'High',
      exploitability: 3,
      controlStatus: 'implemented',
    });
    // name 未指定 → category フォールバック、DREAD/control 未入力 → undefined
    expect(refs![1]).toEqual({
      threatId: 't2',
      name: 'Tampering',
      severity: 'Low',
      exploitability: undefined,
      controlStatus: undefined,
    });
  });

  it('boundary subject の脅威は無視され、subject 無しは nodeId フォールバックする', () => {
    const evidence = buildHopEvidence([
      threat('t1', { subject: { kind: 'boundary', id: 'b1' }, exploitability: 3 }),
      threat('t2', { nodeId: 'n1', exploitability: 2 }),
    ]);
    expect(evidence.size).toBe(1);
    expect(evidence.get(nodeElementKey('n1'))?.threats.map((r) => r.threatId)).toEqual(['t2']);
  });

  it('空入力は空 Map を返す', () => {
    expect(buildHopEvidence([]).size).toBe(0);
  });

  it('edge subject も集約する', () => {
    const evidence = buildHopEvidence([
      threat('t1', { subject: { kind: 'edge', id: 'e1' }, exploitability: 2 }),
    ]);
    expect(evidence.get(edgeElementKey('e1'))?.difficulty).toBe(2);
  });
});

describe('aggregateLogicalHopEvidence', () => {
  it('並行チャネルの最小 difficulty・最弱 coverage・脅威結合を返す', () => {
    const hop: LogicalHop = { key: 'a--b', a: 'a', b: 'b', edgeIds: ['e1', 'e2'] };
    const map = new Map([
      [
        edgeElementKey('e1'),
        {
          difficulty: 1,
          coverage: 'full' as const,
          evaluated: true,
          difficultyBasis: 'dread' as const,
          threats: [{ threatId: 't1', name: 'A', severity: 'High' as const, exploitability: 3 as DreadValue }],
        },
      ],
      [
        edgeElementKey('e2'),
        {
          difficulty: 3,
          coverage: 'none' as const,
          evaluated: false,
          difficultyBasis: 'severity-soft' as const,
          threats: [{ threatId: 't2', name: 'B', severity: 'Low' as const }],
        },
      ],
    ]);
    const agg = aggregateLogicalHopEvidence(hop, (k) => map.get(k) ?? NEUTRAL_EVIDENCE);
    expect(agg.difficulty).toBe(1);
    expect(agg.coverage).toBe('none'); // 最弱
    expect(agg.evaluated).toBe(true);
    expect(agg.difficultyBasis).toBe('dread');
    expect(agg.threats.map((t) => t.threatId)).toEqual(['t1', 't2']);
  });

  it('チャネル無しは NEUTRAL', () => {
    const hop: LogicalHop = { key: 'a--b', a: 'a', b: 'b', edgeIds: [] };
    expect(aggregateLogicalHopEvidence(hop, () => NEUTRAL_EVIDENCE)).toEqual(NEUTRAL_EVIDENCE);
  });
});

describe('threatEvidenceScore', () => {
  it('件数・severity・exploitability で単調増加する', () => {
    expect(threatEvidenceScore([])).toBe(0);
    expect(threatEvidenceScore([{ threatId: 't', name: 'x', severity: 'Low' }])).toBe(1);
    expect(threatEvidenceScore([{ threatId: 't', name: 'x', severity: 'Critical' }])).toBe(4);
    expect(
      threatEvidenceScore([{ threatId: 't', name: 'x', severity: 'High', exploitability: 3 }]),
    ).toBe(1 + 2 + 3);
  });
});
