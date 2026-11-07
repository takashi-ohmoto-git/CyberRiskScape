import { describe, expect, it } from 'vitest';
import {
  BUNDLED_SSVC,
  loadSsvcTable,
  SSVC_AUTOMATABLE,
  SSVC_DECISIONS,
  SSVC_EXPLOITATION,
  SSVC_MISSION,
  SSVC_TECHNICAL_IMPACT,
  ssvcDecide,
  type SsvcDecision,
} from './ssvc';

describe('同梱の SSVC 判定表', () => {
  it('36 通りの組み合わせがちょうど 1 回ずつあり、4 つの判定結果の説明がある', () => {
    expect(BUNDLED_SSVC.rows.size).toBe(36);
    for (const exploitation of SSVC_EXPLOITATION)
      for (const automatable of SSVC_AUTOMATABLE)
        for (const technicalImpact of SSVC_TECHNICAL_IMPACT)
          for (const missionWellbeing of SSVC_MISSION) {
            expect(SSVC_DECISIONS).toContain(ssvcDecide({ exploitation, automatable, technicalImpact, missionWellbeing }));
          }
    for (const d of SSVC_DECISIONS) expect(BUNDLED_SSVC.descriptions[d].length).toBeGreaterThan(0);
  });

  it.each<[string, string, string, string, SsvcDecision]>([
    ['none', 'no', 'total', 'high', 'Track*'],
    ['poc', 'yes', 'total', 'medium', 'Track*'],
    ['active', 'no', 'total', 'medium', 'Attend'],
    ['active', 'yes', 'partial', 'high', 'Act'],
    ['none', 'no', 'partial', 'low', 'Track'],
    ['none', 'yes', 'total', 'high', 'Attend'],
  ])('%s / %s / %s / %s → %s', (exploitation, automatable, technicalImpact, missionWellbeing, expected) => {
    expect(ssvcDecide({ exploitation, automatable, technicalImpact, missionWellbeing } as never)).toBe(expected);
  });

  it('行の欠落・重複は読み込み時に例外', () => {
    const row = '  - { exploitation: none, automatable: no, technicalImpact: partial, missionWellbeing: low, decision: Track }\n';
    const head =
      'schemaVersion: 1\ndecisions:\n' + SSVC_DECISIONS.map((d) => `  - { id: '${d}', description: x }\n`).join('') + 'rows:\n';
    expect(() => loadSsvcTable(head + row)).toThrow('36');
    expect(() => loadSsvcTable(head + row + row)).toThrow('重複');
  });
});
