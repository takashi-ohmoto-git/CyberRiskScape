import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { businessContextReportToJson, businessContextReportToText, importBusinessContext } from './importBusinessContext';
import { parseBusinessContextTable } from '../features/business-context/parseBusinessContextTable';
import { deserializeProject } from '../features/persistence/serialize';
import { findingsPriority, priorityToJson } from './findingsPriority';
import { cveFinding, makeProject } from './__fixtures__/findingsPriorityProject';

const NOW = new Date('2026-11-13T00:00:00.000Z');

function table() {
  const t = parseBusinessContextTable(readFileSync(new URL('../features/business-context/__fixtures__/table.csv', import.meta.url), 'utf-8'), 'table.csv');
  if (!t.ok) throw new Error(t.error);
  return t;
}

describe('importBusinessContext', () => {
  const project = makeProject([cveFinding('f1', 'mid', 'Low', 'CVE-2099-0001')]);

  it('表のノードに businessContext を書き、保存して読み直しても残る。他のノードと項目は変えない', () => {
    const out = importBusinessContext(project, table(), NOW);
    const loaded = deserializeProject(JSON.parse(JSON.stringify(out.project)));
    const nodes = loaded?.layers?.L1?.nodes ?? [];
    expect(nodes.find((n) => n.id === 'web')?.businessContext).toMatchObject({
      criticality: 'High',
      criticalitySource: 'derived',
      processes: [{ name: 'Order-to-Cash', cases: 1200, value: 8000000, currency: 'JPY', period: '2026-10' }, { name: 'Invoice-to-Cash' }],
      source: { product: 'business-context', retrievedAt: NOW.toISOString() },
    });
    expect(nodes.find((n) => n.id === 'mid')?.businessContext?.criticality).toBe('Low'); // 500000 / 10000000 + 1000 = 5%
    expect(nodes.find((n) => n.id === 'pii')?.businessContext).toBeUndefined();
    expect(nodes.find((n) => n.id === 'web')?.attackSurface).toMatchObject({ hasGlobalIp: true });
    expect(out.summary.unknownRefs).toEqual(['ghost']);
  });

  it('High にしたノードは推奨標的になり、その指摘の SSVC Mission & Well-being が high になる', () => {
    const withFinding = makeProject([cveFinding('f2', 'web', 'Low', 'CVE-2099-0002')]);
    const mission = (p: object) => {
      const j = priorityToJson(findingsPriority(p)) as { findings: { ssvcDecision: { points: { missionWellbeing: string }; reasons: string[] } }[] };
      return j.findings[0].ssvcDecision;
    };
    expect(mission(withFinding).points.missionWellbeing).toBe('medium'); // 標的（C4）に届くだけ
    const after = mission(importBusinessContext(withFinding, table(), NOW).project);
    expect(after.points.missionWellbeing).toBe('high');
    expect(after.reasons.join('|')).toContain('業務の重要度 High（金額の割合から）');
  });

  it('報告：text と json の形', () => {
    const out = importBusinessContext(project, table(), NOW);
    const text = businessContextReportToText(out.summary);
    expect(text).toContain('# 業務の文脈の取り込み');
    expect(text).toContain('C2 公開サーバー: High（割合から');
    expect(text).toContain('図に無いノードの参照: ghost');
    expect(businessContextReportToJson(out.summary)).toMatchObject({ kind: 'cyberriskscape-business-context-import-report', basis: 'value' });
  });

  it('プロジェクト JSON が不正なら例外', () => {
    expect(() => importBusinessContext({ nope: true }, table(), NOW)).toThrow('形式が不正');
  });
});
