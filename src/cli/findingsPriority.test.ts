import { describe, expect, it } from 'vitest';
import { findingsPriority, priorityToJson, priorityToMarkdown } from './findingsPriority';
import { cveFinding, makeProject } from './__fixtures__/findingsPriorityProject';

describe('findingsPriority', () => {
  const findings = [
    cveFinding('f1', 'web', 'Medium', 'CVE-2099-0001'),
    cveFinding('f2', 'mid', 'Low', 'CVE-2099-0002'),
    cveFinding('f3', 'mid', 'Low', 'CVE-2099-0003', { kev: { dateAdded: '2099-01-01', ransomware: true } }),
  ];

  it('md：注意書き・優先度別の表・連鎖の節を出す', () => {
    const md = priorityToMarkdown(findingsPriority(makeProject(findings)));
    expect(md).toContain('# 指摘の優先度（推奨）');
    expect(md).toContain('悪用できるとは言わない');
    expect(md).toContain('## P1（先に確認）');
    expect(md).toContain('| 指摘 | 製品 | 元の深刻度 | ノード | 露出 | 届く標的 | KEV |');
    expect(md).toContain('## 組み合わさると標的に届く連鎖');
    expect(md).toContain('【個々は低いが連鎖で届く】');
    expect(md).toContain('C4 顧客情報（2 ホップ）');
  });

  it('json：SSVC との対応・指摘ごとの事実・連鎖', () => {
    const j = priorityToJson(findingsPriority(makeProject(findings))) as {
      evaluated: boolean;
      ssvcMapping: object;
      findings: { id: string; priority: string; exposure: string; exploitation: string; ssvc: { exploitation: string; systemExposure: string | null } }[];
      chains: { allMediumOrBelow: boolean }[];
    };
    expect(j.evaluated).toBe(true);
    expect(j.ssvcMapping).toHaveProperty('systemExposure');
    const f = (id: string) => j.findings.find((x) => x.id === id)!;
    expect(f('f1')).toMatchObject({ priority: 'P1', exposure: 'entry', ssvc: { exploitation: 'none-or-unknown', systemExposure: 'open' } });
    expect(f('f2')).toMatchObject({ priority: 'P2', exposure: 'reachable', ssvc: { systemExposure: 'controlled' } });
    expect(f('f3')).toMatchObject({ priority: 'P1', exploitation: 'active', ssvc: { exploitation: 'active' } });
    expect(j.chains[0].allMediumOrBelow).toBe(true);
  });

  it('攻撃者が図に無ければ評価できない旨を出し、--attacker の不正な指定は拒否する', () => {
    const out = findingsPriority(makeProject(findings, { attacker: false }));
    expect(out.noAttacker).toBe(true);
    expect(priorityToMarkdown(out)).toContain('露出を評価できない');
    expect(() => findingsPriority(makeProject(findings), { attacker: 'C9' })).toThrow('見つかりません');
    expect(() => findingsPriority(makeProject(findings), { attacker: 'C2' })).toThrow('攻撃者');
    expect(findingsPriority(makeProject(findings), { attacker: 'C1' }).noAttacker).toBe(false);
  });
});
