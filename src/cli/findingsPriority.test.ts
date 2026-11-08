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

  it('outcome unverified → 優先度の表に入れず「要確認（重大度なし）」に分ける。attempted は従来どおり表に入る', () => {
    const unverified = cveFinding('f9', 'web', 'Low', 'CVE-2099-0009', { outcome: 'unverified', title: '要確認の指摘' });
    const attempted = cveFinding('f8', 'web', 'Low', 'CVE-2099-0008', { outcome: 'attempted' });
    const out = findingsPriority(makeProject([...findings, unverified, attempted]));
    expect(out.unverified.map((f) => f.id)).toEqual(['f9']);
    expect(out.result.items.map((i) => i.finding.id)).not.toContain('f9');
    expect(out.result.items.map((i) => i.finding.id)).toContain('f8');
    const md = priorityToMarkdown(out);
    expect(md).toContain('## 要確認（重大度なし）（1 件）');
    expect(md).toContain('| 要確認の指摘 | example-scanner | C2 公開サーバー |');
    // 優先度の表には出ない（要確認の節より前の部分）
    expect(md.split('## 要確認（重大度なし）')[0]).not.toContain('要確認の指摘');
    expect(md).not.toContain('## 要確認（重大度なし）（0');
    const j = priorityToJson(out) as { unverified: { id: string; node: string }[]; findings: { id: string }[] };
    expect(j.unverified).toMatchObject([{ id: 'f9', node: 'C2 公開サーバー' }]);
    expect(j.findings.map((f) => f.id)).not.toContain('f9');
  });

  it('要確認が無ければ節を出さない', () => {
    expect(priorityToMarkdown(findingsPriority(makeProject(findings)))).not.toContain('要確認（重大度なし）');
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

describe('findingsPriority（EPSS）', () => {
  const findings = [cveFinding('m', 'mid', 'Low', 'CVE-2099-0002', { epss: { score: 0.42 } })];

  it('既定のしきい値 0.1 で入口の奥の P2 が P1 に上がる。md に EPSS 列と説明、json に epss と exploitation', () => {
    const out = findingsPriority(makeProject(findings));
    expect(out.epssThreshold).toBe(0.1);
    const md = priorityToMarkdown(out);
    expect(md).toContain('| 届く標的 | KEV | EPSS |');
    expect(md).toContain('| 0.42 |');
    expect(md).toContain('EPSS が 0.1 以上');
    const j = priorityToJson(out) as { epssThreshold: number; findings: { priority: string; exploitation: string; epss: { score: number } | null }[] };
    expect(j.epssThreshold).toBe(0.1);
    expect(j.findings[0]).toMatchObject({ priority: 'P1', exploitation: 'likely', epss: { score: 0.42 } });
  });

  it('しきい値を上げると上げない（P2・unknown）', () => {
    const j = priorityToJson(findingsPriority(makeProject(findings), { epssThreshold: 0.5 })) as { findings: { priority: string; exploitation: string }[] };
    expect(j.findings[0]).toMatchObject({ priority: 'P2', exploitation: 'unknown' });
  });
});

describe('findingsPriority（SSVC）', () => {
  const findings = [
    cveFinding('f1', 'web', 'Medium', 'CVE-2099-0001'),
    cveFinding('f3', 'mid', 'Low', 'CVE-2099-0003', { kev: { dateAdded: '2099-01-01' } }),
  ];

  it('md：SSVC 列・※・凡例・内訳を出す', () => {
    const md = priorityToMarkdown(findingsPriority(makeProject(findings)));
    expect(md).toContain('| KEV | EPSS | SSVC |');
    expect(md).toMatch(/\| (Track\*?|Attend|Act)※ \|/);
    expect(md).toContain('Track＝標準の更新期間で対応する');
    expect(md).toContain('Act＝できるだけ早く対応し');
    expect(md).toContain('Technical Impact は CVSS ベクター');
    expect(md).toMatch(/SSVC の内訳：Track \d+ 件 \/ Track\* \d+ 件 \/ Attend \d+ 件 \/ Act \d+ 件/);
  });

  it('json：指摘ごとの ssvcDecision（判定・判定点・仮定・理由）と ssvcCounts', () => {
    const j = priorityToJson(findingsPriority(makeProject(findings))) as {
      ssvcCounts: Record<string, number>;
      findings: {
        id: string;
        ssvcDecision: { decision: string; points: Record<string, string>; assumed: Record<string, boolean>; reasons: string[] };
      }[];
    };
    const f1 = j.findings.find((x) => x.id === 'f1')!.ssvcDecision;
    // 入口・標的に届く（medium）・Medium → partial・KEV なし → none/yes/partial/medium
    expect(f1.points).toEqual({ exploitation: 'none', automatable: 'yes', technicalImpact: 'partial', missionWellbeing: 'medium' });
    expect(f1.decision).toBe('Track');
    expect(f1.assumed).toEqual({ automatable: false, technicalImpact: true, missionWellbeing: false });
    expect(f1.reasons.length).toBeGreaterThanOrEqual(4);
    const f3 = j.findings.find((x) => x.id === 'f3')!.ssvcDecision;
    expect(f3.points.exploitation).toBe('active');
    expect(Object.values(j.ssvcCounts).reduce((a, b) => a + b, 0)).toBe(2);
  });
});
