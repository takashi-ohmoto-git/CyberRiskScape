import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parse as parseYaml } from 'yaml';
import { buildInvestigationPlan, type InvestigationPlanInput } from './buildInvestigationPlan';
import { investigationPlanToJson, investigationPlanToMarkdown } from './investigationPlanOutput';
import {
  BUNDLED_INVESTIGATION_OVERLAY_EN,
  getInvestigationViewpoints,
  loadInvestigationViewpoints,
} from './viewpoints';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';
import { EMPTY_PROJECT_META, type DiagramEdge, type DiagramNode, type ThreatView } from '../../core/model/types';

const NOW = new Date('2026-10-20T12:00:00Z');

describe('investigation viewpoints', () => {
  const text = readFileSync('data/investigation-templates/compromise.yaml', 'utf-8');

  it('YAML がスキーマを通り、id が一意で、canonicalId はすべて同梱の脅威ライブラリに実在する', () => {
    const viewpoints = loadInvestigationViewpoints(text);
    expect(viewpoints.map((v) => v.id)).toEqual([
      'code-execution',
      'credential-misuse',
      'data-access',
      'log-gap',
      'fleet-execution',
    ]);
    const known = new Set(BUNDLED_THREAT_LIBRARY.rules.map((r) => r.canonicalId));
    for (const v of viewpoints) {
      for (const c of v.match.canonicalIds) expect(known.has(c), `${v.id}: ${c}`).toBe(true);
    }
  });

  it('id が重複していると読み込みに失敗する', () => {
    const one = `  - id: a\n    match: { canonicalIds: [x] }\n    title: t\n    checks: [c]\n    logs: [l]\n`;
    expect(() => loadInvestigationViewpoints(`schemaVersion: 1\nviewpoints:\n${one}${one}`)).toThrow(/duplicate/);
  });

  it('英語オーバーレイのキーは原本に存在し、checks / logs の数が一致する', () => {
    const ja = getInvestigationViewpoints('ja');
    const overlay = parseYaml(BUNDLED_INVESTIGATION_OVERLAY_EN ?? '') as {
      viewpoints: Record<string, { title?: string; checks?: string[]; logs?: string[] }>;
    };
    const byId = new Map(ja.map((v) => [v.id, v]));
    for (const [id, o] of Object.entries(overlay.viewpoints)) {
      const orig = byId.get(id);
      expect(orig, id).toBeDefined();
      if (o.checks) expect(o.checks.length, id).toBe(orig!.checks.length);
      if (o.logs) expect(o.logs.length, id).toBe(orig!.logs.length);
    }
    const en = getInvestigationViewpoints('en');
    expect(en.map((v) => v.id)).toEqual(ja.map((v) => v.id));
    en.forEach((v, i) => expect(v.title).not.toBe(ja[i].title));
  });
});

const node = (id: string, seq: number, type: string, extra: Partial<DiagramNode> = {}): DiagramNode =>
  ({ id, seq, type, x: 0, y: 0, label: id, ...extra }) as unknown as DiagramNode;
const edge = (id: string, seq: number, source: string, target: string): DiagramEdge => ({
  id,
  seq,
  source,
  target,
  auth: 'None',
  network: 'Internet',
  encryption: 'Plain',
});
const threat = (id: string, nodeId: string, canonicalId: string, extra: Partial<ThreatView> = {}): ThreatView => ({
  id,
  nodeId,
  subject: { kind: 'node', id: nodeId },
  framework: 'STRIDE',
  category: 'Spoofing',
  severity: 'High',
  description: '説明です。',
  origin: 'detected',
  name: id,
  canonicalId,
  ...extra,
});

/** a(攻撃者) → gw(GATEWAY: logRetention のみ) → api(BACKEND_API: log) → db(DATABASE: log)。iot(IOT: log 系グループ無し) は経路外。 */
function handInput(withAttacker = true): InvestigationPlanInput {
  return {
    nodes: [
      node('a', 1, 'THREAT_ACTOR', withAttacker ? { attackObjectiveId: 'db' } : {}),
      node('gw', 2, 'GATEWAY'),
      node('api', 3, 'BACKEND_API', { posture: { logCollection: 'Collected', logRetention: 'OneYearOrMore' } }),
      node('db', 4, 'DATABASE'),
      node('iot', 5, 'IOT'),
    ],
    edges: [edge('e1', 1, 'a', 'gw'), edge('e2', 2, 'gw', 'api'), edge('e3', 3, 'api', 'db')],
    threats: [
      threat('t1', 'api', 'web-shell-implant'),
      threat('t2', 'api', 'known-vulnerability-unpatched'),
      threat('t3', 'db', 'data-store-tampering'),
      threat('t4', 'db', 'private-endpoint-data-exfiltration', { suppression: { status: 'accepted', note: '', at: 0 } }),
      threat('t5', 'iot', 'web-shell-implant'),
    ],
    projectMeta: { ...EMPTY_PROJECT_META, systemName: 'Demo' },
    layer: 'L1',
  };
}

describe('buildInvestigationPlan', () => {
  it('攻撃者あり: 経路上のノードだけが載り、攻撃者自身と経路外は載らない', () => {
    const plan = buildInvestigationPlan(handInput(), NOW, 'ja');
    expect(plan.generatedAt).toBe('2026-10-20');
    expect(plan.pathBased).toBe(true);
    expect(plan.nodes.map((n) => n.id).sort()).toEqual(['C2', 'C3', 'C4']);
    expect(plan.nodes.every((n) => (n.routeHits ?? 0) >= 1)).toBe(true);
  });

  it('攻撃者なし: 全ノードが対象で、優先度は付かない', () => {
    const plan = buildInvestigationPlan(handInput(false), NOW, 'ja');
    expect(plan.pathBased).toBe(false);
    expect(plan.nodes.map((n) => n.id)).toEqual(['C2', 'C3', 'C4', 'C5']);
    expect(plan.nodes.every((n) => n.routeHits === null)).toBe(true);
    expect(investigationPlanToMarkdown(plan)).toContain('優先度は付けていません');
  });

  it('観点は脅威の canonicalId で引き、同じ観点は 1 回だけ', () => {
    const plan = buildInvestigationPlan(handInput(), NOW, 'ja');
    const api = plan.nodes.find((n) => n.id === 'C3')!;
    expect(api.viewpoints.map((v) => v.id)).toEqual(['code-execution']);
    expect(api.viewpoints[0].threatNames).toHaveLength(2);
    const db = plan.nodes.find((n) => n.id === 'C4')!;
    expect(db.viewpoints.map((v) => v.id)).toEqual(['data-access']);
    expect(db.viewpoints[0].threatNames).toEqual(['t3', 't4']); // t4 はリスク受容だが含める
    // 観点が当たらない経路上のノードも載る
    const gw = plan.nodes.find((n) => n.id === 'C2')!;
    expect(gw.viewpoints).toHaveLength(0);
    expect(gw.limitations.length).toBeGreaterThan(0);
  });

  it('posture 未入力には「調べられない恐れ」が付き、入力済みでは付かない。log グループの無い型は中立', () => {
    const plan = buildInvestigationPlan(handInput(), NOW, 'ja');
    const codes = (id: string) => plan.nodes.find((n) => n.id === id)!.limitations.map((l) => l.code);
    expect(codes('C2')).toEqual(['logRetentionUnset']); // logRetention グループのみ: 収集は問わない
    expect(codes('C3')).toEqual([]); // 収集あり・1 年以上
    expect(codes('C4')).toEqual(['logCollectionUnset', 'logRetentionUnset']); // DATABASE: log グループあり・未入力

    const noLog = buildInvestigationPlan(handInput(false), NOW, 'ja');
    expect(noLog.nodes.find((n) => n.id === 'C5')!.limitations.map((l) => l.code)).toEqual(['logNotModelable']); // IOT

    const unset = handInput();
    unset.nodes[2] = node('api', 3, 'BACKEND_API');
    expect(
      buildInvestigationPlan(unset, NOW, 'ja')
        .nodes.find((n) => n.id === 'C3')!
        .limitations.map((l) => l.code),
    ).toEqual(['logCollectionUnset', 'logRetentionUnset']);

    const bad = handInput();
    bad.nodes[2] = node('api', 3, 'BACKEND_API', { posture: { logCollection: 'NotCollected', logRetention: 'Under90Days' } });
    expect(
      buildInvestigationPlan(bad, NOW, 'ja')
        .nodes.find((n) => n.id === 'C3')!
        .limitations.map((l) => l.code),
    ).toEqual(['logNotCollected', 'logRetentionShort']);
  });

  it('経路の多いノードから並ぶ', () => {
    const plan = buildInvestigationPlan(handInput(), NOW, 'ja');
    const hits = plan.nodes.map((n) => n.routeHits ?? 0);
    expect(hits).toEqual([...hits].sort((a, b) => b - a));
  });

  it('--tool なしでは artifact 名が出力に含まれず、ありでは含まれる', () => {
    const without = buildInvestigationPlan(handInput(), NOW, 'ja');
    expect(investigationPlanToMarkdown(without)).not.toContain('Linux.Sys.Pslist');
    expect(investigationPlanToJson(without)).not.toContain('Linux.Sys.Pslist');
    const withTool = buildInvestigationPlan(handInput(), NOW, 'ja', 'velociraptor');
    const md = investigationPlanToMarkdown(withTool);
    expect(md).toContain('Linux.Sys.Pslist');
    expect(md).toContain('TargetGlob=/var/log/**');
    expect(investigationPlanToJson(withTool)).toContain('Linux.Sys.Pslist');
    // tools の無い観点（data-access）には何も足されない
    expect(withTool.nodes.find((n) => n.id === 'C4')!.viewpoints[0].toolSteps).toBeUndefined();
  });

  it('リスク受容の脅威も観点に含め、判断を併記する。誤検知は除く', () => {
    const input = handInput();
    input.threats.push(
      threat('t6', 'gw', 'log-collection-blinding', { suppression: { status: 'accepted', note: '閉域のため', at: 0 } }),
      threat('t7', 'gw', 'endpoint-fleet-mass-execution', { suppression: { status: 'false-positive', note: '', at: 0 } }),
      threat('t8', 'db', 'private-endpoint-data-exfiltration', { suppression: { status: 'accepted', note: '', at: 0 } }),
    );
    const plan = buildInvestigationPlan(input, NOW, 'ja');
    const gw = plan.nodes.find((n) => n.id === 'C2')!;
    expect(gw.viewpoints.map((v) => v.id)).toEqual(['log-gap']); // 誤検知の fleet-execution は出ない
    expect(gw.viewpoints[0].accepted).toEqual([{ threat: 't6', note: '閉域のため' }]);
    const db = plan.nodes.find((n) => n.id === 'C4')!;
    expect(db.viewpoints[0].accepted).toEqual([{ threat: 't4', note: '' }, { threat: 't8', note: '' }]);
    const md = investigationPlanToMarkdown(plan);
    expect(md).toContain('リスク受容済み（判断：閉域のため）');
    expect(md).toContain('リスク受容済み（判断の理由は記録なし）');
    expect(investigationPlanToJson(plan)).toContain('"accepted"');
  });

  it('Markdown に免責の文言が ja / en で含まれる', () => {
    expect(investigationPlanToMarkdown(buildInvestigationPlan(handInput(), NOW, 'ja'))).toContain(
      '侵害の有無を判定しない。痕跡が無いことは、侵害が無かったことの証明にならない',
    );
    expect(investigationPlanToMarkdown(buildInvestigationPlan(handInput(), NOW, 'en'))).toContain(
      'does not determine whether a compromise occurred',
    );
  });
});
