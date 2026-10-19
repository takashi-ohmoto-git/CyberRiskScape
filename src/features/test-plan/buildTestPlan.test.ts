import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { buildTestPlan, type TestPlanInput } from './buildTestPlan';
import { testPlanToJson, testPlanToMarkdown } from './testPlanOutput';
import { BUNDLED_VIEWPOINT_OVERLAY_EN, getViewpoints, loadViewpoints } from './viewpoints';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';
import { analyzeProject } from '../../cli/analyze';
import { EMPTY_PROJECT_META, type DiagramEdge, type DiagramNode, type ThreatView } from '../../core/model/types';
import { parse as parseYaml } from 'yaml';

const NOW = new Date('2026-10-20T12:00:00Z'); // UTC−11〜+11 で 10-20 になる時刻（generatedAt は実行環境の日付）

describe('pentest viewpoints', () => {
  it('YAML を読め、id が一意で、canonicalId はすべて同梱の脅威ライブラリに実在する', () => {
    const text = readFileSync('data/test-templates/pentest.yaml', 'utf-8');
    const viewpoints = loadViewpoints(text);
    expect(viewpoints.length).toBeGreaterThan(0);
    expect(new Set(viewpoints.map((v) => v.id)).size).toBe(viewpoints.length);
    const known = new Set(BUNDLED_THREAT_LIBRARY.rules.map((r) => r.canonicalId));
    for (const v of viewpoints) {
      for (const c of v.match.canonicalIds) expect(known.has(c), `${v.id}: ${c}`).toBe(true);
    }
  });

  it('id が重複していると読み込みに失敗する', () => {
    const one = `  - id: a\n    match: { canonicalIds: [x] }\n    title: t\n    checks: [c]\n    references: []\n`;
    expect(() => loadViewpoints(`schemaVersion: 1\nviewpoints:\n${one}${one}`)).toThrow(/duplicate/);
  });

  it('英語オーバーレイのキーは原本に存在し、checks の数が一致する', () => {
    const ja = getViewpoints('ja');
    const overlay = parseYaml(BUNDLED_VIEWPOINT_OVERLAY_EN ?? '') as {
      viewpoints: Record<string, { title?: string; checks?: string[] }>;
    };
    const byId = new Map(ja.map((v) => [v.id, v]));
    for (const [id, o] of Object.entries(overlay.viewpoints)) {
      const orig = byId.get(id);
      expect(orig, id).toBeDefined();
      if (o.checks) expect(o.checks.length, id).toBe(orig!.checks.length);
    }
    const en = getViewpoints('en');
    expect(en.map((v) => v.id)).toEqual(ja.map((v) => v.id));
    en.forEach((v, i) => expect(v.title).not.toBe(ja[i].title));
  });
});

function sampleInput(): TestPlanInput {
  const raw = JSON.parse(readFileSync('src/cli/__fixtures__/sample-project.json', 'utf-8'));
  return analyzeProject(raw)[0].input;
}

describe('buildTestPlan (sample-project)', () => {
  it('入口・重点テスト項目を作り、観点は要素ごとに 1 回だけ載る', () => {
    const plan = buildTestPlan(sampleInput(), NOW, 'ja');
    expect(plan.generatedAt).toBe('2026-10-20');
    expect(plan.focusGroups.length).toBeGreaterThan(0);
    for (const g of plan.focusGroups) {
      const ids = g.viewpoints.map((v) => v.id);
      expect(new Set(ids).size).toBe(ids.length);
    }
    expect(plan.focusGroups.some((g) => g.viewpoints.length > 0)).toBe(true);
    // 重大度の高い要素から並ぶ
    const order = ['Critical', 'High', 'Medium', 'Low'];
    const ranks = plan.focusGroups.map((g) => order.indexOf(g.maxSeverity));
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
  });

  it('Markdown に ja / en の見出しが出る', () => {
    const ja = testPlanToMarkdown(buildTestPlan(sampleInput(), NOW, 'ja'));
    for (const h of ['## 1. 概要と前提', '## 2. 範囲', '## 3. 攻撃シナリオ', '## 4. 重点テスト項目', '## 5. 対象外とする脅威']) {
      expect(ja).toContain(h);
    }
    const en = testPlanToMarkdown(buildTestPlan(sampleInput(), NOW, 'en'));
    for (const h of ['## 1. Overview and premises', '## 2. Scope', '## 3. Attack scenarios', '## 4. Focus test items', '## 5. Threats set aside']) {
      expect(en).toContain(h);
    }
  });
});

// ── 攻撃者 + objective を持つ小さな手組みの入力 ──
const node = (id: string, seq: number, type: string, extra: Partial<DiagramNode> = {}): DiagramNode =>
  ({ id, seq, type, x: 0, y: 0, label: id, ...extra }) as unknown as DiagramNode;
const edge = (id: string, seq: number, source: string, target: string, extra: Partial<DiagramEdge> = {}): DiagramEdge => ({
  id,
  seq,
  source,
  target,
  auth: 'None',
  network: 'Internet',
  encryption: 'Plain',
  ...extra,
});
const threat = (id: string, nodeId: string, extra: Partial<ThreatView>): ThreatView => ({
  id,
  nodeId,
  subject: { kind: 'node', id: nodeId },
  framework: 'STRIDE',
  category: 'Spoofing',
  severity: 'High',
  description: '説明です。二文目です。',
  origin: 'detected',
  ...extra,
});

function handInput(): TestPlanInput {
  return {
    nodes: [
      node('a', 1, 'THREAT_ACTOR', { attackObjectiveId: 'db' }),
      node('gw', 2, 'GATEWAY'),
      node('db', 3, 'DATABASE'),
    ],
    edges: [edge('e1', 1, 'a', 'gw'), edge('e2', 2, 'gw', 'db', { network: 'VPC', auth: 'Token', encryption: 'TLS' })],
    threats: [
      threat('t1', 'gw', { canonicalId: 'web-missing-authentication', name: '認証欠如', ruleId: 'r1' }),
      threat('t2', 'gw', { canonicalId: 'unauthenticated-internet-channel', name: 'なりすまし', ruleId: 'r2', severity: 'Critical' }),
      threat('t3', 'db', { name: '受容した脅威', ruleId: 'r3', suppression: { status: 'accepted', note: '閉域のため', at: 0 } }),
      threat('t4', 'db', { name: '観点なし', ruleId: 'r4', severity: 'Low' }),
    ],
    projectMeta: { ...EMPTY_PROJECT_META, systemName: 'Demo' },
    layer: 'L1',
  };
}

describe('buildTestPlan (attacker with objective)', () => {
  const plan = buildTestPlan(handInput(), NOW, 'ja');

  it('入口は攻撃者から直接届くノードだけ', () => {
    expect(plan.entryPoints.map((e) => e.node.id)).toEqual(['C2']);
    expect(plan.entryPoints[0].inbound[0]).toMatchObject({ auth: 'None', network: 'Internet' });
  });

  it('攻撃シナリオに経路と要所が出る', () => {
    expect(plan.scenarios).toHaveLength(1);
    const sc = plan.scenarios[0];
    expect(sc.routes[0].path.map((p) => p.id)).toEqual(['C1', 'C2', 'C3']);
    expect(sc.routes[0].weakestHop).not.toBeNull();
    expect(sc.chokePoints.length).toBeGreaterThan(0);
  });

  it('抑制した脅威は 5 章へ、重点テスト項目には入らない', () => {
    expect(plan.suppressed.map((s) => s.ruleId)).toEqual(['r3']);
    const names = plan.focusGroups.flatMap((g) => g.threats.map((t) => t.name));
    expect(names).not.toContain('受容した脅威');
    expect(names).toContain('観点なし');
    const md = testPlanToMarkdown(plan);
    expect(md.split('## 5.')[1]).toContain('閉域のため');
  });

  it('同じ観点に当たる 2 件の脅威は、観点を 1 回だけ載せる', () => {
    const gw = plan.focusGroups.find((g) => g.target.id === 'C2')!;
    expect(gw.threats).toHaveLength(2);
    expect(gw.viewpoints).toHaveLength(1);
    expect(gw.viewpoints[0].threatNames).toHaveLength(2);
    expect(gw.maxSeverity).toBe('Critical');
  });

  it('観点の無い脅威も説明だけで載る', () => {
    const db = plan.focusGroups.find((g) => g.target.id === 'C3')!;
    expect(db.viewpoints).toHaveLength(0);
    expect(db.threats[0].description).toBe('説明です。');
  });

  it('JSON は英語キーの構造を持つ', () => {
    const json = JSON.parse(testPlanToJson(plan));
    expect(Object.keys(json)).toEqual(
      expect.arrayContaining(['locale', 'system', 'layer', 'generatedAt', 'entryPoints', 'scenarios', 'focusGroups', 'suppressed']),
    );
  });

  it('objective を持つ攻撃者がいなければ、追加方法の案内が出る', () => {
    const input = handInput();
    input.nodes[0] = node('a', 1, 'THREAT_ACTOR');
    const p = buildTestPlan(input, NOW, 'ja');
    expect(p.scenarios).toHaveLength(0);
    expect(testPlanToMarkdown(p)).toContain('OBJECTIVE');
  });
});
