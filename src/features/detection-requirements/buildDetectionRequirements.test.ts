import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parse as parseYaml } from 'yaml';
import { buildDetectionRequirements, type DetectionRequirementsInput } from './buildDetectionRequirements';
import { detectionRequirementsToJson, detectionRequirementsToMarkdown } from './detectionRequirementsOutput';
import { BUNDLED_DETECTION_OVERLAY_EN, getDetectionRequirements, loadDetectionRequirements } from './requirements';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';
import { EMPTY_PROJECT_META, type DiagramEdge, type DiagramNode, type ThreatView } from '../../core/model/types';

const NOW = new Date('2026-11-07T12:00:00Z');

describe('detection requirements data', () => {
  const text = readFileSync('data/detection-requirements/detection.yaml', 'utf-8');

  it('YAML がスキーマを通り、canonicalId はすべて同梱の脅威ライブラリに実在し、25 件以上ある', () => {
    const list = loadDetectionRequirements(text);
    expect(list.length).toBeGreaterThanOrEqual(25);
    const known = new Set(BUNDLED_THREAT_LIBRARY.rules.map((r) => r.canonicalId));
    for (const v of list) for (const c of v.match.canonicalIds) expect(known.has(c), `${v.id}: ${c}`).toBe(true);
  });

  it('id の重複・canonicalId の重複登録は読み込みに失敗する', () => {
    const one = (id: string, c: string) =>
      `  - id: ${id}\n    match: { canonicalIds: [${c}] }\n    title: t\n    watch: [w]\n    logs: [l]\n`;
    const head = 'schemaVersion: 1\nrequirements:\n';
    expect(() => loadDetectionRequirements(`${head}${one('a', 'x')}${one('a', 'y')}`)).toThrow(/duplicate/);
    expect(() => loadDetectionRequirements(`${head}${one('a', 'x')}${one('b', 'x')}`)).toThrow(/canonicalId/);
  });

  it('英語オーバーレイのキーは原本に存在し、watch / logs の数が一致する', () => {
    const ja = getDetectionRequirements('ja');
    const overlay = parseYaml(BUNDLED_DETECTION_OVERLAY_EN ?? '') as {
      requirements: Record<string, { title?: string; watch?: string[]; logs?: string[] }>;
    };
    const byId = new Map(ja.map((v) => [v.id, v]));
    for (const [id, o] of Object.entries(overlay.requirements)) {
      const orig = byId.get(id);
      expect(orig, id).toBeDefined();
      if (o.watch) expect(o.watch.length, id).toBe(orig!.watch.length);
      if (o.logs) expect(o.logs.length, id).toBe(orig!.logs.length);
    }
    const en = getDetectionRequirements('en');
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

/** a(攻撃者) → gw → api(logSinkId=siem: 転送あり) → db(未入力)。iot は経路外。 */
function handInput(withAttacker = true): DetectionRequirementsInput {
  return {
    nodes: [
      node('a', 1, 'THREAT_ACTOR', withAttacker ? { attackObjectiveId: 'db' } : {}),
      node('gw', 2, 'GATEWAY'),
      node('api', 3, 'BACKEND_API', { logSinkId: 'siem' }),
      node('db', 4, 'DATABASE', { posture: { logCollection: 'Collected' } }),
      node('siem', 5, 'SIEM'),
    ],
    edges: [edge('e1', 1, 'a', 'gw'), edge('e2', 2, 'gw', 'api'), edge('e3', 3, 'api', 'db')],
    threats: [
      threat('t1', 'api', 'web-shell-implant'),
      threat('t2', 'api', 'known-vulnerability-unpatched'),
      threat('t3', 'db', 'data-store-tampering'),
      threat('t4', 'db', 'private-endpoint-data-exfiltration', { suppression: { status: 'false-positive', note: '', at: 0 } }),
      threat('t5', 'siem', 'web-shell-implant'),
    ],
    projectMeta: { ...EMPTY_PROJECT_META, systemName: 'Demo' },
    layer: 'L1',
  };
}

describe('buildDetectionRequirements', () => {
  it('攻撃者あり: 経路上のノードだけが載り、同じ要件は 1 件にまとまり、誤検知は除かれる', () => {
    const d = buildDetectionRequirements(handInput(), NOW, 'ja');
    expect(d.generatedAt).toBe('2026-11-07');
    expect(d.pathBased).toBe(true);
    expect(d.nodes.map((n) => n.id).sort()).toEqual(['C2', 'C3', 'C4']);
    const api = d.nodes.find((n) => n.id === 'C3')!;
    expect(api.requirements.map((r) => r.id)).toEqual(['web-exploit-and-shell']);
    expect(api.requirements[0].threatNames).toEqual(['t1', 't2']);
    const db = d.nodes.find((n) => n.id === 'C4')!;
    expect(db.requirements.map((r) => r.id)).toEqual(['data-store-access']);
    expect(db.requirements[0].threatNames).toEqual(['t3']);
  });

  it('ログの状態: 送信先あり=forwarded、ローカルのみ=localOnly、未入力=none（assumed）', () => {
    const d = buildDetectionRequirements(handInput(), NOW, 'ja');
    const log = (id: string) => d.nodes.find((n) => n.id === id)!.log;
    expect(log('C3')).toEqual({ state: 'forwarded', assumed: false });
    expect(log('C4')).toEqual({ state: 'localOnly', assumed: false });
    expect(log('C2')).toEqual({ state: 'none', assumed: true });
  });

  it('経路ごとに、ログが監視先に届かない区間を列挙する', () => {
    const d = buildDetectionRequirements(handInput(), NOW, 'ja');
    expect(d.routes).toHaveLength(1);
    expect(d.routes[0].gaps).toEqual([['C2'], ['C4']]);
    expect(d.routes[0].blind).toBe(false);
  });

  it('攻撃者なし: 全ノード対象で優先度なし', () => {
    const d = buildDetectionRequirements(handInput(false), NOW, 'ja');
    expect(d.pathBased).toBe(false);
    expect(d.routes).toEqual([]);
    expect(d.nodes.every((n) => n.routeHits === null)).toBe(true);
    expect(d.nodes.map((n) => n.id)).toContain('C5');
  });

  it('Markdown は「検知できる」と書かず、ログが届かない区間を所定の言い回しで示す。英語にも切り替わる', () => {
    const ja = detectionRequirementsToMarkdown(buildDetectionRequirements(handInput(), NOW, 'ja'));
    expect(ja).toContain('監視すべき振る舞い');
    expect(ja).toContain('必要なログ');
    expect(ja).toContain('この区間はログが監視先に届かない（届くかは未確認／未入力）: C2');
    expect(ja).not.toMatch(/検知できます|検知できる。/);
    const en = detectionRequirementsToMarkdown(buildDetectionRequirements(handInput(), NOW, 'en'));
    expect(en).toContain('Behaviors to monitor');
    expect(en).toContain('Logs needed');
  });

  it('JSON は構造をそのまま出す', () => {
    const json = JSON.parse(detectionRequirementsToJson(buildDetectionRequirements(handInput(), NOW, 'ja')));
    expect(json.routes[0].gaps).toEqual([['C2'], ['C4']]);
    expect(json.nodes[0]).toHaveProperty('requirements');
  });
});
