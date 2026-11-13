import { describe, expect, it } from 'vitest';
import { analyzeResolvedProject, resolveProject } from '../../cli/analyze';
import { diffProjects } from '../../cli/diff';
import { cveFinding, makeProject } from '../../cli/__fixtures__/findingsPriorityProject';
import { getChangeTriggers } from '../../change-triggers/loader/bundledChangeTriggers';
import type { DiagramNode, LayerData, LayerKey, ThreatView } from '../../core/model/types';
import { buildEventLog, ACTIVITY, type EventLogModel } from './buildEventLog';
import { toEventCsv } from './eventCsv';
import { OcelLogSchema, toOcelJson } from './ocel';
import type { ModelSnapshot } from './types';

interface FakeModel extends EventLogModel {
  threats: ThreatView[];
}

const LAYERS: LayerKey[] = ['L0', 'L1', 'L2', 'L3', 'PQC'];
const node = (id: string, seq: number, extra: Partial<DiagramNode> = {}): DiagramNode =>
  ({ id, seq, type: 'DB', x: 0, y: 0, label: id, ...extra }) as DiagramNode;
function model(nodes: DiagramNode[], threats: ThreatView[], extra: Partial<FakeModel> = {}): FakeModel {
  const layers = Object.fromEntries(
    LAYERS.map((k) => [k, { nodes: k === 'L1' ? nodes : [], edges: [], boundaries: [], annotations: [] } satisfies LayerData]),
  ) as unknown as Record<LayerKey, LayerData>;
  return { layers, suppressions: {}, threats, ...extra };
}
const threat = (id: string, nodeId: string, severity: ThreatView['severity']): ThreatView =>
  ({
    id,
    ruleId: 'rule-x',
    canonicalId: 'canon-x',
    nodeId,
    subject: { kind: 'node', id: nodeId },
    framework: 'STRIDE',
    category: 'Tampering',
    name: `脅威 ${id}`,
    severity,
    description: '',
    origin: 'detected',
  }) as ThreatView;
const snap = (rev: string, time: string, raw: FakeModel, author?: string): ModelSnapshot => ({
  revision: rev.padEnd(40, '0'),
  time,
  author,
  message: `commit ${rev}`,
  raw,
});

const deps = {
  resolve: (raw: unknown) => {
    if (!raw || typeof raw !== 'object') throw new Error('不正');
    return raw as FakeModel;
  },
  analyze: (m: FakeModel) => [{ layer: 'L1' as LayerKey, threats: m.threats }],
  appVersion: '9.9.9',
};

const T1 = 'L1:t1';
function scenario(): ModelSnapshot[] {
  const web = node('web', 1, { label: '公開サーバー', type: 'FRONT_END_SERVER' });
  const db = node('db', 2);
  const s1 = model([web, db], [threat('t1', 'web', 'High'), threat('t2', 'db', 'Medium')]);
  const s2 = model([web, { ...db, description: '更新' }], [threat('t1', 'web', 'High'), threat('t2', 'db', 'Critical')], {
    suppressions: { t1: { status: 'accepted', note: '=受容, "理由"', at: Date.parse('2026-11-02T10:30:00Z') } },
    controlStatuses: { t2: { status: 'implemented', note: '対策済み', at: Date.parse('2026-10-01T00:00:00Z'), by: 'carol' } },
    findings: [cveFinding('f1', 'web', 'High', 'CVE-2099-0001', { observedAt: '2026-11-02T10:45:00Z' })] as never,
  });
  const s3 = model([{ ...web, x: 500, label: '公開サーバー(改)' }, { ...db, description: '更新' }], [threat('t2', 'db', 'Critical')], {
    controlStatuses: { t2: { status: 'implemented', note: '対策済み', at: Date.parse('2026-10-01T00:00:00Z'), by: 'carol' } },
  });
  return [snap('aaa', '2026-11-02T10:00:00Z', s1, 'alice'), snap('bbb', '2026-11-02T11:00:00Z', s2, 'bob'), snap('ccc', '2026-11-02T12:00:00Z', s3, 'alice')];
}

const acts = (log: ReturnType<typeof buildEventLog>, activity: string) => log.events.filter((e) => e.activity === activity);

describe('buildEventLog', () => {
  const log = buildEventLog(scenario(), deps);

  it('最初の版は空との差：構成要素の追加と脅威の検出。作者が資源、版の時刻が時刻', () => {
    const first = log.events.filter((e) => e.attributes.commit === 'aaa'.padEnd(40, '0'));
    expect(first.filter((e) => e.activity === ACTIVITY.nodeAdded)).toHaveLength(2);
    const det = acts(log, ACTIVITY.detected);
    expect(det.map((e) => e.relations[0].objectId).sort()).toEqual(['L1:t1', 'L1:t2']);
    expect(det[0]).toMatchObject({ time: '2026-11-02T10:00:00.000Z', attributes: { resource: 'alice', analysis_version: '9.9.9', commit_message: 'commit aaa' } });
  });

  it('対応方針：at が窓の中ならその時刻、作者が資源', () => {
    const d = acts(log, ACTIVITY.decision);
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ time: '2026-11-02T10:30:00.000Z', attributes: { status: 'accepted', resource: 'bob', severity: 'High' } });
    expect(d[0].relations.map((r) => r.objectId)).toContain(T1);
  });

  it('対策の状況：at が窓の外ならコミット時刻、by が資源', () => {
    const c = acts(log, ACTIVITY.control);
    expect(c).toHaveLength(1);
    expect(c[0]).toMatchObject({ time: '2026-11-02T11:00:00.000Z', attributes: { status: 'implemented', note: '対策済み', resource: 'carol' } });
  });

  it('重大度の変更・脅威の解消・対応方針の取り消し', () => {
    expect(acts(log, ACTIVITY.severityChanged)[0].attributes).toMatchObject({ severity: 'Critical', previous_severity: 'Medium' });
    expect(acts(log, ACTIVITY.resolved).map((e) => e.relations[0].objectId)).toEqual([T1]);
    expect(acts(log, ACTIVITY.decisionRevoked)[0].attributes).toMatchObject({ previous_status: 'accepted' });
    const t2 = log.objects.find((o) => o.id === 'L1:t2');
    expect(t2?.attributes.filter((a) => a.name === 'severity').map((a) => a.value)).toEqual(['Medium', 'Critical']);
  });

  it('指摘：観測時刻で取り込み、消えたら記録。ノードに関連', () => {
    const imp = acts(log, ACTIVITY.findingImported);
    expect(imp[0].time).toBe('2026-11-02T10:45:00.000Z');
    expect(imp[0].relations.map((r) => r.objectId)).toEqual(['finding:f1', 'L1:web']);
    expect(acts(log, ACTIVITY.findingGone)).toHaveLength(1);
  });

  it('構成要素：x/y だけの変更は無視、他の項目の変更は項目名つき', () => {
    const ch = acts(log, ACTIVITY.nodeChanged);
    expect(ch.map((e) => [e.relations[0].objectId, e.attributes.changed_fields])).toEqual([
      ['L1:db', 'description'],
      ['L1:web', 'label'],
    ]);
    const web = log.objects.find((o) => o.id === 'L1:web');
    expect(web?.attributes.filter((a) => a.name === 'label').map((a) => a.value)).toEqual(['公開サーバー', '公開サーバー(改)']);
  });

  it('同じ入力から同じ結果（イベント ID は決定的）。ID は一意', () => {
    expect(buildEventLog(scenario(), deps)).toEqual(log);
    expect(new Set(log.events.map((e) => e.id)).size).toBe(log.events.length);
  });

  it('読み込めない版は飛ばして報告し、残りの版で続ける', () => {
    const bad = { ...snap('bad', '2026-11-02T10:30:00Z', model([], [])), raw: null };
    const out = buildEventLog([scenario()[0], bad, scenario()[1]], deps);
    expect(out.versions).toBe(2);
    expect(out.skipped).toHaveLength(1);
    expect(out.skipped[0]).toContain('bad');
  });
});

describe('toOcelJson', () => {
  const log = buildEventLog(scenario(), deps);
  const ocel = toOcelJson(log);

  it('OCEL 2.0 の形・参照の整合を満たす', () => {
    expect(OcelLogSchema.safeParse(ocel).success).toBe(true);
    expect(ocel.events.every((e) => e.relationships.length >= 1)).toBe(true);
    expect(ocel.objects.find((o) => o.id === 'L1:t1')?.relationships).toEqual([{ objectId: 'L1:web', qualifier: '対象の要素' }]);
  });

  it('スキーマは不整合を検出する', () => {
    const broken = structuredClone(ocel);
    broken.events[0].relationships = [];
    expect(OcelLogSchema.safeParse(broken).success).toBe(false);
    const undeclared = structuredClone(ocel);
    undeclared.events[0].type = '宣言なし';
    expect(OcelLogSchema.safeParse(undeclared).success).toBe(false);
    const dangling = structuredClone(ocel);
    dangling.events[0].relationships = [{ objectId: 'nope', qualifier: 'x' }];
    expect(OcelLogSchema.safeParse(dangling).success).toBe(false);
  });
});

describe('toEventCsv', () => {
  const csv = toEventCsv(buildEventLog(scenario(), deps));
  const lines = csv.trimEnd().split('\r\n');

  it('ヘッダーと、脅威に関連するイベントだけの行', () => {
    expect(lines[0]).toBe('case_id,activity,timestamp,resource,severity,rule_id,canonical_id,threat_name,element,element_label,element_type,layer,status,note,commit,commit_message');
    expect(csv).not.toContain('構成要素の追加');
    expect(csv).not.toContain('指摘の取り込み');
    expect(lines.some((l) => l.startsWith('L1:t1,脅威を検出,2026-11-02T10:00:00.000Z,alice,High,rule-x,canon-x,脅威 t1,C1,公開サーバー,FRONT_END_SERVER,L1'))).toBe(true);
  });

  it('カンマ・引用符は引用、式の先頭文字は無害化', () => {
    const row = lines.find((l) => l.includes('対応方針の決定'));
    expect(row).toContain(`"'=受容, ""理由"""`);
  });
});

describe('実際の解析（現在の脅威ライブラリ）', () => {
  const realDeps = {
    resolve: resolveProject,
    analyze: (m: ReturnType<typeof resolveProject>) => analyzeResolvedProject(m, { framework: 'ALL', locale: 'ja' }),
    triggerIds: (a: unknown, b: unknown) => diffProjects(a, b, { locale: 'ja', triggers: getChangeTriggers('ja').triggers }).triggerHits.map((h) => h.triggerId),
    appVersion: 'test',
  };
  const p1 = makeProject([]);
  const p2 = makeProject([cveFinding('f1', 'web', 'High', 'CVE-2099-0001')]);

  it('脅威が検出され、OCEL・CSV が妥当', () => {
    const log = buildEventLog(
      [
        { revision: 'a'.repeat(40), time: '2026-11-01T00:00:00Z', author: 'alice', raw: p1 },
        { revision: 'b'.repeat(40), time: '2026-11-02T00:00:00Z', author: 'bob', raw: p2 },
      ],
      realDeps,
    );
    expect(log.versions).toBe(2);
    expect(acts(log, ACTIVITY.detected).length).toBeGreaterThan(0);
    expect(acts(log, ACTIVITY.findingImported)).toHaveLength(1);
    expect(OcelLogSchema.safeParse(toOcelJson(log)).success).toBe(true);
    expect(toEventCsv(log).split('\r\n')[1]).toContain('脅威を検出');
  });
});
