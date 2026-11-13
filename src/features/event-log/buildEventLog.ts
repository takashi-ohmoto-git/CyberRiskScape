import { formatElementalId } from '../../core/model/elementalId';
import { effectiveSeverity } from '../../core/model/risk';
import type {
  ControlStatusState,
  DiagramNode,
  Finding,
  LayerData,
  LayerKey,
  Severity,
  SuppressionState,
  ThreatView,
} from '../../core/model/types';
import type { ModelSnapshot } from './types';

/**
 * 脅威・指摘への対応のイベントログ（プロセスマイニング用）を、モデル JSON の版の列から組み立てる純粋関数
 * （docs/log §2.136）。DOM にも Node にも依存しない。解析（読み込み・脅威検出）は deps で受け取る。
 *
 * 重要：**全ての版を「現在の」脅威ライブラリで解析する**。ライブラリは版ごとに変わるが過去の版の
 * ライブラリは再現しないため、脅威の出現・解消は「図の変更」だけで起きる（ルールの追加・変更の影響を
 * 混ぜない）。使った版は各イベントの属性 `analysis_version` に記録する。
 *
 * 版どうしを順に比べ（最初の版は空と比べる）、イベントを出す。同じ入力からは同じ ID・同じ並びになる。
 */

export type AttrValue = string | number | boolean;
export type AttrType = 'string' | 'time' | 'integer' | 'float' | 'boolean';
export interface AttrDef {
  name: string;
  type: AttrType;
}
export interface LogRelation {
  objectId: string;
  qualifier: string;
}
export interface LogObject {
  id: string;
  type: string;
  /** 時刻つきの属性（OCEL 2.0 の objects.attributes）。値が変わるたびに足す。 */
  attributes: { name: string; time: string; value: AttrValue }[];
  relations: LogRelation[];
}
export interface LogEvent {
  id: string;
  activity: string;
  /** ISO 8601（UTC）。 */
  time: string;
  attributes: Record<string, AttrValue>;
  relations: LogRelation[];
}
export interface EventLog {
  /** 解析に使ったアプリ（脅威ライブラリ）の版。 */
  appVersion: string;
  /** 読み込めた版の数。 */
  versions: number;
  /** 飛ばした版と理由。 */
  skipped: string[];
  /** 実行トリガーを付けられなかった等の注意。 */
  notes: string[];
  objectTypes: { name: string; attributes: AttrDef[] }[];
  eventTypes: { name: string; attributes: AttrDef[] }[];
  objects: LogObject[];
  events: LogEvent[];
}

/** 解析に必要な最小の形（`ResolvedProject` がそのまま満たす）。 */
export interface EventLogModel {
  layers: Record<LayerKey, LayerData>;
  suppressions: Record<string, SuppressionState>;
  controlStatuses?: Record<string, ControlStatusState>;
  findings?: Finding[];
}

export interface EventLogDeps<M extends EventLogModel> {
  /** 保存済みプロジェクト JSON → 解析できる状態。不正なら例外（その版は飛ばす）。 */
  resolve(raw: unknown): M;
  /** 全レイヤーの脅威（framework は ALL）。 */
  analyze(model: M): { layer: LayerKey; threats: ThreatView[] }[];
  /** 2 つの版の差から該当する実行トリガー（T1〜T8）の ID。省略可。例外は握りつぶして注意に積む。 */
  triggerIds?(baseRaw: unknown, headRaw: unknown): string[];
  /** package.json の version。 */
  appVersion: string;
}

// ── 名前の定義 ──────────────────────────────────────────

export const OBJECT_TYPE = { threat: '脅威', finding: '指摘', node: '構成要素' } as const;
export const ACTIVITY = {
  detected: '脅威を検出',
  resolved: '脅威が解消',
  severityChanged: '重大度の変更',
  decision: '対応方針の決定',
  decisionRevoked: '対応方針の取り消し',
  control: '対策の状況の変更',
  controlRevoked: '対策の状況の取り消し',
  findingImported: '指摘の取り込み',
  findingGone: '指摘が消えた',
  nodeAdded: '構成要素の追加',
  nodeRemoved: '構成要素の削除',
  nodeChanged: '構成要素の変更',
} as const;
export const QUALIFIER = { eventThreat: '対象', eventNode: '要素', eventFinding: '対象', objectNode: '対象の要素' } as const;

const s = (name: string): AttrDef => ({ name, type: 'string' });
const COMMON = [s('resource'), s('commit'), s('commit_message'), s('analysis_version')];

export const OBJECT_TYPE_DEFS: EventLog['objectTypes'] = [
  {
    name: OBJECT_TYPE.threat,
    attributes: ['rule_id', 'canonical_id', 'name', 'framework', 'category', 'layer', 'element_id', 'element_label', 'element_type', 'severity'].map(s),
  },
  { name: OBJECT_TYPE.finding, attributes: ['product', 'format', 'rule_id', 'severity', 'title'].map(s) },
  { name: OBJECT_TYPE.node, attributes: ['type', 'label', 'business_criticality'].map(s) },
];

const A = ACTIVITY;
export const EVENT_TYPE_DEFS: EventLog['eventTypes'] = [
  [A.detected, ['severity']],
  [A.resolved, ['severity']],
  [A.severityChanged, ['severity', 'previous_severity']],
  [A.decision, ['severity', 'status', 'note']],
  [A.decisionRevoked, ['severity', 'previous_status']],
  [A.control, ['severity', 'status', 'note']],
  [A.controlRevoked, ['severity', 'previous_status']],
  [A.findingImported, ['severity']],
  [A.findingGone, ['severity']],
  [A.nodeAdded, ['changed_fields', 'triggers']],
  [A.nodeRemoved, ['changed_fields', 'triggers']],
  [A.nodeChanged, ['changed_fields', 'triggers']],
].map(([name, extra]) => ({ name: name as string, attributes: [...COMMON, ...(extra as string[]).map(s)] }));

// ── 補助 ────────────────────────────────────────────────

interface ElementInfo {
  id: string;
  label: string;
  type: string;
}

function elementInfo(view: ThreatView, data: LayerData): ElementInfo {
  const ref = view.subject ?? { kind: 'node' as const, id: view.nodeId };
  if (ref.kind === 'edge') {
    const e = data.edges.find((x) => x.id === ref.id);
    return { id: e?.seq != null ? formatElementalId('edge', e.seq) : ref.id, label: e?.dataFlowName?.trim() ?? '', type: 'DataFlow' };
  }
  if (ref.kind === 'boundary') {
    const b = data.boundaries.find((x) => x.id === ref.id);
    return {
      id: b?.seq != null ? formatElementalId('boundary', b.seq) : ref.id,
      label: b?.label?.trim() || b?.vlanName?.trim() || '',
      type: b?.type ?? 'Boundary',
    };
  }
  const n = data.nodes.find((x) => x.id === ref.id);
  return { id: n?.seq != null ? formatElementalId('node', n.seq) : ref.id, label: n?.label?.trim() || '', type: n?.type ?? '' };
}

/** キーを並べ替えた JSON（順序の違いを差にしない）。 */
function stable(v: unknown): string {
  return JSON.stringify(v, (_k, val: unknown) =>
    val && typeof val === 'object' && !Array.isArray(val)
      ? Object.fromEntries(Object.entries(val as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : val,
  );
}

function changedFields(a: DiagramNode, b: DiagramNode): string[] {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  const out: string[] = [];
  for (const k of [...keys].sort()) {
    if (k === 'x' || k === 'y') continue;
    if (stable((a as unknown as Record<string, unknown>)[k]) !== stable((b as unknown as Record<string, unknown>)[k])) out.push(k);
  }
  return out;
}

/** 記録された時刻（epoch ms）が (前の版, この版] に収まれば採用、外れればこの版の時刻。 */
function pickTime(at: number | undefined, prevMs: number | undefined, curMs: number): number {
  if (typeof at === 'number' && Number.isFinite(at) && at <= curMs && (prevMs === undefined || at > prevMs)) return at;
  return curMs;
}

const iso = (ms: number) => new Date(ms).toISOString();
const same = (a: object | undefined, b: object) => stable(a) === stable(b);

interface ThreatState {
  key: string;
  layer: LayerKey;
  view: ThreatView;
  severity: Severity;
}
interface Cur<M> {
  model: M;
  raw: unknown;
  threats: Map<string, ThreatState>;
  nodes: Map<string, DiagramNode>;
  findings: Map<string, Finding>;
}

// ── 本体 ────────────────────────────────────────────────

export function buildEventLog<M extends EventLogModel>(snapshots: ModelSnapshot[], deps: EventLogDeps<M>): EventLog {
  const objects = new Map<string, LogObject>();
  const events: LogEvent[] = [];
  const eventIds = new Set<string>();
  const skipped: string[] = [];
  const notes: string[] = [];
  const lastSeverity = new Map<string, string>();
  const keyByRawId = new Map<string, string>();
  let triggerFailed = false;

  const addRel = (o: LogObject, objectId: string, qualifier: string) => {
    if (!o.relations.some((r) => r.objectId === objectId && r.qualifier === qualifier)) o.relations.push({ objectId, qualifier });
  };

  const ensureNode = (layer: LayerKey, node: DiagramNode, timeMs: number): string => {
    const id = `${layer}:${node.id}`;
    if (!objects.has(id)) {
      const t = iso(timeMs);
      const attrs: LogObject['attributes'] = [
        { name: 'type', time: t, value: node.type },
        { name: 'label', time: t, value: node.label?.trim() ?? '' },
      ];
      if (node.businessContext) attrs.push({ name: 'business_criticality', time: t, value: node.businessContext.criticality });
      objects.set(id, { id, type: OBJECT_TYPE.node, attributes: attrs, relations: [] });
    }
    return id;
  };

  const ensureThreat = (st: ThreatState, data: LayerData, nodes: Map<string, DiagramNode>, timeMs: number): string => {
    const id = st.key;
    const t = iso(timeMs);
    if (!objects.has(id)) {
      const el = elementInfo(st.view, data);
      const v = st.view;
      const attrs: LogObject['attributes'] = [
        ['rule_id', v.ruleId ?? ''],
        ['canonical_id', v.canonicalId ?? ''],
        ['name', v.name ?? v.category],
        ['framework', v.framework],
        ['category', v.category],
        ['layer', st.layer],
        ['element_id', el.id],
        ['element_label', el.label],
        ['element_type', el.type],
      ].map(([name, value]) => ({ name, time: t, value }));
      const o: LogObject = { id, type: OBJECT_TYPE.threat, attributes: attrs, relations: [] };
      const node = (v.subject?.kind ?? 'node') === 'node' ? nodes.get(`${st.layer}:${v.subject?.id ?? v.nodeId}`) : undefined;
      if (node) addRel(o, ensureNode(st.layer, node, timeMs), QUALIFIER.objectNode);
      objects.set(id, o);
    }
    if (lastSeverity.get(id) !== st.severity) {
      objects.get(id)?.attributes.push({ name: 'severity', time: t, value: st.severity });
      lastSeverity.set(id, st.severity);
    }
    return id;
  };

  /** 図に現れなかった脅威への対応方針などのための最小のオブジェクト。 */
  const ensureBareThreat = (key: string, rawId: string, timeMs: number): string => {
    if (!objects.has(key)) {
      objects.set(key, {
        id: key,
        type: OBJECT_TYPE.threat,
        attributes: [{ name: 'name', time: iso(timeMs), value: rawId }],
        relations: [],
      });
    }
    return key;
  };

  const emit = (
    snap: ModelSnapshot,
    activity: string,
    timeMs: number,
    resource: string | undefined,
    attrs: Record<string, AttrValue | undefined>,
    relations: LogRelation[],
    idKey: string,
  ) => {
    const base = `${snap.revision.slice(0, 12)}:${activity}:${idKey}`;
    let id = base;
    for (let n = 2; eventIds.has(id); n++) id = `${base}#${n}`;
    eventIds.add(id);
    const attributes: Record<string, AttrValue> = {};
    if (resource) attributes.resource = resource;
    attributes.commit = snap.revision;
    if (snap.message) attributes.commit_message = snap.message;
    attributes.analysis_version = deps.appVersion;
    for (const [k, v] of Object.entries(attrs)) if (v !== undefined && v !== '') attributes[k] = v;
    events.push({ id, activity, time: iso(timeMs), attributes, relations });
  };

  let prev: (Cur<M> & { ms: number }) | undefined;
  let versions = 0;

  for (const snap of snapshots) {
    const short = snap.revision.slice(0, 12);
    const curMs = Date.parse(snap.time);
    if (!Number.isFinite(curMs)) {
      skipped.push(`${short}：コミット時刻が不正なため飛ばしました。`);
      continue;
    }
    let cur: Cur<M>;
    try {
      const model = deps.resolve(snap.raw);
      const threats = new Map<string, ThreatState>();
      for (const r of deps.analyze(model)) {
        for (const view of r.threats) {
          const key = `${r.layer}:${view.id}`;
          threats.set(key, { key, layer: r.layer, view, severity: effectiveSeverity(view) });
          keyByRawId.set(view.id, key);
        }
      }
      const nodes = new Map<string, DiagramNode>();
      for (const layer of Object.keys(model.layers) as LayerKey[]) {
        for (const n of model.layers[layer].nodes) nodes.set(`${layer}:${n.id}`, n);
      }
      cur = { model, raw: snap.raw, threats, nodes, findings: new Map((model.findings ?? []).map((f) => [f.id, f])) };
    } catch (e) {
      skipped.push(`${short}：読み込めないため飛ばしました（${e instanceof Error ? e.message : String(e)}）。`);
      continue;
    }
    versions++;
    const author = snap.author;
    const prevMs = prev?.ms;
    const empty = { threats: new Map<string, ThreatState>(), nodes: new Map<string, DiagramNode>(), findings: new Map<string, Finding>() };
    const before = prev ?? empty;
    const dataOf = (st: ThreatState) => cur.model.layers[st.layer];
    const prevDataOf = (st: ThreatState) => prev?.model.layers[st.layer] ?? dataOf(st);
    const sevNow = (key: string) => cur.threats.get(key)?.severity ?? lastSeverity.get(key);

    // 脅威
    for (const [key, st] of cur.threats) {
      const p = before.threats.get(key);
      const oid = ensureThreat(st, dataOf(st), cur.nodes, curMs);
      const rels = threatRels(oid, st, cur.nodes);
      if (!p) {
        emit(snap, ACTIVITY.detected, curMs, author, { severity: st.severity }, rels, oid);
      } else if (p.severity !== st.severity) {
        emit(snap, ACTIVITY.severityChanged, curMs, author, { severity: st.severity, previous_severity: p.severity }, rels, oid);
      }
    }
    for (const [key, st] of before.threats) {
      if (cur.threats.has(key)) continue;
      const oid = ensureThreat(st, prevDataOf(st), before.nodes, prevMs ?? curMs);
      emit(snap, ACTIVITY.resolved, curMs, author, { severity: st.severity }, threatRels(oid, st, before.nodes), oid);
    }

    // 対応方針・対策の状況
    const allNodes = new Map([...before.nodes, ...cur.nodes]);
    const objectOfRaw = (rawId: string): { oid: string; rels: LogRelation[] } => {
      const key = keyByRawId.get(rawId) ?? `unknown:${rawId}`;
      const inCur = cur.threats.get(key);
      const st = inCur ?? before.threats.get(key);
      if (!st) {
        const oid = ensureBareThreat(key, rawId, curMs);
        return { oid, rels: [{ objectId: oid, qualifier: QUALIFIER.eventThreat }] };
      }
      const oid = ensureThreat(st, inCur ? dataOf(st) : prevDataOf(st), allNodes, curMs);
      return { oid, rels: threatRels(oid, st, allNodes) };
    };
    const beforeSup = prev?.model.suppressions ?? {};
    for (const [rawId, sup] of Object.entries(cur.model.suppressions)) {
      const p = beforeSup[rawId];
      if (p && same(p, sup)) continue;
      const { oid, rels } = objectOfRaw(rawId);
      emit(snap, ACTIVITY.decision, pickTime(sup.at, prevMs, curMs), author, { severity: sevNow(oid), status: sup.status, note: sup.note }, rels, oid);
    }
    for (const [rawId, p] of Object.entries(beforeSup)) {
      if (cur.model.suppressions[rawId]) continue;
      const { oid, rels } = objectOfRaw(rawId);
      emit(snap, ACTIVITY.decisionRevoked, curMs, author, { severity: sevNow(oid), previous_status: p.status }, rels, oid);
    }
    const curCtl = cur.model.controlStatuses ?? {};
    const beforeCtl = prev?.model.controlStatuses ?? {};
    for (const [rawId, c] of Object.entries(curCtl)) {
      const p = beforeCtl[rawId];
      if (p && same(p, c)) continue;
      const { oid, rels } = objectOfRaw(rawId);
      emit(snap, ACTIVITY.control, pickTime(c.at, prevMs, curMs), c.by ?? author, { severity: sevNow(oid), status: c.status, note: c.note }, rels, oid);
    }
    for (const [rawId, p] of Object.entries(beforeCtl)) {
      if (curCtl[rawId]) continue;
      const { oid, rels } = objectOfRaw(rawId);
      emit(snap, ACTIVITY.controlRevoked, curMs, p.by ?? author, { severity: sevNow(oid), previous_status: p.status }, rels, oid);
    }

    // 指摘
    const findingObject = (f: Finding, nodes: Map<string, DiagramNode>, timeMs: number): { oid: string; rels: LogRelation[] } => {
      const oid = `finding:${f.id}`;
      const o: LogObject = objects.get(oid) ?? {
        id: oid,
        type: OBJECT_TYPE.finding,
        attributes: [
          ['product', f.source.product],
          ['format', f.source.format],
          ['rule_id', f.identifiers[0]?.value ?? f.externalId],
          ['severity', f.severity],
          ['title', f.title ?? ''],
        ].map(([name, value]) => ({ name, time: iso(timeMs), value })),
        relations: [],
      };
      objects.set(oid, o);
      const rels: LogRelation[] = [{ objectId: oid, qualifier: QUALIFIER.eventFinding }];
      const node = f.subject ? nodes.get(`${f.subject.layer}:${f.subject.nodeId}`) : undefined;
      if (f.subject && node) {
        const nid = ensureNode(f.subject.layer, node, timeMs);
        addRel(o, nid, QUALIFIER.objectNode);
        rels.push({ objectId: nid, qualifier: QUALIFIER.eventNode });
      }
      return { oid, rels };
    };
    for (const [id, f] of cur.findings) {
      if (before.findings.has(id)) continue;
      const { oid, rels } = findingObject(f, cur.nodes, curMs);
      const obs = f.observedAt ? Date.parse(f.observedAt) : NaN;
      emit(snap, ACTIVITY.findingImported, Number.isFinite(obs) ? obs : curMs, author, { severity: f.severity }, rels, oid);
    }
    for (const [id, f] of before.findings) {
      if (cur.findings.has(id)) continue;
      const { oid, rels } = findingObject(f, before.nodes, prevMs ?? curMs);
      emit(snap, ACTIVITY.findingGone, curMs, author, { severity: f.severity }, rels, oid);
    }

    // 構成要素
    let triggers: string | undefined;
    const nodeTriggers = (): string | undefined => {
      if (!prev || !deps.triggerIds) return undefined;
      if (triggers === undefined) {
        try {
          triggers = deps.triggerIds(prev.raw, cur.raw).join(',');
        } catch (e) {
          triggers = '';
          if (!triggerFailed) {
            triggerFailed = true;
            notes.push(`実行トリガーを判定できない版がありました（${short}：${e instanceof Error ? e.message : String(e)}）。`);
          }
        }
      }
      return triggers;
    };
    const nodeEvent = (activity: string, key: string, node: DiagramNode, fields: string[]) => {
      const layer = key.slice(0, key.indexOf(':')) as LayerKey;
      const oid = ensureNode(layer, node, curMs);
      const o = objects.get(oid);
      const t = iso(curMs);
      if (o && activity === ACTIVITY.nodeChanged) {
        const lastOf = (name: string) => [...o.attributes].reverse().find((a) => a.name === name)?.value;
        const label = node.label?.trim() ?? '';
        if (lastOf('label') !== label) o.attributes.push({ name: 'label', time: t, value: label });
        const crit = node.businessContext?.criticality ?? '';
        if ((lastOf('business_criticality') ?? '') !== crit) o.attributes.push({ name: 'business_criticality', time: t, value: crit });
      }
      emit(snap, activity, curMs, author, { changed_fields: fields.join(','), triggers: nodeTriggers() }, [{ objectId: oid, qualifier: QUALIFIER.eventNode }], oid);
    };
    for (const [key, n] of cur.nodes) {
      const p = before.nodes.get(key);
      if (!p) nodeEvent(ACTIVITY.nodeAdded, key, n, []);
      else {
        const f = changedFields(p, n);
        if (f.length > 0) nodeEvent(ACTIVITY.nodeChanged, key, n, f);
      }
    }
    for (const [key, n] of before.nodes) if (!cur.nodes.has(key)) nodeEvent(ACTIVITY.nodeRemoved, key, n, []);

    prev = { ...cur, ms: curMs };
  }

  // 同じ時刻はそのままの順（Array.sort は安定）。
  events.sort((a, b) => Date.parse(a.time) - Date.parse(b.time));
  if (!deps.triggerIds) notes.push('実行トリガー（T1〜T8）は付けていません。');
  return {
    appVersion: deps.appVersion,
    versions,
    skipped,
    notes,
    objectTypes: OBJECT_TYPE_DEFS,
    eventTypes: EVENT_TYPE_DEFS,
    objects: [...objects.values()],
    events,
  };
}

function threatRels(oid: string, st: ThreatState, nodes: Map<string, DiagramNode>): LogRelation[] {
  const rels: LogRelation[] = [{ objectId: oid, qualifier: QUALIFIER.eventThreat }];
  const subj = st.view.subject;
  if ((subj?.kind ?? 'node') === 'node') {
    const nid = `${st.layer}:${subj?.id ?? st.view.nodeId}`;
    if (nodes.has(nid)) rels.push({ objectId: nid, qualifier: QUALIFIER.eventNode });
  }
  return rels;
}
