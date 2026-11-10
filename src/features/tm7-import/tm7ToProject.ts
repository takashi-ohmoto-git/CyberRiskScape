import type {
  AuthType,
  ControlStatusState,
  ControlStatusValue,
  DiagramAnnotation,
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  EncryptionType,
  LayerData,
  LayerKey,
  ManualThreat,
  ProjectMeta,
  Severity,
} from '../../core/model/types';
import { EMPTY_LAYER, EMPTY_PROJECT_META } from '../../core/model/types';
import { MACRO_TRUST_TO_TRUST_LEVEL } from '../../core/constants/boundaryTypes';
import { getNodeDimensions } from '../../core/canvas/nodeGeometry';
import { getLocale, translate, type TranslationKey } from '../../i18n';
import { serializeProject } from '../persistence/serialize';
import type { PersistedProject } from '../persistence/schema';
import { parseTm7, TM7_MAX_BYTES, type Tm7Attribute, type Tm7Element, type Tm7Model } from './parseTm7';
import { BUNDLED_TM7_MAP, resolveTm7Target, type Tm7Map } from './tm7Map';

/**
 * .tm7 → CyberRiskScape のプロジェクト。移行が目的なので情報を落とさない（docs/decisions.md §4、2026-11-11）。
 *
 * - 要素：型は対応表（data/import-maps/tm7.yaml）で寄せ、元の型・選んだ属性・対象外とその理由はノード・線の説明に残す
 * - 線の形の境界・つながっていない線・メモ・対応表に無いモデル情報：注釈として残す（領域の境界に直せないため）
 * - 脅威：手動脅威（線に紐づけ）＋対策の実装状況。元の項目は `importedFrom.fields` にそのまま残す
 * - 脅威の判定はしない（CyberRiskScape の脅威エンジンが改めて出す）
 */

export const TM7_PRODUCT = 'Microsoft Threat Modeling Tool';

export interface Tm7ReviewItem {
  layer: LayerKey;
  /** 画面に出す要素の名前。 */
  label: string;
  reason: 'unmappedType' | 'lineBoundary' | 'danglingFlow';
}

export interface Tm7ImportSummary {
  nodes: number;
  edges: number;
  boundaries: number;
  annotations: number;
  threats: number;
  controlStatuses: number;
  /** 取り込めなかった図（5 枚目以降）の名前。 */
  skippedSurfaces: string[];
  review: Tm7ReviewItem[];
}

export type Tm7ImportResult =
  | { ok: true; project: PersistedProject; summary: Tm7ImportSummary }
  | { ok: false; error: string };

export interface Tm7ImportOptions {
  /** 日時の無い記録に使う取り込み時刻（epoch ms）。テストで固定する。 */
  now?: number;
  map?: Tm7Map;
}

/** 図（タブ）を入れるレイヤーの順。 */
const LAYER_ORDER: LayerKey[] = ['L1', 'L2', 'L3', 'L0'];

const STATE_TO_CONTROL: Record<string, ControlStatusValue> = {
  Mitigated: 'implemented',
  NotApplicable: 'not-applicable',
  NeedsInvestigation: 'required',
};

const PRIORITY_TO_SEVERITY: Record<string, Severity> = { High: 'High', Medium: 'Medium', Low: 'Low' };

/** 属性のうち、説明に残すもの（既定の選択のままのリスト・見出し・名前・対象外は除く）。 */
function recordedAttributes(attrs: readonly Tm7Attribute[]): Tm7Attribute[] {
  return attrs.filter((a) => {
    if (a.value === undefined || a.kind === 'HeaderDisplayAttribute') return false;
    if (a.displayName === 'Name' || a.displayName === 'Out Of Scope' || a.displayName === 'Reason For Out Of Scope') return false;
    if (a.kind === 'ListDisplayAttribute') return (a.selectedIndex ?? 0) !== 0;
    if (a.kind === 'StaticListDisplayAttribute') return true;
    if (a.displayName === 'Dataflow Order') return a.value !== '0';
    return a.value !== '';
  });
}

const attr = (e: Tm7Element, displayName: string): string | undefined =>
  e.attributes.find((a) => a.displayName === displayName)?.value;
const attrByName = (e: Tm7Element, name: string): string | undefined =>
  e.attributes.find((a) => a.name === name)?.value;
/** 型の画面名（最初の見出し。例: 'OS Process'）。 */
const typeName = (e: Tm7Element): string =>
  e.attributes.find((a) => a.kind === 'HeaderDisplayAttribute')?.displayName ?? e.typeId;
const elementName = (e: Tm7Element): string => attr(e, 'Name') ?? typeName(e);

/** TMT 既定のテンプレート（TMCore）か汎用型でない型＝対応表を作っていないテンプレートの型。 */
const isForeignType = (typeId: string): boolean => !typeId.includes('.TMCore.') && !typeId.startsWith('GE.');

const center = (e: Tm7Element) => ({ x: (e.left ?? 0) + (e.width ?? 0) / 2, y: (e.top ?? 0) + (e.height ?? 0) / 2 });
const inside = (b: Tm7Element, p: { x: number; y: number }) =>
  p.x >= (b.left ?? 0) && p.x <= (b.left ?? 0) + (b.width ?? 0) && p.y >= (b.top ?? 0) && p.y <= (b.top ?? 0) + (b.height ?? 0);

function parseTime(s: string | undefined, fallback: number): number {
  if (!s) return fallback;
  const t = Date.parse(s);
  return Number.isFinite(t) && t > 0 ? t : fallback;
}

export function tm7ToProject(xml: string, options: Tm7ImportOptions = {}): Tm7ImportResult {
  const locale = getLocale();
  const t = (key: TranslationKey, params?: Record<string, string | number>) => translate(key, locale, params);
  if (xml.length > TM7_MAX_BYTES) return { ok: false, error: t('tm7.error.tooLarge') };
  const parsed = parseTm7(xml);
  if (!parsed.ok) return { ok: false, error: t(parsed.error === 'parse' ? 'tm7.error.parse' : 'tm7.error.notTm7') };
  return convert(parsed.model, options.map ?? BUNDLED_TM7_MAP, options.now ?? Date.now(), t);
}

function convert(
  model: Tm7Model,
  map: Tm7Map,
  now: number,
  t: (key: TranslationKey, params?: Record<string, string | number>) => string,
): Tm7ImportResult {
  const layers: Record<LayerKey, LayerData> = { L0: EMPTY_LAYER, L1: EMPTY_LAYER, L2: EMPTY_LAYER, L3: EMPTY_LAYER, PQC: EMPTY_LAYER };
  const manualThreats: Record<LayerKey, ManualThreat[]> = { L0: [], L1: [], L2: [], L3: [], PQC: [] };
  const controlStatuses: Record<string, ControlStatusState> = {};
  const review: Tm7ReviewItem[] = [];
  const skippedSurfaces: string[] = [];
  /** 図の GUID → レイヤー。線の GUID → { レイヤー, 線 }。 */
  const surfaceLayer = new Map<string, LayerKey>();
  const edgeIndex = new Map<string, { layer: LayerKey; edge: DiagramEdge }>();
  const nodeLayer = new Map<string, LayerKey>();

  model.surfaces.forEach((surface, i) => {
    const layer = LAYER_ORDER[i];
    if (!layer) {
      skippedSurfaces.push(surface.header);
      return;
    }
    surfaceLayer.set(surface.guid, layer);
    const nodes: DiagramNode[] = [];
    const edges: DiagramEdge[] = [];
    const boundaries: DiagramBoundary[] = [];
    const annotations: DiagramAnnotation[] = [];
    const tmtBorders: Tm7Element[] = [];
    const elementsByGuid = new Map<string, Tm7Element>();

    const descLines = (e: Tm7Element, mappedTo: string, foreign: boolean): string[] => {
      const lines = [t('tm7.desc.type', { name: typeName(e), typeId: e.typeId })];
      const rec = recordedAttributes(e.attributes);
      if (rec.length > 0) lines.push(t('tm7.desc.attributes', { list: rec.map((a) => `${a.displayName} = ${a.value}`).join(' / ') }));
      if (attr(e, 'Out Of Scope') === 'true') {
        lines.push(t('tm7.desc.outOfScope', { reason: attr(e, 'Reason For Out Of Scope') || t('tm7.desc.noReason') }));
      }
      if (foreign) lines.push(t('tm7.desc.review', { type: mappedTo }));
      return lines;
    };

    for (const e of surface.borders) {
      elementsByGuid.set(e.guid, e);
      const resolved = resolveTm7Target(map, e.typeId, e.genericTypeId);
      const foreign = isForeignType(e.typeId);
      if (resolved?.target.boundary) {
        tmtBorders.push(e);
        const b = resolved.target.boundary;
        const trustLevel = b.macroTrust ? MACRO_TRUST_TO_TRUST_LEVEL[b.macroTrust] : (b.trustLevel ?? 'Internal');
        boundaries.push({
          id: e.guid,
          type: b.type,
          x: e.left ?? 0,
          y: e.top ?? 0,
          width: Math.max(1, e.width ?? 1),
          height: Math.max(1, e.height ?? 1),
          trustLevel,
          ...(b.macroTrust ? { macroTrust: b.macroTrust } : {}),
          label: elementName(e).slice(0, 64),
        });
        // 境界は説明の欄を持たないため、型の記録は注釈に残す（寄せた型が元の型を表しきれない場合）。
        const rec = recordedAttributes(e.attributes);
        if (!resolved.exact || rec.length > 0) {
          annotations.push({
            id: `${e.guid}-note`,
            kind: 'label',
            x: (e.left ?? 0) + 8,
            y: (e.top ?? 0) + 8,
            text: descLines(e, b.type, foreign).join('\n'),
          });
        }
        if (foreign) review.push({ layer, label: elementName(e), reason: 'unmappedType' });
        continue;
      }
      const nodeType = resolved?.target.node ?? 'PROCESS';
      const base: DiagramNode = { id: e.guid, type: nodeType, x: 0, y: 0 };
      const d = getNodeDimensions(base);
      const c = center(e);
      nodes.push({
        ...base,
        x: Math.round(c.x - d.w / 2),
        y: Math.round(c.y - d.h / 2),
        label: elementName(e),
        description: descLines(e, nodeType, foreign || !resolved).join('\n'),
      });
      nodeLayer.set(e.guid, layer);
      if (foreign || !resolved) review.push({ layer, label: elementName(e), reason: 'unmappedType' });
    }

    const nodeIds = new Set(nodes.map((n) => n.id));
    const sharesBorder = (a: string, b: string): boolean => {
      const ea = elementsByGuid.get(a);
      const eb = elementsByGuid.get(b);
      if (!ea || !eb) return false;
      return tmtBorders.some((bd) => inside(bd, center(ea)) && inside(bd, center(eb)));
    };

    for (const e of surface.lines) {
      const resolved = resolveTm7Target(map, e.typeId, e.genericTypeId);
      const mid = { x: Math.round(e.handleX ?? ((e.sourceX ?? 0) + (e.targetX ?? 0)) / 2), y: Math.round(e.handleY ?? ((e.sourceY ?? 0) + (e.targetY ?? 0)) / 2) };
      const coords = {
        sx: e.sourceX ?? 0,
        sy: e.sourceY ?? 0,
        tx: e.targetX ?? 0,
        ty: e.targetY ?? 0,
        hx: e.handleX ?? 0,
        hy: e.handleY ?? 0,
      };
      if (resolved?.target.lineBoundary || (!resolved?.target.edge && e.genericTypeId !== 'GE.DF')) {
        annotations.push({
          id: e.guid,
          kind: 'label',
          ...mid,
          text: [t('tm7.annotation.lineBoundary', { name: elementName(e), typeId: e.typeId, ...coords }), ...descLines(e, '', false).slice(1)].join('\n'),
        });
        review.push({ layer, label: elementName(e), reason: 'lineBoundary' });
        continue;
      }
      const src = e.sourceGuid ?? '';
      const dst = e.targetGuid ?? '';
      if (!nodeIds.has(src) || !nodeIds.has(dst)) {
        annotations.push({
          id: e.guid,
          kind: 'label',
          ...mid,
          text: [t('tm7.annotation.danglingFlow', { name: elementName(e), typeId: e.typeId, ...coords }), ...descLines(e, '', false).slice(1)].join('\n'),
        });
        review.push({ layer, label: elementName(e), reason: 'danglingFlow' });
        continue;
      }
      const edgeMap = resolved?.target.edge ?? {};
      const conf = attrByName(e, 'providesConfidentiality');
      const encryption: EncryptionType = conf === 'Yes' ? 'TLS' : conf === 'No' ? 'Plain' : (edgeMap.encryption ?? 'Plain');
      // 認証の方式は TMT に無いので、認証ありは控えめに Password とする（利用者が図で引き上げる）。
      const auth: AuthType = attrByName(e, 'authenticatesSource') === 'Yes' ? 'Password' : 'None';
      const name = elementName(e);
      const foreign = isForeignType(e.typeId);
      const desc = descLines(e, 'data flow', foreign);
      if (name.length > 80) desc.unshift(t('tm7.desc.fullName', { name }));
      const edge: DiagramEdge = {
        id: e.guid,
        source: src,
        target: dst,
        auth,
        network: sharesBorder(src, dst) ? 'VPC' : 'Internet',
        encryption,
        dataFlow: 'outbound',
        ...(name ? { dataFlowName: name.slice(0, 80) } : {}),
        ...(edgeMap.protocol ? { protocol: edgeMap.protocol } : {}),
        description: desc.join('\n'),
      };
      edges.push(edge);
      edgeIndex.set(e.guid, { layer, edge });
      if (foreign) review.push({ layer, label: name, reason: 'unmappedType' });
    }

    layers[layer] = { nodes, edges, boundaries, annotations };
  });

  // メモと、対応表に無いモデル情報は L1 の図の下に注釈として並べる。
  const first = layers.L1;
  const ys = [...first.nodes.map((n) => n.y + 120), ...first.boundaries.map((b) => b.y + b.height + 40), 0];
  let y = Math.max(...ys) + 40;
  const extra: DiagramAnnotation[] = [];
  for (const n of model.notes) {
    extra.push({ id: `tm7-note-${n.id}`, kind: 'label', x: 0, y, text: t('tm7.annotation.note', { id: n.id, message: n.message, by: n.addedBy, date: n.date }) });
    y += 60;
  }
  const KNOWN_META = new Set(['ThreatModelName', 'HighLevelSystemDescription', 'Owner', 'Reviewer', 'Contributors', 'Assumptions', 'ExternalDependencies']);
  const otherMeta = Object.entries(model.meta).filter(([k, v]) => !KNOWN_META.has(k) && v !== '');
  if (otherMeta.length > 0) {
    extra.push({ id: 'tm7-meta', kind: 'label', x: 0, y, text: [t('tm7.annotation.meta'), ...otherMeta.map(([k, v]) => `${k}: ${v}`)].join('\n') });
  }
  if (extra.length > 0) layers.L1 = { ...first, annotations: [...first.annotations, ...extra] };

  // 脅威 → 手動脅威＋対策の実装状況
  let threatCount = 0;
  for (const th of model.threats) {
    const f = th.fields;
    const flow = f.FlowGuid ? edgeIndex.get(f.FlowGuid) : undefined;
    const targetLayer = nodeLayer.get(f.TargetGuid ?? '');
    const layer = flow?.layer ?? targetLayer ?? surfaceLayer.get(f.DrawingSurfaceGuid ?? '') ?? 'L1';
    const id = `tm7-${f.Id ?? `${f.TypeId ?? 'x'}-${f.InteractionKey ?? threatCount}`}`;
    const title = f.Title ?? f.UserThreatCategory ?? f.TypeId ?? id;
    const description = f.UserThreatDescription ?? f.UserThreatShortDescription ?? title;
    const threat: ManualThreat = {
      id,
      framework: 'STRIDE',
      ...(flow ? { nodeId: flow.edge.target, subject: { kind: 'edge' as const, id: flow.edge.id } } : targetLayer ? { nodeId: f.TargetGuid } : {}),
      category: title.slice(0, 200),
      severity: PRIORITY_TO_SEVERITY[f.Priority ?? ''] ?? 'Medium',
      description: description.slice(0, 4000),
      importedFrom: { product: TM7_PRODUCT, externalId: f.Id ?? id, fields: f },
    };
    manualThreats[layer].push(threat);
    threatCount += 1;
    const status = STATE_TO_CONTROL[f.State ?? ''];
    if (status) {
      controlStatuses[id] = {
        status,
        note: f.StateInformation || t('tm7.status.noReason', { state: f.State ?? '' }),
        at: parseTime(f.ModifiedAt, now),
        ...(f.ChangedBy ? { by: f.ChangedBy.slice(0, 200) } : {}),
      };
    }
  }

  const m = model.meta;
  const projectMeta: ProjectMeta = {
    ...EMPTY_PROJECT_META,
    name: (m.ThreatModelName ?? '').slice(0, 200),
    purpose: (m.HighLevelSystemDescription ?? '').slice(0, 2000),
    owner: (m.Owner ?? '').slice(0, 200),
    reviewer: (m.Reviewer ?? '').slice(0, 200),
    contributors: (m.Contributors ?? '').slice(0, 1000),
    assumptions: (m.Assumptions ?? '').slice(0, 4000),
    externalDependencies: (m.ExternalDependencies ?? '').slice(0, 4000),
  };

  const numbered = (l: LayerData): LayerData => ({
    nodes: l.nodes.map((n, i) => ({ ...n, seq: i + 1 })),
    edges: l.edges.map((e, i) => ({ ...e, seq: i + 1 })),
    boundaries: l.boundaries.map((b, i) => ({ ...b, seq: i + 1 })),
    annotations: l.annotations,
  });
  const keys: LayerKey[] = ['L0', 'L1', 'L2', 'L3', 'PQC'];
  const finalLayers = Object.fromEntries(keys.map((k) => [k, numbered(layers[k])])) as Record<LayerKey, LayerData>;
  const idCounters = Object.fromEntries(
    keys.map((k) => [k, { node: layers[k].nodes.length, edge: layers[k].edges.length, boundary: layers[k].boundaries.length }]),
  ) as Record<LayerKey, { node: number; edge: number; boundary: number }>;

  const project = serializeProject({
    layers: finalLayers,
    activeLayer: 'L1',
    activeFramework: 'ALL',
    idCounters,
    projectMeta,
    manualThreats,
    controlStatuses,
  });

  const sum = (fn: (l: LayerData) => number) => keys.reduce((s, k) => s + fn(finalLayers[k]), 0);
  return {
    ok: true,
    project,
    summary: {
      nodes: sum((l) => l.nodes.length),
      edges: sum((l) => l.edges.length),
      boundaries: sum((l) => l.boundaries.length),
      annotations: sum((l) => l.annotations.length),
      threats: threatCount,
      controlStatuses: Object.keys(controlStatuses).length,
      skippedSurfaces,
      review,
    },
  };
}
