import { analyzeResolvedProject, resolveProject, SEVERITY_RANK } from './analyze';
import { detectTriggers, manualCheckTriggers, type TriggerHit } from '../change-triggers/detectTriggers';
import type { ChangeTrigger } from '../change-triggers/schema/trigger';
import { formatElementalId } from '../core/model/elementalId';
import { effectiveSeverity } from '../core/model/risk';
import {
  isSuppressed,
  LAYER_KEYS,
  type DiagramBoundary,
  type DiagramEdge,
  type DiagramNode,
  type ElementRef,
  type LayerKey,
  type Severity,
  type SuppressionStatus,
  type ThreatView,
} from '../core/model/types';
import { getLocale, translate, type Locale } from '../i18n';

/**
 * モデル差分（base/head の 2 版比較）＋実行トリガー判定＋ゲート判定。
 *
 * `analyze.ts`（単版の脅威検出）の上に積む形で実装する：base/head をそれぞれ
 * `resolveProject` → `analyzeResolvedProject` に通し、脅威 id（`${layer}:${threat.id}`）で
 * 突き合わせる。全レイヤーを対象にする（ノードが無いレイヤーも、どちらか一方にだけ
 * ノードがあるレイヤーを比較から漏らさないため比較対象に含める）。
 */

/** `diffProjects` のオプション。トリガー定義は呼び出し側（CLI）が同梱／カスタムを選んで渡す。 */
export interface DiffOptions {
  locale?: Locale;
  triggers: readonly ChangeTrigger[];
}

/** 対象要素の表示文字列（ElementalID ＋名前）。`sarif.ts` の `assetLabel` と同じ整形規約。 */
function assetLabel(
  subject: ElementRef | undefined,
  nodes: DiagramNode[],
  edges: DiagramEdge[],
  boundaries: DiagramBoundary[],
): string {
  if (!subject) return '';
  if (subject.kind === 'node') {
    const n = nodes.find((x) => x.id === subject.id);
    if (!n) return '';
    const id = n.seq != null ? formatElementalId('node', n.seq) : n.id;
    return `${id} ${n.label?.trim() || n.type}`;
  }
  if (subject.kind === 'edge') {
    const e = edges.find((x) => x.id === subject.id);
    if (!e) return '';
    const id = e.seq != null ? formatElementalId('edge', e.seq) : e.id;
    const name = e.dataFlowName?.trim();
    return name ? `${id} ${name}` : id;
  }
  const b = boundaries.find((x) => x.id === subject.id);
  if (!b) return '';
  const id = b.seq != null ? formatElementalId('boundary', b.seq) : b.id;
  return `${id} ${b.vlanName?.trim() || b.blastRadiusLabel?.trim() || b.type}`;
}

/** 脅威 1 件分の差分エントリ。`asset` は検出元の版（添加は head、解消は base）の図から求める。 */
export interface ThreatDiffEntry {
  layer: LayerKey;
  threat: ThreatView;
  asset: string;
}

/** 対応方針（抑制状態）の変更。`needsApproval` は受容・誤検知への変更時のみ true。 */
export interface SuppressionChangeEntry {
  layer: LayerKey;
  threat: ThreatView;
  asset: string;
  before: SuppressionStatus | undefined;
  after: SuppressionStatus | undefined;
  needsApproval: boolean;
}

/** 実効 severity の変化。 */
export interface SeverityChangeEntry {
  layer: LayerKey;
  threat: ThreatView;
  asset: string;
  before: Severity;
  after: Severity;
}

export interface ProjectDiff {
  added: ThreatDiffEntry[];
  removed: ThreatDiffEntry[];
  suppressionChanged: SuppressionChangeEntry[];
  severityChanged: SeverityChangeEntry[];
  /** 根拠付きで該当した実行トリガー。 */
  triggerHits: TriggerHit[];
  /** モデル差分だけでは自動判定できないトリガー（`detect: []`。T4 相当）。常に提示する。 */
  manualCheckTriggers: ChangeTrigger[];
}

/** 受容・誤検知への変更＝承認が必要（§2.50 設計判断：受容への変更はゲートを落とさず「要承認」で目立たせる）。 */
function needsApproval(status: SuppressionStatus | undefined): boolean {
  return status === 'accepted' || status === 'false-positive';
}

export function diffProjects(baseRaw: unknown, headRaw: unknown, opts: DiffOptions): ProjectDiff {
  const locale = opts.locale ?? 'ja';
  const baseResolved = resolveProject(baseRaw);
  const headResolved = resolveProject(headRaw);

  const added: ThreatDiffEntry[] = [];
  const removed: ThreatDiffEntry[] = [];
  const suppressionChanged: SuppressionChangeEntry[] = [];
  const severityChanged: SeverityChangeEntry[] = [];

  for (const layer of LAYER_KEYS) {
    const baseLayerData = baseResolved.layers[layer];
    const headLayerData = headResolved.layers[layer];
    const baseThreats = analyzeResolvedProject(baseResolved, { layer, framework: 'ALL', locale })[0]
      .threats;
    const headThreats = analyzeResolvedProject(headResolved, { layer, framework: 'ALL', locale })[0]
      .threats;
    const baseById = new Map(baseThreats.map((t) => [t.id, t] as const));
    const headById = new Map(headThreats.map((t) => [t.id, t] as const));

    for (const t of headThreats) {
      if (baseById.has(t.id)) continue;
      const asset = assetLabel(t.subject, headLayerData.nodes, headLayerData.edges, headLayerData.boundaries);
      added.push({ layer, threat: t, asset });
      // 追加と同時に受容・誤検知にされた脅威はゲート（未抑制のみ）を素通りするため、
      // 対応方針の変更（未対応 → 受容等）として「要承認」に必ず載せる。
      const after = t.suppression?.status;
      if (after !== undefined) {
        suppressionChanged.push({ layer, threat: t, asset, before: undefined, after, needsApproval: needsApproval(after) });
      }
    }
    for (const t of baseThreats) {
      if (headById.has(t.id)) continue;
      removed.push({
        layer,
        threat: t,
        asset: assetLabel(t.subject, baseLayerData.nodes, baseLayerData.edges, baseLayerData.boundaries),
      });
    }
    for (const t of headThreats) {
      const prev = baseById.get(t.id);
      if (!prev) continue;
      const asset = assetLabel(t.subject, headLayerData.nodes, headLayerData.edges, headLayerData.boundaries);

      const before = prev.suppression?.status;
      const after = t.suppression?.status;
      if (before !== after) {
        suppressionChanged.push({ layer, threat: t, asset, before, after, needsApproval: needsApproval(after) });
      }

      const beforeSeverity = effectiveSeverity(prev);
      const afterSeverity = effectiveSeverity(t);
      if (beforeSeverity !== afterSeverity) {
        severityChanged.push({ layer, threat: t, asset, before: beforeSeverity, after: afterSeverity });
      }
    }
  }

  const triggerHits = detectTriggers(baseResolved.layers, headResolved.layers, opts.triggers);

  return {
    added,
    removed,
    suppressionChanged,
    severityChanged,
    triggerHits,
    manualCheckTriggers: manualCheckTriggers(opts.triggers),
  };
}

/**
 * ゲート判定：**新規に追加された脅威だけ**を対象にする（既存の未対応脅威で毎回落ちないように）。
 * 未抑制かつ実効 severity が `failOn` 以上なら offender とする。
 * 受容・誤検知への変更（`suppressionChanged`）はゲートに含めない。
 */
export function evaluateDiffGate(diff: ProjectDiff, failOn: Severity): ThreatDiffEntry[] {
  const threshold = SEVERITY_RANK[failOn];
  return diff.added.filter(
    ({ threat }) => !isSuppressed(threat) && SEVERITY_RANK[effectiveSeverity(threat)] >= threshold,
  );
}

/** `diffToMarkdown` の任意パラメータ：ゲート結果（`--fail-on` 指定時のみ）。 */
export interface DiffGateResult {
  failOn: Severity;
  offenders: ThreatDiffEntry[];
}

function mdCell(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\r\n|\r|\n/g, '<br>');
}

function mdRow(cells: string[]): string {
  return `| ${cells.map(mdCell).join(' | ')} |`;
}

function threatTitle(t: ThreatView): string {
  return t.name ?? t.category;
}

/** 対応状況ラベル（`report.status.*` を再利用。抑制無し＝未対応）。 */
const STATUS_KEY: Record<SuppressionStatus, 'report.status.avoid' | 'report.status.reduce' | 'report.status.transfer' | 'report.status.accepted' | 'report.status.falsePositive'> = {
  avoid: 'report.status.avoid',
  reduce: 'report.status.reduce',
  transfer: 'report.status.transfer',
  accepted: 'report.status.accepted',
  'false-positive': 'report.status.falsePositive',
};

function statusLabel(status: SuppressionStatus | undefined, locale: Locale): string {
  return status ? translate(STATUS_KEY[status], locale) : translate('report.status.unaddressed', locale);
}

/**
 * PR コメントにそのまま貼れる Markdown へ変換する純粋関数。
 * `gate` は `--fail-on` 指定時のみ渡す（未指定なら「未設定」節を出す）。
 */
export function diffToMarkdown(diff: ProjectDiff, gate?: DiffGateResult): string {
  const locale = getLocale();
  const out: string[] = [];

  out.push(translate('diff.heading', locale), '');
  const approvalCount = diff.suppressionChanged.filter((c) => c.needsApproval).length;
  out.push(
    `- ${translate('diff.summary.added', locale, { count: diff.added.length })}`,
    `- ${translate('diff.summary.removed', locale, { count: diff.removed.length })}`,
    `- ${translate('diff.summary.suppressionChanged', locale, {
      count: diff.suppressionChanged.length,
      approvalCount,
    })}`,
    `- ${translate('diff.summary.severityChanged', locale, { count: diff.severityChanged.length })}`,
  );

  // ── 実行トリガー ──
  out.push('', translate('diff.section.triggers', locale), '');
  if (diff.triggerHits.length === 0 && diff.manualCheckTriggers.length === 0) {
    out.push(translate('diff.triggers.none', locale));
  }
  for (const hit of diff.triggerHits) {
    out.push(`### ${hit.triggerId} ${hit.title}`, '', hit.checkpoint, '');
    for (const ev of hit.evidence) {
      // フィールド名（`auth` 等）はロケール非依存の技術名のため ASCII 括弧で添える。
      const detail = ev.detail ? ` (${ev.detail})` : '';
      out.push(`- [${ev.layer}] ${ev.element.label}${detail}`);
    }
    out.push('');
  }
  if (diff.manualCheckTriggers.length > 0) {
    out.push(translate('diff.triggers.manualHeading', locale), '');
    for (const t of diff.manualCheckTriggers) {
      out.push(`- ${t.id} ${t.title} — ${t.checkpoint}`);
    }
    out.push('');
  }

  // ── 追加された脅威 ──
  out.push(translate('diff.section.added', locale), '');
  if (diff.added.length === 0) {
    out.push(translate('diff.table.none', locale));
  } else {
    out.push(
      mdRow([translate('diff.col.severity', locale), translate('diff.col.asset', locale), translate('diff.col.threat', locale)]),
      mdRow(['---', '---', '---']),
    );
    for (const { threat, asset } of diff.added) {
      out.push(mdRow([effectiveSeverity(threat), asset, threatTitle(threat)]));
    }
  }

  // ── 解消された脅威 ──
  out.push('', translate('diff.section.removed', locale), '');
  if (diff.removed.length === 0) {
    out.push(translate('diff.table.none', locale));
  } else {
    out.push(
      mdRow([translate('diff.col.severity', locale), translate('diff.col.asset', locale), translate('diff.col.threat', locale)]),
      mdRow(['---', '---', '---']),
    );
    for (const { threat, asset } of diff.removed) {
      out.push(mdRow([effectiveSeverity(threat), asset, threatTitle(threat)]));
    }
  }

  // ── 対応方針の変更 ──
  out.push('', translate('diff.section.suppressionChanged', locale), '');
  if (diff.suppressionChanged.length === 0) {
    out.push(translate('diff.table.none', locale));
  } else {
    out.push(
      mdRow([
        translate('diff.col.asset', locale),
        translate('diff.col.threat', locale),
        translate('diff.col.before', locale),
        translate('diff.col.after', locale),
        translate('diff.col.approval', locale),
      ]),
      mdRow(['---', '---', '---', '---', '---']),
    );
    for (const c of diff.suppressionChanged) {
      out.push(
        mdRow([
          c.asset,
          threatTitle(c.threat),
          statusLabel(c.before, locale),
          statusLabel(c.after, locale),
          c.needsApproval ? translate('diff.approval.yes', locale) : translate('diff.approval.no', locale),
        ]),
      );
    }
  }

  // ── 実効 severity の変化 ──
  out.push('', translate('diff.section.severityChanged', locale), '');
  if (diff.severityChanged.length === 0) {
    out.push(translate('diff.table.none', locale));
  } else {
    out.push(
      mdRow([
        translate('diff.col.asset', locale),
        translate('diff.col.threat', locale),
        translate('diff.col.before', locale),
        translate('diff.col.after', locale),
      ]),
      mdRow(['---', '---', '---', '---']),
    );
    for (const c of diff.severityChanged) {
      out.push(mdRow([c.asset, threatTitle(c.threat), c.before, c.after]));
    }
  }

  // ── ゲート判定 ──
  out.push('', translate('diff.section.gate', locale), '');
  if (!gate) {
    out.push(translate('diff.gate.notConfigured', locale));
  } else if (gate.offenders.length === 0) {
    out.push(translate('diff.gate.pass', locale, { failOn: gate.failOn }));
  } else {
    out.push(translate('diff.gate.fail', locale, { failOn: gate.failOn, count: gate.offenders.length }));
    for (const { threat, asset } of gate.offenders) {
      out.push(`- [${effectiveSeverity(threat)}] ${asset} ${threatTitle(threat)}`);
    }
  }

  return out.join('\n');
}

/** 機械処理用の JSON オブジェクトを組み立てる（`toJson` が文字列化する前の形）。 */
export function diffToJsonObject(diff: ProjectDiff, gate?: DiffGateResult): Record<string, unknown> {
  const threatSummary = (e: ThreatDiffEntry) => ({
    layer: e.layer,
    id: e.threat.id,
    asset: e.asset,
    severity: effectiveSeverity(e.threat),
    category: e.threat.category,
    name: e.threat.name,
    description: e.threat.description,
  });
  return {
    schemaVersion: 1,
    kind: 'cyberriskscape-model-diff',
    triggers: diff.triggerHits,
    manualCheckTriggers: diff.manualCheckTriggers.map((t) => ({
      id: t.id,
      title: t.title,
      checkpoint: t.checkpoint,
    })),
    added: diff.added.map(threatSummary),
    removed: diff.removed.map(threatSummary),
    suppressionChanged: diff.suppressionChanged.map((c) => ({
      layer: c.layer,
      id: c.threat.id,
      asset: c.asset,
      before: c.before ?? null,
      after: c.after ?? null,
      needsApproval: c.needsApproval,
    })),
    severityChanged: diff.severityChanged.map((c) => ({
      layer: c.layer,
      id: c.threat.id,
      asset: c.asset,
      before: c.before,
      after: c.after,
    })),
    gate: gate
      ? { failOn: gate.failOn, passed: gate.offenders.length === 0, offenders: gate.offenders.map((o) => o.threat.id) }
      : null,
  };
}

/** `diffToJsonObject` を整形済み JSON 文字列へ変換する。 */
export function diffToJson(diff: ProjectDiff, gate?: DiffGateResult): string {
  return JSON.stringify(diffToJsonObject(diff, gate), null, 2);
}
