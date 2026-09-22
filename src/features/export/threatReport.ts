import type {
  ControlStatusValue,
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  FrameworkView,
  LayerKey,
  ProjectMeta,
  RiskScore,
  Severity,
  ThreatView,
} from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';
import { BRANDING } from '../../core/branding';
import { effectiveSeverity, impactLevel, likelihoodLevel, type AxisLevel } from '../../core/model/risk';
import { getLocale, translate, type Locale, type TranslationKey } from '../../i18n';

/**
 * 脅威レポート（案B）。社内 TM Excel テンプレート「Project Specific Threats」シートの
 * 列構成を参考に、**現在表示中の脅威一覧**（アクティブレイヤー＋アクティブ framework、
 * Analytics と同スコープ）を監査エビデンス用の表として書き出す。
 *
 * 列は「アプリがデータを持っている列」だけに絞る。手作業ワークフロー列
 * （Backlog Tasks / Security focused story / Abuse Cases 等）は出力しない。
 * Status / Comments には既存の `SuppressionState`（リスク受容 / 誤検知）を流用する。
 *
 * 本モジュールは純粋関数のみ（DOM・時刻・registry に非依存）。ダウンロード副作用は
 * [[download]]、表示ラベルの最終整形は UI 層に委ねる。
 */

/** v2 で severity 2 列化 ＋ name / impact / likelihood / controlStatus / risk を追加。 */
export const THREAT_REPORT_SCHEMA_VERSION = 2 as const;
export const THREAT_REPORT_KIND = 'cyberriskscape-threat-report' as const;

/** 脅威 1 件＝レポート 1 行。CSV に出る値は整形済み文字列。`risk` のみ JSON 専用の生値。 */
export interface ThreatReportRow {
  /** 脅威の安定 ID（`ThreatView.id`）。 */
  id: string;
  /** 対象要素：ElementalID（`C3` / `DF2` / `Z1`）＋ラベル。未割当（全体スコープ）は空。 */
  asset: string;
  framework: string;
  category: string;
  /** 脅威名（`ThreatView.name`）。未設定は空。 */
  name: string;
  /** 脅威の説明（`description`）。 */
  threat: string;
  /** ルール由来（脅威ライブラリの既定値）の severity。 */
  severity: Severity;
  /** 実効 severity（リスク評価済みなら評価由来、未評価はルール由来）。 */
  effectiveSeverity: Severity;
  /** Impact 軸。リスク評価済みのみ、未評価は空。 */
  impact: AxisLevel | '';
  /** Likelihood 軸。リスク評価済みのみ、未評価は空。 */
  likelihood: AxisLevel | '';
  /** 緩和策（`mitigation`）。未設定は空。 */
  countermeasure: string;
  /** 対応状況。検出脅威のみ：未対応 / 回避 / 低減 / 移転 / リスク受容 / 誤検知。手動脅威は空。 */
  status: string;
  /** 対策実装状況（`ControlStatusState.status`）。未設定は空。 */
  controlStatus: string;
  /** 開発者コメント等（`SuppressionState.note`）。 */
  comments: string;
  /** 種別：自動検出 / 手動。 */
  origin: string;
  /** リスク評価の生値（1–3）。**JSON 専用**で CSV には出ない。未評価は undefined。 */
  risk?: RiskScore;
}

export interface ThreatReport {
  project: ProjectMeta;
  framework: FrameworkView;
  layer: LayerKey;
  rows: ThreatReportRow[];
}

export interface BuildThreatReportInput {
  /** アクティブレイヤー＋アクティブ framework で構築済みの脅威ビュー。 */
  threats: ThreatView[];
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  boundaries: DiagramBoundary[];
  projectMeta: ProjectMeta;
  framework: FrameworkView;
  layer: LayerKey;
}

/** 対象要素の表示文字列（ElementalID ＋ラベル）を引くための索引値。 */
interface AssetEntry {
  elementalId: string;
  name: string;
}

function buildAssetIndex(
  nodes: DiagramNode[],
  edges: DiagramEdge[],
  boundaries: DiagramBoundary[],
): Map<string, AssetEntry> {
  const index = new Map<string, AssetEntry>();
  for (const n of nodes) {
    index.set(`node:${n.id}`, {
      elementalId: n.seq != null ? formatElementalId('node', n.seq) : n.id,
      name: n.label?.trim() || n.type,
    });
  }
  for (const e of edges) {
    index.set(`edge:${e.id}`, {
      elementalId: e.seq != null ? formatElementalId('edge', e.seq) : e.id,
      name: e.dataFlowName?.trim() ?? '',
    });
  }
  for (const b of boundaries) {
    index.set(`boundary:${b.id}`, {
      elementalId: b.seq != null ? formatElementalId('boundary', b.seq) : b.id,
      name: b.vlanName?.trim() || b.blastRadiusLabel?.trim() || b.type,
    });
  }
  return index;
}

function assetLabel(threat: ThreatView, index: Map<string, AssetEntry>): string {
  if (!threat.subject) return '';
  const entry = index.get(`${threat.subject.kind}:${threat.subject.id}`);
  if (!entry) return '';
  return entry.name ? `${entry.elementalId} ${entry.name}` : entry.elementalId;
}

// `src/ui/panels/controlStatusStyle.ts` の CONTROL_STATUS_LABEL_KEY と同じキーだが、
// features/ から ui/ へ依存させないための意図的な重複。
const CONTROL_STATUS_LABEL_KEY: Record<ControlStatusValue, TranslationKey> = {
  implemented: 'threats.controlStatus.implemented',
  required: 'threats.controlStatus.required',
  'not-applicable': 'threats.controlStatus.notApplicable',
  rejected: 'threats.controlStatus.rejected',
};

function controlStatusLabel(threat: ThreatView, locale: Locale): string {
  if (!threat.controlStatus) return '';
  return translate(CONTROL_STATUS_LABEL_KEY[threat.controlStatus.status], locale);
}

function statusLabel(threat: ThreatView, locale: Locale): string {
  // 手動脅威は対応状況（抑制注記）の対象外＝空欄。
  if (threat.origin === 'manual') return '';
  if (!threat.suppression) return translate('report.status.unaddressed', locale);
  switch (threat.suppression.status) {
    case 'avoid':
      return translate('report.status.avoid', locale);
    case 'reduce':
      return translate('report.status.reduce', locale);
    case 'transfer':
      return translate('report.status.transfer', locale);
    case 'accepted':
      return translate('report.status.accepted', locale);
    case 'false-positive':
      return translate('report.status.falsePositive', locale);
  }
}

export function buildThreatReport({
  threats,
  nodes,
  edges,
  boundaries,
  projectMeta,
  framework,
  layer,
}: BuildThreatReportInput): ThreatReport {
  const locale = getLocale();
  const index = buildAssetIndex(nodes, edges, boundaries);
  const rows: ThreatReportRow[] = threats.map((t) => ({
    id: t.id,
    asset: assetLabel(t, index),
    framework: t.framework,
    category: t.category,
    name: t.name ?? '',
    threat: t.description,
    severity: t.severity,
    effectiveSeverity: effectiveSeverity(t),
    // AxisLevel の生値（Low/Medium/High）をそのまま出す。既存の severity 列が
    // Severity の生 enum を出しているのと揃えるため（翻訳しない）。
    impact: t.risk ? impactLevel(t.risk) : '',
    likelihood: t.risk ? likelihoodLevel(t.risk) : '',
    countermeasure: t.mitigation ?? '',
    status: statusLabel(t, locale),
    controlStatus: controlStatusLabel(t, locale),
    comments: t.origin === 'detected' ? (t.suppression?.note ?? '') : '',
    origin:
      t.origin === 'manual'
        ? translate('report.origin.manual', locale)
        : translate('report.origin.detected', locale),
    risk: t.risk,
  }));
  return { project: projectMeta, framework, layer, rows };
}

// ─── シリアライザ ────────────────────────────────────────────

/** RFC 4180 風の CSV セル整形（カンマ・改行・ダブルクオートを含む値は引用＋"" でエスケープ）。 */
function csvCell(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

function csvRow(cells: string[]): string {
  return cells.map(csvCell).join(',');
}

const CSV_COLUMN_KEYS: readonly TranslationKey[] = [
  'report.csv.col.id',
  'report.csv.col.asset',
  'report.csv.col.framework',
  'report.csv.col.category',
  'report.csv.col.name',
  'report.csv.col.threat',
  'report.csv.col.severity',
  'report.csv.col.effectiveSeverity',
  'report.csv.col.impact',
  'report.csv.col.likelihood',
  'report.csv.col.mitigation',
  'report.csv.col.status',
  'report.csv.col.controlStatus',
  'report.csv.col.comments',
  'report.csv.col.origin',
];

/**
 * レポートを CSV 文字列へ変換する（UTF-8 / CRLF 改行）。
 * 先頭にプロジェクトメタ（2 列）ブロック → 空行 → 脅威表ヘッダ → 各行の順。
 * BOM は付与しない（Excel 向け BOM はダウンロード時に付与する。[[download]]）。
 */
export function toCsv(report: ThreatReport): string {
  const locale = getLocale();
  const { project } = report;
  const lines: string[] = [
    csvRow([translate('report.csv.meta.projectName', locale), project.name]),
    csvRow([translate('report.csv.meta.systemName', locale), project.systemName]),
    csvRow([translate('report.csv.meta.purpose', locale), project.purpose]),
    csvRow([translate('report.csv.meta.businessImpact', locale), project.businessImpact]),
    csvRow([translate('report.csv.meta.securityObjectives', locale), project.securityObjectives]),
    csvRow([translate('report.csv.meta.framework', locale), report.framework]),
    csvRow([translate('report.csv.meta.layer', locale), report.layer]),
    csvRow([translate('report.csv.meta.threatCount', locale), String(report.rows.length)]),
    '',
    csvRow(CSV_COLUMN_KEYS.map((k) => translate(k, locale))),
  ];
  for (const r of report.rows) {
    lines.push(
      csvRow([
        r.id,
        r.asset,
        r.framework,
        r.category,
        r.name,
        r.threat,
        r.severity,
        r.effectiveSeverity,
        r.impact,
        r.likelihood,
        r.countermeasure,
        r.status,
        r.controlStatus,
        r.comments,
        r.origin,
      ]),
    );
  }
  return lines.join('\r\n');
}

/** レポートを機械可読な JSON 文字列へ変換する（整形済み）。 */
export function toJson(report: ThreatReport): string {
  return JSON.stringify(
    {
      schemaVersion: THREAT_REPORT_SCHEMA_VERSION,
      kind: THREAT_REPORT_KIND,
      framework: report.framework,
      layer: report.layer,
      project: report.project,
      threats: report.rows,
    },
    null,
    2,
  );
}

// ─── DCRH（Anthropic 公式 THREAT_MODEL.md）シリアライザ ───────────
//
// Anthropic 公式 OSS `defending-code-reference-harness` の `/threat-model` スキル
// が出力する `THREAT_MODEL.md`（見出し・列順・enum 値が下流ツールとの「契約」）に
// 準拠した Markdown を生成する。詳細は docs/interop-anthropic-threat-model.md。
//
// 既存の CSV/JSON 経路（`ThreatReport` ベース）とは独立し、生の `ThreatView[]` を
// 含む `BuildThreatReportInput` を直接取る純粋関数（DOM・時刻・registry 非依存）。
// `ThreatView.id`・suppression・controlStatus・risk は読むだけで一切書き換えない。
// `Tn` 採番は出力文字列内のローカルラベルに限定する。

/** Markdown 表セルの安全化：`|` をエスケープし、改行を `<br>` に畳む。 */
function mdCell(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\r\n|\r|\n/g, '<br>');
}

/** Markdown 表の 1 行（先頭末尾にパイプ）。 */
function mdRow(cells: string[]): string {
  return `| ${cells.map(mdCell).join(' | ')} |`;
}

/** 要素（node/edge/boundary）の表示ラベル（ElementalID ＋名前）。索引は読み取りのみ。 */
function elementLabel(
  index: Map<string, AssetEntry>,
  kind: string,
  id: string,
): string {
  const entry = index.get(`${kind}:${id}`);
  if (!entry) return '';
  return entry.name ? `${entry.elementalId} ${entry.name}` : entry.elementalId;
}

type DcrhImpact = 'low' | 'medium' | 'high' | 'critical';
type DcrhLikelihood = 'very_rare' | 'rare' | 'possible' | 'likely' | 'almost_certain';
type DcrhStatus = 'unmitigated' | 'partially_mitigated' | 'mitigated' | 'risk_accepted';

/** Severity → 公式 impact（existential は使わない）。実効 severity を使う（likelihood と出所を揃える）。 */
const DCRH_IMPACT: Record<Severity, DcrhImpact> = {
  Low: 'low',
  Medium: 'medium',
  High: 'high',
  Critical: 'critical',
};

/** (impact, likelihood) 降順ソート用のランク。 */
const IMPACT_RANK: Record<DcrhImpact, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const LIKELIHOOD_RANK: Record<DcrhLikelihood, number> = {
  very_rare: 0,
  rare: 1,
  possible: 2,
  likely: 3,
  almost_certain: 4,
};

/**
 * likelihood 推定：リスク評価があれば Reproducibility + Exploitability（2..6）から
 * DCRH の 5 段階へ写像。未評価なら既定 `possible`（その事実は section 6 に明記）。
 *
 * アプリ内の Severity マトリクスは 3×3 なので `likelihoodLevel()` で 3 段階へ畳むが、
 * DCRH 側は 5 段階を持つためここでは和をそのまま使って解像度を落とさない。
 * 両者は単調で入れ子（Low→very_rare/rare、Medium→possible、High→likely/almost_certain）。
 */
function dcrhLikelihood(t: ThreatView): DcrhLikelihood {
  if (!t.risk) return 'possible';
  switch (t.risk.reproducibility + t.risk.exploitability) {
    case 2:
      return 'very_rare';
    case 3:
      return 'rare';
    case 4:
      return 'possible';
    case 5:
      return 'likely';
    default:
      return 'almost_certain'; // 6
  }
}

function dcrhReason(locale: Locale, label: string, note?: string): string {
  const trimmed = note?.trim();
  return trimmed ? translate('report.dcrh.reasonWithNote', locale, { label, note: trimmed }) : label;
}

/** 脅威の処遇：section 4 に載せる（status 付き）か、section 5 へ落とすか。 */
type DcrhDisposition =
  | { kind: 'threat'; status: DcrhStatus }
  | { kind: 'deprioritized'; reason: string };

/**
 * status マッピング（docs §7-3 の保守的方針）。
 * 1. 誤検知 false-positive → section 4 から除外し section 5 へ。
 * 2. controlStatus=not-applicable → section 4 から除外し section 5 へ。
 * 3. controlStatus=implemented のときのみ mitigated に格上げ。
 * 4. suppression∈{reduce,avoid,transfer} → partially_mitigated。
 * 5. suppression=accepted → risk_accepted（section 5 にも理由付きで載せる）。
 * 6. どれも無し → unmitigated。
 */
function dcrhDisposition(t: ThreatView, locale: Locale): DcrhDisposition {
  const sup = t.suppression?.status;
  const ctrl = t.controlStatus?.status;
  if (sup === 'false-positive') {
    return {
      kind: 'deprioritized',
      reason: dcrhReason(locale, translate('report.dcrh.reason.falsePositive', locale), t.suppression?.note),
    };
  }
  if (ctrl === 'not-applicable') {
    return {
      kind: 'deprioritized',
      reason: dcrhReason(locale, translate('report.dcrh.reason.notApplicable', locale), t.controlStatus?.note),
    };
  }
  if (ctrl === 'implemented') return { kind: 'threat', status: 'mitigated' };
  if (sup === 'reduce' || sup === 'avoid' || sup === 'transfer') {
    return { kind: 'threat', status: 'partially_mitigated' };
  }
  if (sup === 'accepted') return { kind: 'threat', status: 'risk_accepted' };
  return { kind: 'threat', status: 'unmitigated' };
}

/** controls 列：緩和策＋（partially_mitigated 時は対応方針注記）。空なら `none`。 */
function dcrhControls(t: ThreatView, status: DcrhStatus, locale: Locale): string {
  let controls = t.mitigation?.trim() ?? '';
  if (status === 'partially_mitigated' && t.suppression) {
    const labelKey: TranslationKey | undefined =
      t.suppression.status === 'reduce'
        ? 'report.status.reduce'
        : t.suppression.status === 'avoid'
          ? 'report.status.avoid'
          : t.suppression.status === 'transfer'
            ? 'report.status.transfer'
            : undefined;
    const label = labelKey ? translate(labelKey, locale) : '';
    const note = t.suppression.note?.trim();
    const extra = note ? translate('report.dcrh.reasonWithNote', locale, { label, note }) : label;
    controls = controls
      ? translate('report.dcrh.controlsWithNote', locale, { controls, extra })
      : extra;
  }
  return controls || 'none';
}

interface DcrhThreatRow {
  source: ThreatView;
  surface: string;
  asset: string;
  impact: DcrhImpact;
  likelihood: DcrhLikelihood;
  status: DcrhStatus;
  controls: string;
}

/**
 * CyberRiskScape の脅威モデルを Anthropic 公式 `THREAT_MODEL.md` 互換 Markdown へ
 * 変換する（ロスあり変換。埋められない列は空/既定とし section 6 に明記）。
 *
 * 純粋関数：入力を mutate せず、時刻にも依存しない（日付は `exportDate` で受ける）。
 *
 * @param input  `buildThreatReport` と同じ入力（生 `ThreatView[]` ＋図要素＋メタ）。
 * @param exportDate provenance 用の日付（`YYYY-MM-DD`）。未指定なら `unset`。
 */
export function toDCRHThreatModelMarkdown(
  input: BuildThreatReportInput,
  exportDate?: string,
): string {
  const { threats, nodes, edges, boundaries, projectMeta, framework, layer } = input;
  const locale = getLocale();
  const index = buildAssetIndex(nodes, edges, boundaries);
  const edgeById = new Map(edges.map((e) => [e.id, e]));

  // ── section 4 の脅威行と section 5 の deprioritized 行を 1 パスで分類 ──
  const threatRows: DcrhThreatRow[] = [];
  const deprioritized: { threat: string; reason: string }[] = [];
  let usedDefaultLikelihood = false;

  for (const t of threats) {
    const disp = dcrhDisposition(t, locale);
    if (disp.kind === 'deprioritized') {
      deprioritized.push({ threat: t.description, reason: disp.reason });
      continue;
    }
    if (!t.risk) usedDefaultLikelihood = true;
    const surface = t.subject ? elementLabel(index, t.subject.kind, t.subject.id) : '';
    // asset：エッジ起点の脅威は到達先ノード、それ以外は対象要素自身。
    let asset = surface;
    if (t.subject?.kind === 'edge') {
      const e = edgeById.get(t.subject.id);
      const target = e ? elementLabel(index, 'node', e.target) : '';
      if (target) asset = target;
    }
    threatRows.push({
      source: t,
      surface,
      asset,
      impact: DCRH_IMPACT[effectiveSeverity(t)],
      likelihood: dcrhLikelihood(t),
      status: disp.status,
      controls: dcrhControls(t, disp.status, locale),
    });
    if (disp.status === 'risk_accepted') {
      deprioritized.push({
        threat: t.description,
        reason: dcrhReason(locale, translate('report.status.accepted', locale), t.suppression?.note),
      });
    }
  }

  // (impact, likelihood) 降順。同点は元の安定順 → id で決定的に。
  const sorted = threatRows
    .map((row, i) => ({ row, i }))
    .sort((a, b) => {
      const di = IMPACT_RANK[b.row.impact] - IMPACT_RANK[a.row.impact];
      if (di !== 0) return di;
      const dl = LIKELIHOOD_RANK[b.row.likelihood] - LIKELIHOOD_RANK[a.row.likelihood];
      if (dl !== 0) return dl;
      if (a.i !== b.i) return a.i - b.i;
      return a.row.source.id.localeCompare(b.row.source.id);
    })
    .map((x) => x.row);

  const localId = (i: number) => `T${i + 1}`;

  // ── 出力組み立て ──
  const out: string[] = [];
  const systemName = projectMeta.systemName.trim() || projectMeta.name.trim() || 'Untitled';
  out.push(`# Threat Model: ${systemName}`);

  // 1. System context（散文）
  out.push('', '## 1. System context', '');
  const ctx: string[] = [];
  if (projectMeta.purpose.trim()) ctx.push(projectMeta.purpose.trim());
  if (projectMeta.businessImpact.trim())
    ctx.push(
      translate('report.dcrh.businessImpactLine', locale, {
        value: projectMeta.businessImpact.trim(),
      }),
    );
  if (projectMeta.securityObjectives.trim())
    ctx.push(
      translate('report.dcrh.securityObjectivesLine', locale, {
        value: projectMeta.securityObjectives.trim(),
      }),
    );
  if (ctx.length === 0)
    ctx.push(
      translate('report.dcrh.defaultContext', locale, { name: systemName, brand: BRANDING.name }),
    );
  out.push(ctx.join('\n\n'));

  // 2. Assets
  out.push('', '## 2. Assets', '', '| asset | description | sensitivity |', '|---|---|---|');
  for (const n of nodes) {
    out.push(
      mdRow([elementLabel(index, 'node', n.id), n.description?.trim() || n.type, 'medium']),
    );
  }
  for (const b of boundaries) {
    // BLAST_RADIUS は侵害時の影響範囲を示す注記であって信頼境界でもアセットでもないため除外
    // （src/core/model/types.ts の TRUST_BEARING_BOUNDARY_TYPES 付近のコメント参照）。
    if (b.type === 'BLAST_RADIUS') continue;
    out.push(mdRow([elementLabel(index, 'boundary', b.id), b.type, 'medium']));
  }

  // 3. Entry points & trust boundaries（脅威が紐づくデータフローのみ）
  const surfaceSet = new Set(sorted.map((r) => r.surface).filter(Boolean));
  out.push(
    '',
    '## 3. Entry points & trust boundaries',
    '',
    '| entry_point | description | trust_boundary | reachable_assets |',
    '|---|---|---|---|',
  );
  for (const e of edges) {
    const ep = elementLabel(index, 'edge', e.id);
    if (!surfaceSet.has(ep)) continue; // カバレッジ不変条件：surface に現れる entry_point のみ
    out.push(
      mdRow([
        ep,
        translate('report.dcrh.dataFlowDescription', locale, {
          network: e.network,
          encryption: e.encryption,
        }),
        `network=${e.network}, auth=${e.auth}`,
        elementLabel(index, 'node', e.target),
      ]),
    );
  }

  // 4. Threats
  out.push(
    '',
    '## 4. Threats',
    '',
    '| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |',
    '|---|---|---|---|---|---|---|---|---|---|',
  );
  sorted.forEach((r, i) => {
    out.push(
      mdRow([
        localId(i),
        r.source.description,
        '', // actor：未モデル化（section 6 参照）
        r.surface,
        r.asset,
        r.impact,
        r.likelihood,
        r.status,
        r.controls,
        '', // evidence：常に空（CRS は確定済み証拠を未保持）
      ]),
    );
  });

  // 5. Deprioritized
  out.push('', '## 5. Deprioritized', '', '| threat | reason |', '|---|---|');
  for (const d of deprioritized) {
    out.push(mdRow([d.threat, d.reason]));
  }

  // 6. Open questions（ロス変換で埋められなかった列を正直に明示）
  out.push('', '## 6. Open questions', '');
  out.push(translate('report.dcrh.openQuestions.actor', locale, { brand: BRANDING.name }));
  if (usedDefaultLikelihood) out.push(translate('report.dcrh.openQuestions.likelihood', locale));
  out.push(translate('report.dcrh.openQuestions.evidence', locale));
  out.push(translate('report.dcrh.openQuestions.sensitivity', locale));
  out.push(translate('report.dcrh.openQuestions.entryPoint', locale));
  out.push(translate('report.dcrh.openQuestions.section8', locale));

  // 7. Provenance
  out.push('', '## 7. Provenance', '');
  out.push('- mode: cyberriskscape-export');
  out.push(`- date: ${exportDate?.trim() || 'unset'}`);
  out.push(`- target: ${systemName}`);
  out.push(`- inputs: CyberRiskScape diagram (framework=${framework}, layer=${layer})`);
  out.push('- owner: unset');
  out.push(`- tool: ${BRANDING.name}`);

  // 8. Recommended mitigations（任意・簡易）。緩和策ごとに脅威 id を束ねる。
  out.push(
    '',
    '## 8. Recommended mitigations',
    '',
    '| mitigation | threat_ids | closes_class | effort |',
    '|---|---|---|---|',
  );
  const mitMap = new Map<string, string[]>();
  sorted.forEach((r, i) => {
    const m = r.source.mitigation?.trim();
    if (!m) return;
    const list = mitMap.get(m);
    if (list) list.push(localId(i));
    else mitMap.set(m, [localId(i)]);
  });
  for (const [mitigation, ids] of mitMap) {
    out.push(mdRow([mitigation, ids.join(','), 'partial', 'M']));
  }

  // 末尾：Tn → ThreatView.id 対応表（HTML コメント。section regex に干渉しない位置）。
  const idMap = sorted.map((r, i) => `${localId(i)}=${r.source.id}; `).join('');
  out.push('', `<!-- crs-id-map: ${idMap}-->`);

  return out.join('\n');
}
