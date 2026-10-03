import { PDFDocument, rgb, type PDFFont, type PDFPage, type RGB } from 'pdf-lib';
import fontkit from '@pdf-lib/fontkit';
import { BRANDING } from '../../../core/branding';
import type { LayerKey, Severity, ThreatView } from '../../../core/model/types';
import { getComplianceMap } from '../../../compliance/loader/bundledComplianceMap';
import { makeComplianceKey } from '../../../compliance/loader/loadComplianceMap';
import type { StandardId } from '../../../compliance/schema/complianceItem';
import { translate, type Locale, type TranslationKey } from '../../../i18n';
import { THREAT_REPORT_SCHEMA_VERSION, type ThreatReport, type ThreatReportRow } from '../threatReport';
import { createFontSubsetter } from './fontSubset';
import { createCursor, flowInline, layoutTableRow, wrapText, type PageCursor } from './layout';
import {
  CONTROL_BUCKETS,
  SEVERITY_ORDER,
  TREATMENTS,
  computeSummary,
  firstStep,
  formatProgress,
  isSuppressedItem,
  mitigationLines,
  rankThreats,
  stripTierTags,
  toSummaryItem,
  type ControlBucket,
  type SummaryItem,
  type Treatment,
} from './summary';

/**
 * 脅威レポートの PDF 生成（A4 縦）。中身は `ThreatReport`（CSV/JSON と同じ行）から作る。
 * フォント・wasm・図の PNG は呼び出し側が注入する（本モジュールは fetch しない）。
 * 流れ：文字列を先に全部確定 → 使用文字で HarfBuzz サブセット → 埋め込み → 描画。
 */

export interface PdfReportLayer {
  layer: LayerKey;
  report: ThreatReport;
  /** この `report` の元になった脅威ビュー。抑制状態・対策実装状況は `row.id` で引いて生値で判定する。 */
  threats: ThreatView[];
  /** 構成図（PNG バイト列）。無ければ図は出さない。 */
  diagramPng?: Uint8Array;
}

export interface BuildPdfReportInput {
  reports: PdfReportLayer[];
  locale: Locale;
  generatedAt: Date;
  appVersion: string;
  fonts: { regular: Uint8Array; bold: Uint8Array };
  harfbuzzWasm: Uint8Array;
}

// ── 定数（pt） ──
const PAGE_W = 595.28;
const PAGE_H = 841.89;
const MARGIN_X = 40;
const MARGIN_TOP = 44;
const MARGIN_BOTTOM = 54;
const CONTENT_W = PAGE_W - MARGIN_X * 2;
const BODY = 9;
const BODY_LH = 13;
const SMALL = 8;
const TABLE_SIZE = 8.5;
const TABLE_LH = 11.5;
const TABLE_PAD_X = 4;
const TABLE_PAD_Y = 3;

const INK = rgb(0.1, 0.1, 0.12);
const MUTED = rgb(0.4, 0.4, 0.45);
const RULE = rgb(0.75, 0.75, 0.78);
const HEAD_BG = rgb(0.92, 0.93, 0.95);

const SEVERITIES: readonly Severity[] = ['Critical', 'High', 'Medium', 'Low'];
const SEVERITY_COLOR: Record<Severity, RGB> = {
  Critical: rgb(0.7, 0.08, 0.12),
  High: rgb(0.8, 0.35, 0),
  Medium: rgb(0.6, 0.45, 0),
  Low: rgb(0.2, 0.5, 0.3),
};

// ── 前処理（描画に使う文字列をすべて確定する） ──

interface PreparedRow {
  layer: LayerKey;
  no: string;
  asset: string;
  name: string;
  severity: Severity;
  status: string;
  controlStatus: string;
  category: string;
  description: string;
  mitigation: string;
  firstStep: string;
  compliance: string[];
  impact: string;
  likelihood: string;
  comments: string;
}

interface PreparedLayer {
  layer: LayerKey;
  diagramPng?: Uint8Array;
  active: PreparedRow[];
  suppressed: PreparedRow[];
}

/** 制御文字を除き、改行は `\n` に正規化する（フォントに無い文字での描画エラー防止）。 */
function clean(s: string): string {
  return s
    .replace(/\r\n?/g, '\n')
    .replace(/\t/g, ' ')
    .replace(/[\u0000-\u0009\u000b-\u001f\u007f]/g, ''); // eslint-disable-line no-control-regex
}

function formatDate(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

const TREATMENT_KEY: Record<Treatment, TranslationKey> = {
  unaddressed: 'report.status.unaddressed',
  avoid: 'report.status.avoid',
  reduce: 'report.status.reduce',
  transfer: 'report.status.transfer',
  accepted: 'report.status.accepted',
  'false-positive': 'report.status.falsePositive',
};

const CONTROL_KEY: Record<ControlBucket, TranslationKey> = {
  implemented: 'threats.controlStatus.implemented',
  required: 'threats.controlStatus.required',
  rejected: 'threats.controlStatus.rejected',
  'not-applicable': 'threats.controlStatus.notApplicable',
  unset: 'report.pdf.control.unset',
};

function resolveCompliance(row: ThreatReportRow, locale: Locale): string[] {
  const map = getComplianceMap(locale);
  return (row.complianceRefs ?? []).map((r) => {
    const id = r.standard as StandardId;
    const key = makeComplianceKey(id, r.ref);
    const std = map.standards.get(id)?.title ?? r.standard;
    const label = map.refLabels?.get(key) ?? r.ref;
    const item = map.index.get(key);
    return clean(`${std} · ${label}${item ? ` — ${item.title}` : ''}`);
  });
}

/** 緩和策：`mitigationTiers` があれば段階ごとの行、無ければ従来の文（残ったタグは除去）。 */
function formatMitigation(row: ThreatReportRow): string {
  const lines = mitigationLines(row);
  if (lines.length > 0) return clean(lines.map((l) => `${l.tier}: ${l.text}`).join('\n'));
  return clean(stripTierTags(row.countermeasure));
}

function prepareRow(item: SummaryItem, no: number, locale: Locale): PreparedRow {
  const r = item.row;
  return {
    layer: item.layer,
    no: String(no),
    asset: clean(r.asset),
    name: clean(r.name || r.category),
    severity: item.severity,
    status: translate(TREATMENT_KEY[item.treatment], locale),
    controlStatus: translate(CONTROL_KEY[item.control ?? 'unset'], locale),
    category: clean(r.category),
    description: clean(r.threat),
    mitigation: formatMitigation(r),
    firstStep: clean(firstStep(r, item.control)),
    compliance: resolveCompliance(r, locale),
    impact: r.impact,
    likelihood: r.likelihood,
    comments: clean(r.comments),
  };
}

/** レイヤー内の全脅威を SummaryItem にする（`row.id` で ThreatView を引く）。 */
function toItems(l: PdfReportLayer): SummaryItem[] {
  const views = new Map(l.threats.map((t) => [t.id, t]));
  return l.report.rows.map((row, i) => toSummaryItem(l.layer, i, row, views.get(row.id)));
}

function prepareLayer(l: PdfReportLayer, items: SummaryItem[], locale: Locale): PreparedLayer {
  // 実効深刻度の降順（同順位は元の並びを維持）。
  const sorted = [...items].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.index - b.index,
  );
  // 番号は章内の通し（有効 → 抑制の順）。
  let n = 0;
  const active = sorted.filter((i) => !isSuppressedItem(i)).map((i) => prepareRow(i, ++n, locale));
  const suppressed = sorted.filter(isSuppressedItem).map((i) => prepareRow(i, ++n, locale));
  return { layer: l.layer, diagramPng: l.diagramPng, active, suppressed };
}

/** オブジェクト中の文字列値をすべて集める。 */
function collectStrings(v: unknown, out: string[]): void {
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) v.forEach((x) => collectStrings(x, out));
  else if (v && typeof v === 'object' && !(v instanceof Uint8Array)) {
    Object.values(v).forEach((x) => collectStrings(x, out));
  }
}

// ── 描画 ──

interface Ctx {
  doc: PDFDocument;
  reg: PDFFont;
  bold: PDFFont;
  cursor: PageCursor;
  pages: PDFPage[];
}

function page(ctx: Ctx): PDFPage {
  while (ctx.pages.length <= ctx.cursor.pageIndex) ctx.pages.push(ctx.doc.addPage([PAGE_W, PAGE_H]));
  return ctx.pages[ctx.cursor.pageIndex] as PDFPage;
}

/** 必要な高さが現ページに無ければ改ページ。 */
function need(ctx: Ctx, h: number): void {
  ctx.cursor.ensure(h);
}

/** 現ページに何か描いていれば改ページする。 */
function breakPage(ctx: Ctx): void {
  if (ctx.cursor.y < PAGE_H - MARGIN_TOP) ctx.cursor.ensure(Infinity);
}

function measureOf(font: PDFFont) {
  return (t: string, size: number) => font.widthOfTextAtSize(t, size);
}

/** 折返しつつ段落を描く。ページをまたいでよい。 */
function paragraph(
  ctx: Ctx,
  text: string,
  opts: { font?: PDFFont; size?: number; lineHeight?: number; x?: number; width?: number; color?: RGB } = {},
): void {
  const font = opts.font ?? ctx.reg;
  const size = opts.size ?? BODY;
  const lh = opts.lineHeight ?? BODY_LH;
  const x = opts.x ?? MARGIN_X;
  const width = opts.width ?? CONTENT_W - (x - MARGIN_X);
  for (const line of wrapText(text, width, size, measureOf(font))) {
    need(ctx, lh);
    if (line) page(ctx).drawText(line, { x, y: ctx.cursor.y - size, size, font, color: opts.color ?? INK });
    ctx.cursor.advance(lh);
  }
}

interface TableRow {
  cells: string[];
  colors?: (RGB | undefined)[];
  bold?: boolean[];
}

/** 罫線付きの表。ヘッダ行は改ページ後も繰り返す。`right` の列は右寄せ。 */
function table(
  ctx: Ctx,
  headers: string[],
  widths: number[],
  rows: TableRow[],
  opts: { right?: number[]; maxLines?: number; padY?: number } = {},
): void {
  const right = opts.right ?? [];
  const padY = opts.padY ?? TABLE_PAD_Y;
  const maxLines = opts.maxLines ?? 8;
  const drawRow = (row: TableRow, header: boolean) => {
    const font0 = header ? ctx.bold : ctx.reg;
    const lay = layoutTableRow(row.cells, widths, TABLE_SIZE, TABLE_LH, TABLE_PAD_X, padY, measureOf(font0), maxLines);
    // ヘッダは直後に最低 2 行分が続く位置でだけ置く。
    need(ctx, header ? lay.height + TABLE_LH * 2 : lay.height);
    const p = page(ctx);
    const top = ctx.cursor.y;
    if (header) {
      p.drawRectangle({ x: MARGIN_X, y: top - lay.height, width: CONTENT_W, height: lay.height, color: HEAD_BG });
    }
    let x = MARGIN_X;
    lay.lines.forEach((lines, i) => {
      const w = widths[i] as number;
      const font = header || row.bold?.[i] ? ctx.bold : ctx.reg;
      lines.forEach((line, li) => {
        if (!line) return;
        const tw = font.widthOfTextAtSize(line, TABLE_SIZE);
        p.drawText(line, {
          x: right.includes(i) ? x + w - TABLE_PAD_X - tw : x + TABLE_PAD_X,
          y: top - padY - TABLE_SIZE - li * TABLE_LH,
          size: TABLE_SIZE,
          font,
          color: row.colors?.[i] ?? INK,
        });
      });
      x += w;
    });
    p.drawLine({
      start: { x: MARGIN_X, y: top - lay.height },
      end: { x: MARGIN_X + CONTENT_W, y: top - lay.height },
      thickness: 0.5,
      color: RULE,
    });
    ctx.cursor.advance(lay.height);
  };
  const headerRow: TableRow = { cells: headers };
  drawRow(headerRow, true);
  for (const r of rows) {
    const h = layoutTableRow(r.cells, widths, TABLE_SIZE, TABLE_LH, TABLE_PAD_X, padY, measureOf(ctx.reg), maxLines).height;
    if (ctx.cursor.y - h < MARGIN_BOTTOM) {
      need(ctx, h);
      drawRow(headerRow, true);
    }
    drawRow(r, false);
  }
}

function heading(ctx: Ctx, text: string, size: number, gapBefore = 8): void {
  need(ctx, size + gapBefore + BODY_LH * 3);
  ctx.cursor.advance(gapBefore);
  paragraph(ctx, text, { font: ctx.bold, size, lineHeight: size + 5 });
}

async function drawDiagram(ctx: Ctx, png: Uint8Array): Promise<void> {
  const img = await ctx.doc.embedPng(png);
  const maxH = (PAGE_H - MARGIN_TOP - MARGIN_BOTTOM) * 0.6;
  const scale = Math.min(CONTENT_W / img.width, maxH / img.height, 1);
  const w = img.width * scale;
  const h = img.height * scale;
  need(ctx, h + 8);
  page(ctx).drawImage(img, { x: MARGIN_X + (CONTENT_W - w) / 2, y: ctx.cursor.y - h, width: w, height: h });
  ctx.cursor.advance(h + 10);
}

type T = (key: TranslationKey, params?: Record<string, string | number>) => string;

function detailBlock(ctx: Ctx, r: PreparedRow, t: T, top = false): void {
  need(ctx, 14 + BODY_LH * 4);
  ctx.cursor.advance(8);
  // 見出し：「No. 脅威名」＋右端に実効深刻度（色付き）
  const sevW = ctx.bold.widthOfTextAtSize(r.severity, BODY);
  page(ctx).drawText(r.severity, {
    x: MARGIN_X + CONTENT_W - sevW,
    y: ctx.cursor.y - 10,
    size: BODY,
    font: ctx.bold,
    color: SEVERITY_COLOR[r.severity],
  });
  paragraph(ctx, `${r.no}. ${r.name}`, { font: ctx.bold, size: 10, lineHeight: 14, width: CONTENT_W - sevW - 10 });
  ctx.cursor.advance(1);
  // 短い項目は「ラベル 値」の横並びメタ行にまとめる（幅を超えたら次の行へ）。
  const metaRows = flowInline(
    [
      ...(top ? [{ label: t('report.pdf.detail.layer'), value: r.layer }] : []),
      { label: t('report.pdf.detail.category'), value: r.category },
      { label: t('report.pdf.detail.asset'), value: r.asset },
      { label: t('report.pdf.detail.impact'), value: r.impact },
      { label: t('report.pdf.detail.likelihood'), value: r.likelihood },
      { label: t('report.pdf.detail.status'), value: r.status },
      { label: t('report.pdf.detail.controlStatus'), value: r.controlStatus },
    ],
    CONTENT_W,
    {
      label: (s) => ctx.bold.widthOfTextAtSize(s, SMALL),
      value: (s) => ctx.reg.widthOfTextAtSize(s, BODY),
    },
  );
  for (const row of metaRows) {
    need(ctx, BODY_LH);
    const p = page(ctx);
    const baseline = ctx.cursor.y - BODY;
    for (const seg of row) {
      let x = MARGIN_X + seg.x;
      if (seg.label) {
        p.drawText(seg.label, { x, y: baseline, size: SMALL, font: ctx.bold, color: MUTED });
        x += ctx.bold.widthOfTextAtSize(seg.label, SMALL) + 4;
      }
      p.drawText(seg.text, { x, y: baseline, size: BODY, font: ctx.reg, color: INK });
    }
    ctx.cursor.advance(BODY_LH);
  }
  // 長い項目はラベル行＋本文。
  const field = (label: string, body: string) => {
    if (!body) return;
    need(ctx, BODY_LH * 2);
    paragraph(ctx, label, { font: ctx.bold, size: SMALL, lineHeight: 11, color: MUTED });
    paragraph(ctx, body, { x: MARGIN_X + 8 });
  };
  field(t('report.pdf.detail.description'), r.description);
  field(t('report.pdf.detail.mitigation'), r.mitigation);
  if (top) field(t('report.pdf.detail.firstStep'), r.firstStep);
  field(t('report.pdf.detail.compliance'), r.compliance.map((c) => `・${c}`).join('\n'));
  field(t('report.pdf.detail.comments'), r.comments);
  need(ctx, 6);
  page(ctx).drawLine({
    start: { x: MARGIN_X, y: ctx.cursor.y - 2 },
    end: { x: MARGIN_X + CONTENT_W, y: ctx.cursor.y - 2 },
    thickness: 0.4,
    color: RULE,
  });
  ctx.cursor.advance(4);
}

// 列幅は太字見出し・ラベルの実測（8.5pt＋左右余白）で決めた最小幅を確保する：
// 実効深刻度/Effective ≈52pt、Unaddressed ≈70pt、Not applicable ≈76pt、FRONT_END_SERVER ≈104pt（空白で折り返す前提）。
const THREAT_WIDTHS = [26, 106, 180, 53, 72, 78];

function threatSection(ctx: Ctx, title: string, rows: PreparedRow[], t: T): void {
  heading(ctx, title, 11);
  ctx.cursor.advance(2);
  table(
    ctx,
    [
      t('report.pdf.table.no'),
      t('report.pdf.table.asset'),
      t('report.pdf.table.name'),
      t('report.pdf.table.severity'),
      t('report.pdf.table.status'),
      t('report.pdf.table.controlStatus'),
    ],
    THREAT_WIDTHS,
    rows.map((r) => ({
      cells: [r.no, r.asset, r.name, r.severity, r.status, r.controlStatus],
      colors: [undefined, undefined, undefined, SEVERITY_COLOR[r.severity]],
      bold: [false, false, false, true],
    })),
  );
  heading(ctx, t('report.pdf.section.details'), 10, 12);
  for (const r of rows) detailBlock(ctx, r, t);
}

/** 描画で `t()` から直接引く固定ラベル（使用文字の収集用）。 */
const STATIC_LABEL_KEYS: readonly TranslationKey[] = [
  'report.pdf.title',
  'report.pdf.summary.heading',
  'report.pdf.layer.heading',
  'report.pdf.section.threats',
  'report.pdf.section.suppressed',
  'report.pdf.section.details',
  'report.pdf.noThreats',
  'report.pdf.table.no',
  'report.pdf.table.asset',
  'report.pdf.table.name',
  'report.pdf.table.severity',
  'report.pdf.table.status',
  'report.pdf.table.controlStatus',
  'report.pdf.detail.category',
  'report.pdf.detail.asset',
  'report.pdf.detail.description',
  'report.pdf.detail.mitigation',
  'report.pdf.detail.compliance',
  'report.pdf.detail.impact',
  'report.pdf.detail.likelihood',
  'report.pdf.detail.comments',
  'report.pdf.detail.status',
  'report.pdf.detail.controlStatus',
  'report.pdf.detail.firstStep',
  'report.pdf.detail.layer',
  'report.pdf.footer.page',
  'report.pdf.top.heading',
  'report.pdf.top.rank',
  'report.pdf.top.layer',
  'report.pdf.top.empty',
  'report.pdf.counts.treatment',
  'report.pdf.counts.control',
  'report.pdf.premise.heading',
  'report.pdf.topDetail.heading',
  'report.pdf.appendix.heading',
  ...TREATMENTS.map((x) => TREATMENT_KEY[x]),
  ...CONTROL_BUCKETS.map((x) => CONTROL_KEY[x]),
];

interface Metric {
  label: string;
  value: string;
  subs: string[];
}

/** 1 ページ目の主要指標ボックス。 */
function metricBoxes(ctx: Ctx, metrics: Metric[]): void {
  const gap = 8;
  const w = (CONTENT_W - gap * (metrics.length - 1)) / metrics.length;
  const h = 68;
  need(ctx, h + 6);
  const top = ctx.cursor.y;
  const p = page(ctx);
  metrics.forEach((m, i) => {
    const x = MARGIN_X + i * (w + gap);
    p.drawRectangle({ x, y: top - h, width: w, height: h, borderColor: RULE, borderWidth: 0.6 });
    wrapText(m.label, w - 12, SMALL, measureOf(ctx.bold))
      .slice(0, 2)
      .forEach((line, li) => {
        p.drawText(line, { x: x + 6, y: top - 10 - li * 10, size: SMALL, font: ctx.bold, color: MUTED });
      });
    p.drawText(m.value, { x: x + 6, y: top - 42, size: 18, font: ctx.bold, color: INK });
    m.subs.forEach((line, li) => {
      p.drawText(line, { x: x + 6, y: top - 52 - li * 10, size: SMALL, font: ctx.reg, color: MUTED });
    });
  });
  ctx.cursor.advance(h + 6);
}

export async function buildPdfReport(input: BuildPdfReportInput): Promise<Uint8Array> {
  const { locale } = input;
  const t: T = (key, params) => translate(key, locale, params);
  const layerItems = input.reports.map(toItems);
  const allItems = layerItems.flat();
  const layerKeys = input.reports.map((l) => l.layer);
  const layers = input.reports.map((l, i) => prepareLayer(l, layerItems[i] as SummaryItem[], locale));
  const summary = computeSummary(allItems, layerKeys);
  const top = rankThreats(allItems, layerKeys).map((it, i) => prepareRow(it, i + 1, locale));

  const first = input.reports[0]?.report;
  const project = first?.project;
  const systemName = clean(project?.systemName ?? '');
  const toolLine = `${BRANDING.name} v${input.appVersion}`;

  // ── 1 ページ目（サマリ）の文字列 ──
  const coverLine = [
    `${t('report.pdf.meta.generatedAt')}: ${formatDate(input.generatedAt)}`,
    `${t('report.pdf.meta.layers')}: ${layerKeys.join(', ')}`,
    `${t('report.pdf.meta.tool')}: ${toolLine}`,
  ].join('    ');
  const { progressAll, progressCriticalHigh } = summary;
  const metrics: Metric[] = [
    { label: t('report.pdf.metric.active'), value: String(summary.activeCount), subs: [] },
    { label: t('report.pdf.metric.criticalHigh'), value: String(summary.criticalHighCount), subs: [] },
    {
      label: t('report.pdf.metric.progress'),
      value: formatProgress(progressAll),
      subs: [
        t('report.pdf.metric.progressDone', { done: progressAll.implemented, total: progressAll.total }),
        t('report.pdf.metric.progressCh', { rate: formatProgress(progressCriticalHigh) }),
      ],
    },
    { label: t('report.pdf.metric.unaddressed'), value: String(summary.unaddressedCount), subs: [] },
  ];
  const topRows: TableRow[] = top.map((r) => ({
    cells: [r.no, r.name, r.asset, r.layer, r.severity, r.status, r.controlStatus],
    colors: [undefined, undefined, undefined, undefined, SEVERITY_COLOR[r.severity]],
    bold: [false, false, false, false, true],
  }));
  const topHeaders = [
    t('report.pdf.top.rank'),
    t('report.pdf.table.name'),
    t('report.pdf.table.asset'),
    t('report.pdf.top.layer'),
    t('report.pdf.table.severity'),
    t('report.pdf.table.status'),
    t('report.pdf.table.controlStatus'),
  ];
  const treatmentHeaders = TREATMENTS.map((x) => t(TREATMENT_KEY[x]));
  const treatmentValues = TREATMENTS.map((x) => String(summary.treatmentCounts[x]));
  const controlHeaders = CONTROL_BUCKETS.map((x) => t(CONTROL_KEY[x]));
  const controlValues = CONTROL_BUCKETS.map((x) => String(summary.controlCounts[x]));
  const layerHeaders = [
    t('report.pdf.summary.layer'),
    ...SEVERITY_ORDER,
    t('report.pdf.summary.total'),
    t('report.pdf.summary.suppressed'),
  ];
  const layerRows = summary.byLayer.map((l) => [
    l.layer,
    ...SEVERITY_ORDER.map((s) => String(l.severity[s])),
    String(l.active),
    String(l.suppressed),
  ]);
  layerRows.push([
    t('report.pdf.summary.grandTotal'),
    ...layerHeaders.slice(1).map((_, i) => String(layerRows.reduce((a, r) => a + Number(r[i + 1]), 0))),
  ]);

  // ── 評価の前提 ──
  const premiseRows: [string, string][] = [
    [t('report.pdf.meta.project'), clean(project?.name ?? '')],
    [t('report.pdf.meta.purpose'), clean(project?.purpose ?? '')],
    [t('report.pdf.meta.businessImpact'), clean(project?.businessImpact ?? '')],
    [t('report.pdf.meta.securityObjectives'), clean(project?.securityObjectives ?? '')],
    [t('report.pdf.meta.framework'), first?.framework ?? ''],
    [t('report.pdf.meta.schemaVersion'), String(THREAT_REPORT_SCHEMA_VERSION)],
  ];

  // 使う文字を先に全部集める（描画する文字列はここまでで確定している）。
  const texts: string[] = STATIC_LABEL_KEYS.map((k) => t(k));
  collectStrings(
    [layers, top, systemName, coverLine, metrics, topRows, topHeaders, treatmentHeaders, treatmentValues,
      controlHeaders, controlValues, layerHeaders, layerRows, premiseRows],
    texts,
  );
  const used = texts.join('');

  const subsetter = await createFontSubsetter(input.harfbuzzWasm);
  const doc = await PDFDocument.create();
  doc.registerFontkit(fontkit);
  // liga を切る：既定の fi 等の合字は描画に隙間が出るうえ、テキスト抽出・検索で "fi" が欠ける。
  const embedOpts = { subset: false, features: { liga: false } };
  const reg = await doc.embedFont(subsetter.subset(input.fonts.regular, used), embedOpts);
  const bold = await doc.embedFont(subsetter.subset(input.fonts.bold, used), embedOpts);
  doc.setTitle(`${t('report.pdf.title')} ${systemName}`.trim());
  doc.setCreator(toolLine);
  doc.setProducer(toolLine);
  doc.setCreationDate(input.generatedAt);
  doc.setModificationDate(input.generatedAt);

  const ctx: Ctx = { doc, reg, bold, cursor: createCursor(PAGE_H, MARGIN_TOP, MARGIN_BOTTOM), pages: [] };
  const compact = { padY: 2, maxLines: 2 };
  const equalWidths = (n: number) => Array.from({ length: n }, () => CONTENT_W / n);
  const countCols = (n: number) => Array.from({ length: n }, (_, i) => i);

  // 1. 1 枚サマリ（必ず 1 ページに収める：セルは 2 行まで・表は compact）
  paragraph(ctx, t('report.pdf.title'), { font: bold, size: 20, lineHeight: 26 });
  if (systemName) {
    const [line] = wrapText(systemName, CONTENT_W, 14, measureOf(bold));
    paragraph(ctx, line ?? '', { font: bold, size: 14, lineHeight: 19, color: MUTED });
  }
  paragraph(ctx, coverLine, { size: SMALL, lineHeight: 11, color: MUTED });
  ctx.cursor.advance(6);
  metricBoxes(ctx, metrics);
  heading(ctx, t('report.pdf.top.heading'), 11, 4);
  if (topRows.length === 0) {
    paragraph(ctx, t('report.pdf.top.empty'), { color: MUTED });
  } else {
    table(ctx, topHeaders, [34, 132, 106, 40, 53, 72, 78], topRows, compact); // 幅の根拠は THREAT_WIDTHS の注記。Rank/レイヤー ≈32/39pt
  }
  heading(ctx, t('report.pdf.counts.treatment'), 10, 6);
  table(ctx, treatmentHeaders, equalWidths(TREATMENTS.length), [{ cells: treatmentValues }], {
    ...compact,
    right: countCols(TREATMENTS.length),
  });
  heading(ctx, t('report.pdf.counts.control'), 10, 6);
  table(ctx, controlHeaders, equalWidths(CONTROL_BUCKETS.length), [{ cells: controlValues }], {
    ...compact,
    right: countCols(CONTROL_BUCKETS.length),
  });
  heading(ctx, t('report.pdf.summary.heading'), 10, 6);
  table(
    ctx,
    layerHeaders,
    [75, 55, 55, 55, 55, 85, 135],
    layerRows.map((cells, i) => ({
      cells,
      bold: i === layerRows.length - 1 ? cells.map(() => true) : undefined,
      colors: [undefined, ...SEVERITIES.map((s) => SEVERITY_COLOR[s])],
    })),
    { ...compact, right: [1, 2, 3, 4, 5, 6] },
  );

  // 2. 評価の前提
  breakPage(ctx);
  heading(ctx, t('report.pdf.premise.heading'), 15, 0);
  ctx.cursor.advance(4);
  const labelW = 110;
  for (const [label, value] of premiseRows) {
    if (!value) continue;
    need(ctx, BODY_LH);
    page(ctx).drawText(label, { x: MARGIN_X, y: ctx.cursor.y - BODY, size: SMALL, font: bold, color: MUTED });
    for (const line of wrapText(value, CONTENT_W - labelW, BODY, measureOf(reg))) {
      need(ctx, BODY_LH);
      if (line) {
        page(ctx).drawText(line, { x: MARGIN_X + labelW, y: ctx.cursor.y - BODY, size: BODY, font: reg, color: INK });
      }
      ctx.cursor.advance(BODY_LH);
    }
  }

  // 3. 重要脅威 上位 10 の詳細
  heading(ctx, t('report.pdf.topDetail.heading'), 15, 16);
  if (top.length === 0) paragraph(ctx, t('report.pdf.top.empty'), { color: MUTED });
  for (const r of top) detailBlock(ctx, r, t, true);

  // 4. 付録（レイヤーごと）
  breakPage(ctx);
  paragraph(ctx, t('report.pdf.appendix.heading'), { font: bold, size: 18, lineHeight: 26, color: MUTED });
  ctx.cursor.advance(4);
  for (const [i, l] of layers.entries()) {
    if (i > 0) breakPage(ctx);
    need(ctx, 22 + 20);
    paragraph(ctx, t('report.pdf.layer.heading', { layer: l.layer }), { font: bold, size: 15, lineHeight: 22 });
    ctx.cursor.advance(4);
    if (l.diagramPng) await drawDiagram(ctx, l.diagramPng);
    if (l.active.length === 0 && l.suppressed.length === 0) {
      paragraph(ctx, t('report.pdf.noThreats'), { color: MUTED });
      continue;
    }
    if (l.active.length > 0) threatSection(ctx, t('report.pdf.section.threats'), l.active, t);
    if (l.suppressed.length > 0) threatSection(ctx, t('report.pdf.section.suppressed'), l.suppressed, t);
  }

  // フッタ（全ページ）
  const total = ctx.pages.length;
  ctx.pages.forEach((p, i) => {
    const pageText = t('report.pdf.footer.page', { page: i + 1, total });
    const pw = reg.widthOfTextAtSize(pageText, SMALL);
    p.drawLine({ start: { x: MARGIN_X, y: 36 }, end: { x: MARGIN_X + CONTENT_W, y: 36 }, thickness: 0.4, color: RULE });
    const [sys] = wrapText(systemName, CONTENT_W - pw - 12, SMALL, measureOf(reg));
    if (sys) p.drawText(sys, { x: MARGIN_X, y: 24, size: SMALL, font: reg, color: MUTED });
    p.drawText(pageText, { x: MARGIN_X + CONTENT_W - pw, y: 24, size: SMALL, font: reg, color: MUTED });
  });

  return doc.save();
}
