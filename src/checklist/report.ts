import type { ProjectMeta } from '../core/model/types';
import { translate, type Locale, type TranslationKey } from '../i18n';
import { csvRow } from '../features/export/threatReport';
import { ITEM_STATUSES, type ChecklistResult, type ItemResult } from './evaluate';

/**
 * 注意喚起チェックリストの出力（CSV / Markdown / JSON）。純粋関数のみ（ダウンロードは呼び出し側）。
 * CSV の作法は PQC レポート CSV（pqcReport.ts）に合わせる。
 */
export const CHECKLIST_REPORT_SCHEMA_VERSION = 1 as const;
export const CHECKLIST_REPORT_KIND = 'cyberriskscape-checklist-report' as const;

const LIST_SEPARATOR = '; ';

export interface ChecklistReportContext {
  result: ChecklistResult;
  project: ProjectMeta;
  /** 判定したレイヤー。 */
  layer: string;
  locale: Locale;
}

const statusLabel = (r: ItemResult, locale: Locale) =>
  translate(`checklist.status.${r.status}` as TranslationKey, locale);

function sourceText(c: ChecklistResult['checklist'], locale: Locale): string {
  return translate('checklist.source', locale, {
    publisher: c.source.publisher,
    title: c.source.title,
    date: c.source.publishedAt,
  });
}

function summaryText(result: ChecklistResult, locale: Locale): string {
  return ITEM_STATUSES.map(
    (s) => `${translate(`checklist.status.${s}` as TranslationKey, locale)} ${result.summary[s]}`,
  ).join(LIST_SEPARATOR);
}

/** CSV（UTF-8 / CRLF）。先頭にバージョン行 → メタ情報 → 注記 → 空行 → 項目表 → 空行 → 点検が古いノード表。BOM はダウンロード時に付与する。 */
export function toChecklistCsv(ctx: ChecklistReportContext): string {
  const { result, project, layer, locale } = ctx;
  const tr = (key: TranslationKey, params?: Record<string, string | number>) => translate(key, locale, params);
  const lines: string[] = [
    csvRow([tr('report.csv.meta.schemaVersion'), String(CHECKLIST_REPORT_SCHEMA_VERSION)]),
    csvRow(['kind', CHECKLIST_REPORT_KIND]),
    csvRow([tr('report.csv.meta.projectName'), project.name]),
    csvRow([tr('report.csv.meta.systemName'), project.systemName]),
    csvRow([tr('report.csv.meta.layer'), layer]),
    csvRow([tr('checklist.csv.meta.checklist'), result.checklist.title]),
    csvRow([tr('checklist.csv.meta.source'), `${sourceText(result.checklist, locale)} ${result.checklist.source.url}`]),
    csvRow([tr('checklist.csv.meta.asOf'), result.asOf]),
    csvRow([tr('checklist.csv.meta.staleDays'), String(result.checklist.staleDays)]),
    csvRow([tr('checklist.csv.meta.summary'), summaryText(result, locale)]),
    csvRow([tr('checklist.csv.meta.note'), tr('checklist.disclaimer')]),
    '',
    csvRow([
      tr('checklist.csv.col.group'),
      tr('checklist.csv.col.no'),
      tr('checklist.csv.col.item'),
      tr('checklist.csv.col.status'),
      tr('checklist.csv.col.targets'),
      tr('checklist.csv.col.relatedCount'),
      tr('checklist.csv.col.action'),
      tr('checklist.csv.col.unfilled'),
      tr('checklist.csv.col.accepted'),
      tr('checklist.csv.col.nodes'),
      tr('checklist.csv.col.howTo'),
      tr('checklist.csv.col.actionNodes'),
    ]),
  ];
  for (const g of result.groups) {
    for (const r of g.items) {
      lines.push(
        csvRow([
          g.group.title,
          r.item.id,
          r.item.title,
          statusLabel(r, locale),
          String(r.targetNodeCount),
          String(r.nodes.length),
          String(r.counts.action),
          String(r.counts.unfilled),
          String(r.counts.accepted),
          r.nodes.map((n) => n.label).join(LIST_SEPARATOR),
          r.item.howTo,
          r.actionNodes.map((n) => n.label).join(LIST_SEPARATOR),
        ]),
      );
    }
  }
  lines.push('', csvRow([tr('checklist.stale.heading')]));
  lines.push(csvRow([tr('checklist.stale.col.node'), tr('checklist.stale.col.state')]));
  for (const s of result.staleNodes) lines.push(csvRow([s.node.label, staleText(s, locale)]));
  return lines.join('\r\n');
}

function staleText(s: ChecklistResult['staleNodes'][number], locale: Locale): string {
  return s.reason === 'unrecorded'
    ? translate('checklist.stale.unrecorded', locale)
    : translate('checklist.stale.stale', locale, { date: s.lastReviewedAt ?? '', days: s.daysSince ?? 0 });
}

/** Markdown。`|` は表を壊すのでエスケープする。 */
export function toChecklistMarkdown(ctx: ChecklistReportContext): string {
  const { result, layer, locale } = ctx;
  const tr = (key: TranslationKey, params?: Record<string, string | number>) => translate(key, locale, params);
  const cell = (v: string) => v.replace(/\|/g, '\\|');
  const out: string[] = [
    `# ${result.checklist.title}`,
    '',
    `- ${sourceText(result.checklist, locale)} <${result.checklist.source.url}>`,
    `- ${tr('checklist.csv.meta.asOf')}: ${result.asOf}`,
    `- ${tr('checklist.md.layer')}: ${layer}`,
    '',
    `> ${tr('checklist.disclaimer')}`,
    '',
    `## ${tr('checklist.md.summary')}`,
    '',
    summaryText(result, locale),
  ];
  for (const g of result.groups) {
    out.push(
      '',
      `## ${g.group.title}`,
      '',
      `| ${tr('checklist.md.col.no')} | ${tr('checklist.md.col.item')} | ${tr('checklist.md.col.status')} | ${tr('checklist.md.col.nodes')} |`,
      '|---|---|---|---|',
    );
    for (const r of g.items) {
      out.push(
        `| ${r.item.id} | ${cell(r.item.title)} | ${statusLabel(r, locale)} | ${cell(r.nodes.map((n) => n.label).join(', '))} |`,
      );
    }
  }
  out.push('', `## ${tr('checklist.stale.heading')}`, '');
  out.push(tr('checklist.stale.intro', { days: result.checklist.staleDays, asOf: result.asOf }), '');
  if (result.staleNodes.length === 0) {
    out.push(tr('checklist.stale.none'));
  } else {
    out.push(`| ${tr('checklist.stale.col.node')} | ${tr('checklist.stale.col.state')} |`, '|---|---|');
    for (const s of result.staleNodes) out.push(`| ${cell(s.node.label)} | ${staleText(s, locale)} |`);
  }
  return out.join('\n');
}

/** JSON（機械可読。状態は言語に依存しないコードで出す）。 */
export function toChecklistJson(ctx: ChecklistReportContext): object {
  const { result, project, layer } = ctx;
  return {
    schemaVersion: CHECKLIST_REPORT_SCHEMA_VERSION,
    kind: CHECKLIST_REPORT_KIND,
    project: { name: project.name, systemName: project.systemName },
    layer,
    checklist: {
      id: result.checklist.id,
      title: result.checklist.title,
      source: result.checklist.source,
      staleDays: result.checklist.staleDays,
    },
    asOf: result.asOf,
    summary: result.summary,
    groups: result.groups.map((g) => ({
      id: g.group.id,
      title: g.group.title,
      items: g.items.map((r) => ({
        id: r.item.id,
        title: r.item.title,
        status: r.status,
        targetNodeCount: r.targetNodeCount,
        counts: r.counts,
        nodes: r.nodes.map((n) => n.label),
        actionNodes: r.actionNodes.map((n) => n.label),
        howTo: r.item.howTo,
        ruleIds: r.item.ruleIds,
      })),
    })),
    staleNodes: result.staleNodes.map((s) => ({
      node: s.node.label,
      reason: s.reason,
      ...(s.lastReviewedAt ? { lastReviewedAt: s.lastReviewedAt, daysSince: s.daysSince } : {}),
    })),
  };
}
