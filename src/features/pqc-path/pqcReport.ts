import type {
  CryptoFlow,
  DiagramBoundary,
  DiagramEdge,
  DiagramNode,
  ProjectMeta,
} from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import type { AlgorithmTable, TerminationBehavior } from '../../crypto-behavior/schema';
import { translate, type Locale, type TranslationKey } from '../../i18n';
import { csvRow } from '../export/threatReport';
import { analyzeCryptoPath } from './analyzeCryptoPath';
import type { CryptoSegment, SegmentWarning } from './types';

/**
 * PQC 移行支援レポート（CSV）。区間単位の簡易版で、正規のクリプトインベントリではない
 * （docs/pqc-path-analysis.md §1）。作法は脅威レポート CSV（threatReport.ts）に合わせる。
 * 純粋関数のみ（ダウンロードは呼び出し側）。
 */
export const PQC_REPORT_SCHEMA_VERSION = 1 as const;
export const PQC_REPORT_KIND = 'cyberriskscape-pqc-report' as const;

/** 1 行＝1 区間（経路が無いフローは区間の列が空の 1 行）。値は整形済み文字列。 */
export interface PqcReportRow {
  flow: string;
  route: string;
  segment: string;
  from: string;
  to: string;
  via: string;
  termination: string;
  basis: string;
  protocol: string;
  kex: string;
  signature: string;
  probability: string;
  pqc: string;
  signatureClass: string;
  warnings: string;
}

export interface PqcReport {
  project: ProjectMeta;
  layer: 'PQC';
  locale: Locale;
  flowCount: number;
  segmentCount: number;
  rows: PqcReportRow[];
}

export interface BuildPqcReportInput {
  nodes: readonly DiagramNode[];
  edges: readonly DiagramEdge[];
  boundaries: readonly DiagramBoundary[];
  cryptoFlows: readonly CryptoFlow[];
  behaviors: readonly TerminationBehavior[];
  algorithms: AlgorithmTable;
  projectMeta: ProjectMeta;
  locale: Locale;
}

/** 配列値の連結（カンマを使わないので引用が増えない）。 */
const LIST_SEPARATOR = '; ';
const VIA_SEPARATOR = ' / ';

const COLUMNS: readonly { key: TranslationKey; field: keyof PqcReportRow }[] = [
  { key: 'report.pqc.col.flow', field: 'flow' },
  { key: 'report.pqc.col.route', field: 'route' },
  { key: 'report.pqc.col.segment', field: 'segment' },
  { key: 'report.pqc.col.from', field: 'from' },
  { key: 'report.pqc.col.to', field: 'to' },
  { key: 'report.pqc.col.via', field: 'via' },
  { key: 'report.pqc.col.termination', field: 'termination' },
  { key: 'report.pqc.col.basis', field: 'basis' },
  { key: 'report.pqc.col.protocol', field: 'protocol' },
  { key: 'report.pqc.col.kex', field: 'kex' },
  { key: 'report.pqc.col.signature', field: 'signature' },
  { key: 'report.pqc.col.probability', field: 'probability' },
  { key: 'report.pqc.col.pqc', field: 'pqc' },
  { key: 'report.pqc.col.signatureClass', field: 'signatureClass' },
  { key: 'report.pqc.col.warnings', field: 'warnings' },
];

export function buildPqcReport(input: BuildPqcReportInput): PqcReport {
  const { nodes, edges, boundaries, cryptoFlows, behaviors, algorithms, projectMeta, locale } = input;
  const tr = (key: string) => translate(key as TranslationKey, locale);
  const nodeById = new Map(nodes.map((n) => [n.id, n]));

  /** ElementalID ＋ラベル（`C3 ロードバランサー`）。ノードが無ければ ID のまま。 */
  const label = (id: string): string => {
    const n = nodeById.get(id);
    if (!n) return id;
    const name = getNodeDisplayName(n);
    return n.seq !== undefined ? `${formatElementalId('node', n.seq)} ${name}` : name;
  };
  const needsReview = tr('panels.crypto.confidence.unknown');
  const orReview = (values: string[]) => (values.length > 0 ? values.join(LIST_SEPARATOR) : needsReview);

  const segmentRow = (
    flow: string,
    route: number,
    no: number,
    s: CryptoSegment,
    extraWarnings: string[],
  ): PqcReportRow => {
    const term = s.startTermination;
    return {
      flow,
      route: String(route),
      segment: String(no),
      from: label(s.fromNodeId),
      to: label(s.toNodeId),
      via: s.viaNodeIds.map(label).join(VIA_SEPARATOR),
      termination:
        term.value === 'endpoint'
          ? tr('panels.crypto.terminationEndpoint')
          : tr(`panels.crypto.termination.${term.value}`),
      basis:
        tr(`panels.crypto.confidence.${term.confidence}`) +
        (s.providerManaged ? tr('report.pqc.providerManaged') : ''),
      protocol: s.protocols.join(LIST_SEPARATOR),
      kex: orReview(s.kex),
      signature: orReview(s.signatures),
      probability: tr(`panels.crypto.probability.${s.probability}`),
      pqc: tr(`panels.crypto.class.${s.pqc}`),
      signatureClass: tr(`panels.crypto.class.${s.signatureClass}`),
      warnings: [
        ...extraWarnings,
        ...s.warnings.map((w: SegmentWarning) => tr(`report.pqc.warning.${w}`)),
      ].join(LIST_SEPARATOR),
    };
  };

  const rows: PqcReportRow[] = [];
  for (const f of cryptoFlows) {
    const flowName = f.label?.trim() || `${label(f.sourceId)} → ${label(f.targetId)}`;
    const result = analyzeCryptoPath({
      nodes,
      edges,
      boundaries,
      sourceId: f.sourceId,
      targetId: f.targetId,
      behaviors,
      algorithms,
    });
    if (result.routes.length === 0) {
      rows.push({
        flow: flowName,
        route: '',
        segment: '',
        from: '',
        to: '',
        via: '',
        termination: '',
        basis: '',
        protocol: '',
        kex: '',
        signature: '',
        probability: '',
        pqc: '',
        signatureClass: '',
        warnings: tr('report.pqc.warning.noRoute'),
      });
      continue;
    }
    const extra = result.undirectedFallback ? [tr('report.pqc.warning.undirected')] : [];
    // 全経路で同一の区間（始点・終点・エッジ列が同じ）は最初の経路だけに出す。
    // 区間 No はその経路内での位置（画面の表と同じ番号）。
    const seen = new Set<string>();
    result.routes.forEach((route, ri) => {
      route.segments.forEach((s, si) => {
        const key = `${s.fromNodeId}|${s.toNodeId}|${s.edgeIds.join(',')}`;
        if (seen.has(key)) return;
        seen.add(key);
        rows.push(segmentRow(flowName, ri + 1, si + 1, s, extra));
      });
    });
  }

  return {
    project: projectMeta,
    layer: 'PQC',
    locale,
    flowCount: cryptoFlows.length,
    segmentCount: rows.filter((r) => r.segment !== '').length,
    rows,
  };
}

/**
 * CSV（UTF-8 / CRLF）。先頭にバージョン行 → メタ情報 → 注記 → 空行 → 表。
 * BOM は付けない（ダウンロード時に付与する）。
 */
export function toPqcCsv(report: PqcReport): string {
  const tr = (key: TranslationKey) => translate(key, report.locale);
  const { project } = report;
  const lines: string[] = [
    csvRow([tr('report.csv.meta.schemaVersion'), String(PQC_REPORT_SCHEMA_VERSION)]),
    csvRow(['kind', PQC_REPORT_KIND]),
    csvRow([tr('report.csv.meta.projectName'), project.name]),
    csvRow([tr('report.csv.meta.systemName'), project.systemName]),
    csvRow([tr('report.csv.meta.layer'), report.layer]),
    csvRow([tr('report.pqc.meta.flowCount'), String(report.flowCount)]),
    csvRow([tr('report.pqc.meta.segmentCount'), String(report.segmentCount)]),
    csvRow([tr('report.pqc.meta.note'), tr('report.pqc.note')]),
    '',
    csvRow(COLUMNS.map((c) => tr(c.key))),
  ];
  for (const r of report.rows) lines.push(csvRow(COLUMNS.map((c) => r[c.field])));
  return lines.join('\r\n');
}
