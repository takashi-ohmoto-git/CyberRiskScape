import { BRANDING } from '../core/branding';
import { formatElementalId } from '../core/model/elementalId';
import { effectiveSeverity } from '../core/model/risk';
import {
  isSuppressed,
  type DiagramBoundary,
  type DiagramEdge,
  type DiagramNode,
  type Finding,
  type ElementRef,
  type Severity,
  type ThreatView,
} from '../core/model/types';
import type { LayerAnalysisResult } from './analyze';

/** `toSarif` のオプション。`artifactUri` は入力ファイルの参照先（相対パス等）。 */
export interface ToSarifOptions {
  artifactUri: string;
  /** 指定し、かつ 1 件以上あるとき、製品ごとの run を run[0] の後ろに追加する（`--with-findings`）。 */
  findings?: readonly Finding[];
}

/** 手動脅威（ルール非経由）に割り当てる固定 ruleId。 */
const MANUAL_THREAT_RULE_ID = 'manual-threat';

/** 実効 severity → SARIF の result level（Critical/High は error、Medium は warning、Low は note）。 */
function sarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'Critical' || severity === 'High') return 'error';
  if (severity === 'Medium') return 'warning';
  return 'note';
}

/** 対象要素（`ThreatView.subject`）の表示ラベル（ElementalID ＋名前）。見つからなければ空文字。 */
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
  return `${id} ${b.label?.trim() || b.vlanName?.trim() || b.blastRadiusLabel?.trim() || b.type}`;
}

/** 脅威 1 件を生成したルールの id（検出脅威はルール id、手動脅威は固定 id）。 */
function ruleIdOf(t: ThreatView): string {
  return t.origin === 'manual' ? MANUAL_THREAT_RULE_ID : t.ruleId ?? MANUAL_THREAT_RULE_ID;
}

interface SarifRule {
  id: string;
  shortDescription: { text: string };
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: [
    {
      physicalLocation: {
        artifactLocation: { uri: string };
      };
    },
  ];
  logicalLocations: [{ name: string; kind: string }];
  partialFingerprints: { threatId: string };
  suppressions?: [{ kind: 'external'; status: 'accepted'; justification: string }];
  properties: {
    severity: Severity;
    effectiveSeverity: Severity;
    layer: string;
    framework: string;
    category: string;
  };
}

/**
 * レイヤー別解析結果（`analyzeProject` の出力）を SARIF 2.1.0 ログへ変換する純粋関数。
 *
 * 受容・誤検知（抑制）は `suppressions`（kind: external）で表現し、`partialFingerprints`
 * に `ThreatView.id` を載せる（同じ脅威の再出力を下流ツールが同一視できるように）。
 */
export function toSarif(
  results: LayerAnalysisResult[],
  { artifactUri, findings }: ToSarifOptions,
): object {
  const rules = new Map<string, SarifRule>();
  const sarifResults: SarifResult[] = [];

  for (const { layer, input } of results) {
    const { threats, nodes, edges, boundaries } = input;
    for (const t of threats) {
      const ruleId = ruleIdOf(t);
      if (!rules.has(ruleId)) {
        rules.set(ruleId, {
          id: ruleId,
          shortDescription: { text: t.name ?? t.category },
        });
      }

      const label = assetLabel(t.subject, nodes, edges, boundaries);
      const title = t.name ?? t.category;
      const messageText = [label, title, t.description].filter((s) => s !== '').join(' - ');
      const effective = effectiveSeverity(t);

      sarifResults.push({
        ruleId,
        level: sarifLevel(effective),
        message: { text: messageText },
        locations: [{ physicalLocation: { artifactLocation: { uri: artifactUri } } }],
        logicalLocations: [{ name: label, kind: 'element' }],
        partialFingerprints: { threatId: t.id },
        ...(isSuppressed(t)
          ? {
              suppressions: [
                {
                  kind: 'external' as const,
                  status: 'accepted' as const,
                  justification: t.suppression?.note ?? '',
                },
              ],
            }
          : {}),
        properties: {
          severity: t.severity,
          effectiveSeverity: effective,
          layer,
          framework: t.framework,
          category: t.category,
        },
      });
    }
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: BRANDING.name,
            rules: [...rules.values()],
          },
        },
        results: sarifResults,
      },
      ...(findings && findings.length > 0 ? findingRuns(results, findings, artifactUri) : []),
    ],
  };
}

/** 変換で持ち越さない情報（形式ごと。SARIF の指摘 run に明記する）。 */
const LOST_IN_CONVERSION: Record<Finding['source']['format'], string[]> = {
  ocsf: ['PASS results (reflected in node posture instead)', 'remediation text', 'resource configuration'],
  xccdf: ['pass/notapplicable/notchecked results', 'rule descriptions and fix text', 'target facts'],
  arf: ['pass/notapplicable/notchecked results', 'rule descriptions and fix text', 'target facts'],
  oval: ['definitions evaluated as not vulnerable', 'test details and collected items'],
};

/** 外部製品の指摘を製品ごとの run にする（docs/architecture.md §8.3）。 */
function findingRuns(results: LayerAnalysisResult[], findings: readonly Finding[], artifactUri: string): object[] {
  const byProduct = new Map<string, Finding[]>();
  for (const f of findings) byProduct.set(f.source.product, [...(byProduct.get(f.source.product) ?? []), f]);

  return [...byProduct.entries()].map(([product, list]) => {
    const rules = new Map<string, { id: string; shortDescription: { text: string } }>();
    const sarifResults = list.map((f) => {
      const ruleId = f.identifiers[0]?.value ?? f.id;
      if (!rules.has(ruleId)) rules.set(ruleId, { id: ruleId, shortDescription: { text: f.title ?? ruleId } });

      // ノードが消えていれば未結合として扱う
      const layerResult = f.subject ? results.find((r) => r.layer === f.subject?.layer) : undefined;
      const node = f.subject ? layerResult?.input.nodes.find((n) => n.id === f.subject?.nodeId) : undefined;
      const nodeLabel =
        layerResult && node && f.subject
          ? assetLabel({ kind: 'node', id: f.subject.nodeId }, layerResult.input.nodes, [], [])
          : '';
      const linkedThreatIds =
        layerResult && node && f.subject
          ? layerResult.threats
              .filter(
                (t) =>
                  t.subject?.kind === 'node' &&
                  t.subject.id === f.subject?.nodeId &&
                  t.canonicalId !== undefined &&
                  f.canonicalIds.includes(t.canonicalId),
              )
              .map((t) => t.id)
          : [];
      const resourceLabel = f.resource?.label ?? '';

      return {
        ruleId,
        level: sarifLevel(f.severity),
        message: { text: [nodeLabel, f.title ?? '', resourceLabel].filter((s) => s !== '').join(' - ') },
        locations: [{ physicalLocation: { artifactLocation: { uri: artifactUri } } }],
        logicalLocations: [{ name: nodeLabel || resourceLabel, kind: 'element' }],
        partialFingerprints: { findingId: f.id },
        properties: {
          severity: f.severity,
          ...(f.sourceSeverity ? { sourceSeverity: f.sourceSeverity } : {}),
          canonicalIds: f.canonicalIds,
          ...(nodeLabel && f.subject ? { layer: f.subject.layer, node: nodeLabel } : {}),
          linkedThreatIds,
          ...(f.observedAt ? { observedAt: f.observedAt } : {}),
          ...(f.resource ? { resource: f.resource } : {}),
        },
      };
    });
    const version = list.find((f) => f.source.productVersion)?.source.productVersion;
    return {
      tool: { driver: { name: product, ...(version ? { version } : {}), rules: [...rules.values()] } },
      conversion: { tool: { driver: { name: BRANDING.name } } },
      results: sarifResults,
      properties: { lostInConversion: [...new Set(list.flatMap((f) => LOST_IN_CONVERSION[f.source.format]))] },
    };
  });
}
