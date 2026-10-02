import { BRANDING } from '../core/branding';
import { formatElementalId } from '../core/model/elementalId';
import { effectiveSeverity } from '../core/model/risk';
import {
  isSuppressed,
  type DiagramBoundary,
  type DiagramEdge,
  type DiagramNode,
  type ElementRef,
  type Severity,
  type ThreatView,
} from '../core/model/types';
import type { LayerAnalysisResult } from './analyze';

/** `toSarif` のオプション。`artifactUri` は入力ファイルの参照先（相対パス等）。 */
export interface ToSarifOptions {
  artifactUri: string;
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
  return `${id} ${b.vlanName?.trim() || b.blastRadiusLabel?.trim() || b.type}`;
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
  { artifactUri }: ToSarifOptions,
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
    ],
  };
}
