import { describe, expect, it } from 'vitest';
import { toSarif } from './sarif';
import type { LayerAnalysisResult } from './analyze';
import { BRANDING } from '../core/branding';
import { EMPTY_PROJECT_META, type DiagramNode, type Finding, type ThreatView } from '../core/model/types';

/** テスト内で参照するフィールドのみを持つ SARIF ログの最小形（`any` を避けるため）。 */
interface SarifLog {
  $schema: string;
  version: string;
  runs: {
    tool: { driver: { name: string; rules: { id: string; shortDescription: { text: string } }[] } };
    results: {
      ruleId: string;
      level: string;
      message: { text: string };
      locations: { physicalLocation: { artifactLocation: { uri: string } } }[];
      logicalLocations: { name: string; kind: string }[];
      partialFingerprints: { threatId: string };
      suppressions?: { kind: string; status: string; justification: string }[];
      properties: {
        severity: string;
        effectiveSeverity: string;
        layer: string;
        framework: string;
        category: string;
      };
    }[];
  }[];
}

const NODES: DiagramNode[] = [{ id: 'n1', seq: 1, type: 'LLM', x: 0, y: 0, label: 'GPT' }];

const DETECTED: ThreatView = {
  id: 'rule-a-n1',
  ruleId: 'rule-a',
  subject: { kind: 'node', id: 'n1' },
  nodeId: 'n1',
  framework: 'AI',
  category: 'モデル抽出',
  name: 'モデル反転',
  severity: 'High',
  description: '出力からトレーニングデータを推測できる',
  origin: 'detected',
};

const SUPPRESSED: ThreatView = {
  id: 'rule-b-n1',
  ruleId: 'rule-b',
  subject: { kind: 'node', id: 'n1' },
  nodeId: 'n1',
  framework: 'AI',
  category: '情報漏えい',
  severity: 'Critical',
  description: '受容済みのリスク',
  origin: 'detected',
  suppression: { status: 'accepted', note: '影響が小さいため受容', at: 0 },
};

function results(threats: ThreatView[]): LayerAnalysisResult[] {
  return [
    {
      layer: 'L1',
      threats,
      input: {
        threats,
        nodes: NODES,
        edges: [],
        boundaries: [],
        projectMeta: EMPTY_PROJECT_META,
        framework: 'ALL',
        layer: 'L1',
      },
    },
  ];
}

describe('toSarif', () => {
  it('SARIF 2.1.0 の形を満たす', () => {
    const sarif = toSarif(results([DETECTED]), { artifactUri: 'sample.json' }) as SarifLog;
    expect(sarif.$schema).toBe('https://json.schemastore.org/sarif-2.1.0.json');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].tool.driver.name).toBe('CyberRiskScape');
    expect(sarif.runs[0].tool.driver.rules).toEqual([
      { id: 'rule-a', shortDescription: { text: 'モデル反転' } },
    ]);
  });

  it('High は error、asset ラベルと説明文を message.text に含める', () => {
    const sarif = toSarif(results([DETECTED]), { artifactUri: 'sample.json' }) as SarifLog;
    const r = sarif.runs[0].results[0];
    expect(r.ruleId).toBe('rule-a');
    expect(r.level).toBe('error');
    expect(r.message.text).toContain('C1 GPT');
    expect(r.message.text).toContain('モデル反転');
    expect(r.locations[0].physicalLocation.artifactLocation.uri).toBe('sample.json');
    expect(r.logicalLocations[0]).toEqual({ name: 'C1 GPT', kind: 'element' });
    expect(r.partialFingerprints.threatId).toBe('rule-a-n1');
    expect(r.suppressions).toBeUndefined();
    expect(r.properties).toEqual({
      severity: 'High',
      effectiveSeverity: 'High',
      layer: 'L1',
      framework: 'AI',
      category: 'モデル抽出',
    });
  });

  it('受容済み（accepted）は suppressions を付与する', () => {
    const sarif = toSarif(results([SUPPRESSED]), { artifactUri: 'sample.json' }) as SarifLog;
    const r = sarif.runs[0].results[0];
    expect(r.suppressions).toEqual([
      { kind: 'external', status: 'accepted', justification: '影響が小さいため受容' },
    ]);
  });

  it('手動脅威は ruleId=manual-threat を使う', () => {
    const manual: ThreatView = {
      id: 'mt1',
      nodeId: '',
      framework: 'AgenticAI',
      category: '運用上の懸念',
      severity: 'Medium',
      description: '手動で追加した脅威',
      origin: 'manual',
      manualId: 'mt1',
    };
    const sarif = toSarif(results([manual]), { artifactUri: 'sample.json' }) as SarifLog;
    expect(sarif.runs[0].results[0].ruleId).toBe('manual-threat');
    expect(sarif.runs[0].results[0].level).toBe('warning');
  });
});

describe('toSarif（指摘 run）', () => {
  const finding = (over: Partial<Finding>): Finding => ({
    id: 'Prowler:f1',
    source: { format: 'ocsf', product: 'Prowler', productVersion: '5.0.0', importedAt: 't' },
    externalId: 'f1',
    identifiers: [{ scheme: 'prowler-check', value: 'chk_a' }],
    title: '指摘 A',
    severity: 'High',
    sourceSeverity: 'high',
    canonicalIds: ['canon-a'],
    subject: { layer: 'L1', nodeId: 'n1' },
    resource: { label: 'res-1' },
    ...over,
  });
  const linked: ThreatView = { ...DETECTED, canonicalId: 'canon-a' };
  type Run = {
    tool: { driver: { name: string; version?: string; rules: { id: string }[] } };
    conversion?: { tool: { driver: { name: string } } };
    results: { ruleId: string; level: string; partialFingerprints: { findingId: string }; properties: Record<string, unknown>; logicalLocations: { name: string }[] }[];
    properties?: { lostInConversion: string[] };
  };

  it('findings を渡さない・空なら run は 1 つのまま', () => {
    const a = toSarif(results([linked]), { artifactUri: 'x.json' });
    expect(toSarif(results([linked]), { artifactUri: 'x.json', findings: [] })).toEqual(a);
    expect((a as SarifLog).runs).toHaveLength(1);
  });

  it('製品ごとの run を足し、変換元として本ツールを記す', () => {
    const sarif = toSarif(results([linked]), { artifactUri: 'x.json', findings: [finding({})] }) as { runs: Run[] };
    expect(sarif.runs).toHaveLength(2);
    const run = sarif.runs[1];
    expect(run.tool.driver).toMatchObject({ name: 'Prowler', version: '5.0.0', rules: [{ id: 'chk_a' }] });
    expect(run.conversion?.tool.driver.name).toBe(BRANDING.name);
    expect(run.properties?.lostInConversion.length).toBeGreaterThan(0);
    const r = run.results[0];
    expect(r.ruleId).toBe('chk_a');
    expect(r.level).toBe('error');
    expect(r.partialFingerprints.findingId).toBe('Prowler:f1');
    expect(r.logicalLocations[0].name).toBe('C1 GPT');
    expect(r.properties).toMatchObject({ layer: 'L1', node: 'C1 GPT', linkedThreatIds: ['rule-a-n1'], canonicalIds: ['canon-a'] });
  });

  it('未結合・ノード消失・canonicalId 不一致では linkedThreatIds が空', () => {
    const list = [
      finding({ id: 'p:1', subject: undefined }),
      finding({ id: 'p:2', subject: { layer: 'L1', nodeId: 'gone' } }),
      finding({ id: 'p:3', canonicalIds: ['other'] }),
    ];
    const sarif = toSarif(results([linked]), { artifactUri: 'x.json', findings: list }) as { runs: Run[] };
    const rs = sarif.runs[1].results;
    expect(rs.map((r) => r.properties.linkedThreatIds)).toEqual([[], [], []]);
    expect(rs[0].properties.node).toBeUndefined();
    expect(rs[1].properties.layer).toBeUndefined();
    expect(rs[0].logicalLocations[0].name).toBe('res-1');
  });

  it('SCAP の指摘：ruleId は identifiers[0]、失うものは形式ごと（混在は和集合）', () => {
    const scap = (format: 'xccdf' | 'arf' | 'oval', id: string): Finding =>
      finding({
        id: `OpenSCAP:${id}`,
        source: { format, product: 'OpenSCAP', productVersion: '1.3.8', scope: 'web01', importedAt: 't' },
        identifiers: [{ scheme: format === 'oval' ? 'oval-def' : 'xccdf-rule', value: id }],
      });
    const x = toSarif(results([linked]), { artifactUri: 'x.json', findings: [finding({}), scap('xccdf', 'xccdf_rule_1')] }) as { runs: Run[] };
    expect(x.runs).toHaveLength(3);
    const run = x.runs[2];
    expect(run.tool.driver).toMatchObject({ name: 'OpenSCAP', version: '1.3.8' });
    expect(run.results[0].ruleId).toBe('xccdf_rule_1');
    expect(run.properties?.lostInConversion).toEqual([
      'pass/notapplicable/notchecked results',
      'rule descriptions and fix text',
      'target facts',
    ]);
    const o = toSarif(results([linked]), { artifactUri: 'x.json', findings: [scap('oval', 'oval:x:def:1')] }) as { runs: Run[] };
    expect(o.runs[1].properties?.lostInConversion).toEqual([
      'definitions evaluated as not vulnerable',
      'test details and collected items',
    ]);
    const mixed = toSarif(results([linked]), { artifactUri: 'x.json', findings: [scap('xccdf', 'a'), scap('oval', 'b')] }) as { runs: Run[] };
    expect(mixed.runs[1].properties?.lostInConversion).toHaveLength(5);
  });
});
