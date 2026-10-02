import { describe, expect, it } from 'vitest';
import { toSarif } from './sarif';
import type { LayerAnalysisResult } from './analyze';
import { EMPTY_PROJECT_META, type DiagramNode, type ThreatView } from '../core/model/types';

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
