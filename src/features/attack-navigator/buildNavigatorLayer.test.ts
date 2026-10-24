import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { buildNavigatorLayer, navigatorLayerToJson, type NavigatorInput } from './buildNavigatorLayer';
import { analyzeProject } from '../../cli/analyze';
import { EMPTY_PROJECT_META, type ThreatView } from '../../core/model/types';

const NOW = new Date('2026-10-20T12:00:00Z');

function threat(partial: Partial<ThreatView>): ThreatView {
  return {
    id: 't1',
    origin: 'detected',
    nodeId: 'n1',
    framework: 'STRIDE',
    category: 'c',
    severity: 'High',
    description: 'd',
    ...partial,
  } as ThreatView;
}

describe('buildNavigatorLayer', () => {
  it('references から ATT&CK technique を拾い、ATLAS は分離する', () => {
    const input: NavigatorInput = {
      projectMeta: EMPTY_PROJECT_META,
      threats: [
        threat({
          name: 'A',
          severity: 'Critical',
          references: [{ title: 'ATT&CK T1078.004', url: 'https://attack.mitre.org/techniques/T1078/004' }],
        }),
        threat({
          id: 't2',
          name: 'B',
          severity: 'Medium',
          references: [{ title: 'MITRE ATLAS AML.T0051', url: 'https://atlas.mitre.org/techniques/AML.T0051' }],
        }),
      ],
    };
    const layer = buildNavigatorLayer(input, NOW, 'ja');
    expect(layer.domain).toBe('enterprise-attack');
    expect(layer.techniques.map((x) => x.techniqueID)).toContain('T1078.004');
    // ATLAS の AML.T0051 は Enterprise technique に混ざらない
    expect(layer.techniques.map((x) => x.techniqueID)).not.toContain('T0051');
    expect(layer.atlasTechniques).toContain('AML.T0051');
    // Critical は score 100
    expect(layer.techniques.find((x) => x.techniqueID === 'T1078.004')?.score).toBe(100);
  });

  it('同じ technique は最大severityで畳み込み、脅威名を comment に集約する', () => {
    const input: NavigatorInput = {
      projectMeta: EMPTY_PROJECT_META,
      threats: [
        threat({ name: 'low one', severity: 'Low', references: [{ title: 'T1098' }] }),
        threat({ id: 't2', name: 'high one', severity: 'High', references: [{ title: 'T1098' }] }),
      ],
    };
    const layer = buildNavigatorLayer(input, NOW, 'ja');
    const tech = layer.techniques.find((x) => x.techniqueID === 'T1098');
    expect(tech?.score).toBe(75); // High が勝つ
    expect(tech?.comment).toContain('low one');
    expect(tech?.comment).toContain('high one');
  });

  it('抑制した脅威と references 無しは拾わない', () => {
    const input: NavigatorInput = {
      projectMeta: EMPTY_PROJECT_META,
      threats: [
        threat({ references: [{ title: 'T1195' }], suppression: { status: 'accepted' } as never }),
        threat({ id: 't2', references: undefined }),
      ],
    };
    const layer = buildNavigatorLayer(input, NOW, 'ja');
    expect(layer.techniques).toHaveLength(0);
  });

  it('JSON は Navigator の標準フィールドのみで、atlasTechniques を含まない', () => {
    const input: NavigatorInput = {
      projectMeta: EMPTY_PROJECT_META,
      threats: [threat({ references: [{ title: 'T1484.001', url: 'https://atlas.mitre.org/techniques/AML.T0088' }] })],
    };
    const parsed = JSON.parse(navigatorLayerToJson(buildNavigatorLayer(input, NOW, 'ja')));
    expect(parsed.versions.layer).toBe('4.5');
    expect(parsed.techniques[0].techniqueID).toBe('T1484.001');
    expect(parsed.atlasTechniques).toBeUndefined();
    // ATLAS は説明文に残る
    expect(parsed.description).toContain('AML.T0088');
  });

  it('sample-project でも有効な Navigator レイヤー構造を出す', () => {
    const raw = JSON.parse(readFileSync('src/cli/__fixtures__/sample-project.json', 'utf-8'));
    const layer = buildNavigatorLayer(analyzeProject(raw)[0].input, NOW, 'ja');
    expect(layer.versions.layer).toBe('4.5');
    expect(Array.isArray(layer.techniques)).toBe(true);
    for (const x of layer.techniques) {
      expect(x.techniqueID).toMatch(/^T\d{4}(\.\d{3})?$/);
      expect(x.score).toBeGreaterThan(0);
    }
  });
});
