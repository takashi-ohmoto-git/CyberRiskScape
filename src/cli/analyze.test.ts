import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyzeProject, evaluateGate } from './analyze';
import { serializeProject } from '../features/persistence/serialize';
import { EMPTY_LAYER, type LayerData, type ThreatView } from '../core/model/types';

const FIXTURE_PATH = new URL('./__fixtures__/sample-project.json', import.meta.url);

/** L1 だけにノードを置いた最小プロジェクト（LLM → DB）。 */
function sampleLayers(): Record<'L0' | 'L1' | 'L2' | 'L3', LayerData> {
  const l1: LayerData = {
    nodes: [
      { id: 'n1', seq: 1, type: 'LLM', x: 0, y: 0, label: 'GPT' },
      { id: 'n2', seq: 2, type: 'DB', x: 100, y: 0, label: 'Store' },
    ],
    edges: [
      {
        id: 'e1',
        seq: 1,
        source: 'n1',
        target: 'n2',
        auth: 'None',
        network: 'Internet',
        encryption: 'Plain',
      },
    ],
    boundaries: [],
    annotations: [],
  };
  return { L0: EMPTY_LAYER, L1: l1, L2: EMPTY_LAYER, L3: EMPTY_LAYER };
}

function sampleProjectRaw(): unknown {
  return serializeProject({
    layers: sampleLayers(),
    activeLayer: 'L1',
    activeFramework: 'ALL',
  });
}

describe('analyzeProject', () => {
  it('既定ではノードがあるレイヤーのみを対象にする', () => {
    const results = analyzeProject(sampleProjectRaw());
    expect(results.map((r) => r.layer)).toEqual(['L1']);
    expect(results[0].threats.length).toBeGreaterThan(0);
  });

  it('--layer 相当の指定があればノード数に関わらずそのレイヤーだけを返す', () => {
    const results = analyzeProject(sampleProjectRaw(), { layer: 'L2' });
    expect(results.map((r) => r.layer)).toEqual(['L2']);
    expect(results[0].threats).toEqual([]);
  });

  it('framework で絞り込める（AI は LLM ノードの固有脅威を含む）', () => {
    const results = analyzeProject(sampleProjectRaw(), { layer: 'L1', framework: 'AI' });
    expect(results[0].threats.every((t) => t.framework === 'AI')).toBe(true);
    expect(results[0].threats.length).toBeGreaterThan(0);
  });

  it('不正な入力はエラーを投げる', () => {
    expect(() => analyzeProject({ not: 'a project' })).toThrow();
    expect(() => analyzeProject(null)).toThrow();
  });

  it('CI スモーク用フィクスチャ（sample-project.json）は妥当で、脅威を検出する', () => {
    const raw = JSON.parse(readFileSync(FIXTURE_PATH, 'utf-8'));
    const results = analyzeProject(raw);
    expect(results.map((r) => r.layer)).toEqual(['L1']);
    expect(results[0].threats.length).toBeGreaterThan(0);
  });
});

const BASE: Omit<ThreatView, 'id' | 'severity' | 'suppression'> = {
  nodeId: 'n1',
  framework: 'STRIDE',
  category: 'Spoofing',
  description: 'テスト用の脅威',
  origin: 'detected',
};

describe('evaluateGate', () => {
  it('未抑制かつしきい値以上の脅威だけを返す', () => {
    const threats: ThreatView[] = [
      { ...BASE, id: 't-critical', severity: 'Critical' },
      { ...BASE, id: 't-low', severity: 'Low' },
    ];
    expect(evaluateGate(threats, 'High').map((t) => t.id)).toEqual(['t-critical']);
  });

  it('リスク受容（accepted）は抑制としてゲート対象から外す', () => {
    const threats: ThreatView[] = [
      {
        ...BASE,
        id: 't-accepted',
        severity: 'Critical',
        suppression: { status: 'accepted', at: 0 },
      },
    ];
    expect(evaluateGate(threats, 'High')).toEqual([]);
  });

  it('誤検知（false-positive）は抑制としてゲート対象から外す', () => {
    const threats: ThreatView[] = [
      {
        ...BASE,
        id: 't-fp',
        severity: 'Critical',
        suppression: { status: 'false-positive', at: 0 },
      },
    ];
    expect(evaluateGate(threats, 'High')).toEqual([]);
  });

  it('リスク評価済みなら実効 severity（risk 由来）で判定する', () => {
    const threats: ThreatView[] = [
      {
        ...BASE,
        id: 't-risk',
        severity: 'Low',
        risk: { damage: 3, affectedUsers: 3, reproducibility: 3, exploitability: 3, at: 0 },
      },
    ];
    // damage+affectedUsers=6→High, reproducibility+exploitability=6→High → riskRank High/High=Critical
    expect(evaluateGate(threats, 'Critical').map((t) => t.id)).toEqual(['t-risk']);
  });
});
