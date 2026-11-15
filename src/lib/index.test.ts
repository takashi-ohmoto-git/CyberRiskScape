import { describe, expect, it } from 'vitest';
import * as lib from './index';

/** 外から使われる名前。消したり名前を変えたりすると、利用側が壊れる。 */
const FUNCTIONS = [
  'deserializeProject',
  'serializeProject',
  'normalizeProject',
  'resolveProject',
  'analyzeResolvedProject',
  'analyzeProject',
  'findOrphanedJudgementsInProject',
  'findOrphanedJudgements',
  'effectiveSeverity',
  'computeIndicators',
  'computeAttackPathExposure',
  'loadIndicatorWeights',
  'projectIndicators',
  'diffProjects',
  'identityKey',
  'normalizeIdentifiers',
  'scopeContains',
  'matchServiceScope',
  'buildAssetViews',
  'listBomComponents',
  'applyVulnIntel',
] as const;

const LEGACY = {
  schemaVersion: lib.PERSISTED_PROJECT_SCHEMA_VERSION,
  nodes: [
    { id: 'n1', type: 'USER', x: 0, y: 0 },
    { id: 'n2', type: 'LLM', x: 200, y: 0 },
  ],
  edges: [{ id: 'e1', source: 'n1', target: 'n2', auth: 'Password', network: 'VPC', encryption: 'TLS' }],
  boundaries: [],
  activeFramework: 'ALL',
  updatedAt: 1,
};

describe('lib（外部から使う入口）', () => {
  it.each(FUNCTIONS)('%s を関数として出している', (name) => {
    expect(typeof lib[name]).toBe('function');
  });

  it('値として出しているもの（スキーマ・同梱の重み・識別子の一覧・レイヤーの鍵）がある', () => {
    expect(lib.PersistedProjectSchema).toBeDefined();
    expect(lib.BUNDLED_INDICATOR_WEIGHTS).toBeDefined();
    expect(lib.IDENTIFIER_SCHEMES).toBeDefined();
    expect(lib.LAYER_KEYS).toContain('L1');
  });

  it('旧形式のプロジェクトを現行に直しても、判定と指標の結果は変わらない', () => {
    const normalized = lib.normalizeProject(LEGACY);
    expect(normalized).not.toBeNull();
    const before = lib.projectIndicators(LEGACY);
    const after = lib.projectIndicators(normalized);
    expect(before.indicators.total).toBeGreaterThan(0);
    expect(after).toEqual(before);
  });
});
