import { describe, expect, it } from 'vitest';
import { deserializeProject, serializeProject, type SerializableState } from './serialize';
import { EMPTY_LAYER, EMPTY_PROJECT_META, PROJECT_LIFECYCLES } from '../../core/model/types';

const ID = '3f2a6c1e-8b4d-4f7a-9c21-5d0e7a1bc91e';

const STATE: SerializableState = {
  layers: { L0: EMPTY_LAYER, L1: EMPTY_LAYER, L2: EMPTY_LAYER, L3: EMPTY_LAYER, PQC: EMPTY_LAYER },
  activeLayer: 'L1',
  activeFramework: 'ALL',
};

describe('serializeProject / deserializeProject（プロジェクト ID と組織上の属性）', () => {
  it('projectId を渡すと保存し、読み戻しても同じ ID になる', () => {
    const saved = serializeProject({ ...STATE, projectId: ID });
    expect(saved.projectId).toBe(ID);
    expect(deserializeProject(JSON.parse(JSON.stringify(saved)))?.projectId).toBe(ID);
  });

  it('projectId を渡さなければ、保存データに projectId のキーを作らない', () => {
    expect('projectId' in serializeProject(STATE)).toBe(false);
  });

  it('projectId の無い旧データはそのまま読める（ID は undefined）', () => {
    const loaded = deserializeProject(JSON.parse(JSON.stringify(serializeProject(STATE))));
    expect(loaded).not.toBeNull();
    expect(loaded?.projectId).toBeUndefined();
  });

  it('projectId の形が不正でも、プロジェクト全体は読み込み、ID だけを捨てる', () => {
    const raw = { ...JSON.parse(JSON.stringify(serializeProject(STATE))), projectId: 'not-a-uuid' };
    const loaded = deserializeProject(raw);
    expect(loaded).not.toBeNull();
    expect(loaded?.projectId).toBeUndefined();
  });

  it('組織上の属性だけを入力したプロジェクト概要も保存し、読み戻せる', () => {
    const projectMeta = {
      ...EMPTY_PROJECT_META,
      organizationName: 'サンプル商事株式会社',
      organizationCode: 'ORG-001',
      department: '情報システム部',
      externalSystemId: 'SYS-0042',
      criticality: 'High' as const,
      lifecycle: 'legacy' as const,
    };
    const saved = serializeProject({ ...STATE, projectMeta });
    expect(saved.projectMeta).toEqual(projectMeta);
    expect(deserializeProject(JSON.parse(JSON.stringify(saved)))?.projectMeta).toEqual(projectMeta);
  });

  it.each(PROJECT_LIFECYCLES)('運用段階 %s を読み込める', (lifecycle) => {
    const saved = serializeProject({ ...STATE, projectMeta: { ...EMPTY_PROJECT_META, lifecycle } });
    expect(deserializeProject(JSON.parse(JSON.stringify(saved)))?.projectMeta?.lifecycle).toBe(lifecycle);
  });

  it('未定義の運用段階・重要度は検証で落とす', () => {
    const base = JSON.parse(JSON.stringify(serializeProject({ ...STATE, projectMeta: EMPTY_PROJECT_META })));
    const meta = { name: 'x', systemName: '', purpose: '', businessImpact: '', securityObjectives: '' };
    expect(deserializeProject({ ...base, projectMeta: { ...meta, lifecycle: 'archived' } })).toBeNull();
    expect(deserializeProject({ ...base, projectMeta: { ...meta, criticality: 'Critical' } })).toBeNull();
  });
});
