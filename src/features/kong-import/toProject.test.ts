import { describe, expect, it } from 'vitest';
import { EMPTY_LAYER } from '../../core/model/types';
import { layerToProject } from './toProject';

describe('layerToProject', () => {
  it('name を渡すと projectMeta のプロジェクト名に入る', () => {
    expect(layerToProject(EMPTY_LAYER, 'テスト案件').projectMeta?.name).toBe('テスト案件');
  });
  it('name を渡さなければ projectMeta は付かない', () => {
    expect(layerToProject(EMPTY_LAYER).projectMeta).toBeUndefined();
  });
});
