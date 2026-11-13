import { describe, expect, it } from 'vitest';
import { useDiagramStore, type HydratePayload } from './diagramStore';
import { EMPTY_LAYER } from '../model/types';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ID = '3f2a6c1e-8b4d-4f7a-9c21-5d0e7a1bc91e';

const PAYLOAD: HydratePayload = {
  layers: { L0: EMPTY_LAYER, L1: EMPTY_LAYER, L2: EMPTY_LAYER, L3: EMPTY_LAYER, PQC: EMPTY_LAYER },
  activeLayer: 'L1',
  activeFramework: 'ALL',
};

describe('diagramStore projectId（プロジェクトの固有 ID）', () => {
  it('初期状態で UUID を持つ', () => {
    expect(useDiagramStore.getState().projectId).toMatch(UUID_RE);
  });

  it('hydrate: ID を持つデータを開くと、その ID を使う', () => {
    useDiagramStore.getState().hydrate({ ...PAYLOAD, projectId: ID });
    expect(useDiagramStore.getState().projectId).toBe(ID);
  });

  it('hydrate: ID を持たないデータを開くと、新しく採番する', () => {
    useDiagramStore.getState().hydrate({ ...PAYLOAD, projectId: ID });
    useDiagramStore.getState().hydrate(PAYLOAD);
    const id = useDiagramStore.getState().projectId;
    expect(id).toMatch(UUID_RE);
    expect(id).not.toBe(ID);
  });

  it('newProject: 新しい ID を採番する', () => {
    useDiagramStore.getState().hydrate({ ...PAYLOAD, projectId: ID });
    useDiagramStore.getState().newProject();
    const id = useDiagramStore.getState().projectId;
    expect(id).toMatch(UUID_RE);
    expect(id).not.toBe(ID);
  });

  it('regenerateProjectId: ID だけを振り直し、図と概要は変えない', () => {
    useDiagramStore.getState().hydrate({ ...PAYLOAD, projectId: ID });
    useDiagramStore.getState().updateProjectMeta('name', '受注システム');
    const before = useDiagramStore.getState();
    useDiagramStore.getState().regenerateProjectId();
    const after = useDiagramStore.getState();
    expect(after.projectId).toMatch(UUID_RE);
    expect(after.projectId).not.toBe(ID);
    expect(after.layers).toBe(before.layers);
    expect(after.projectMeta.name).toBe('受注システム');
  });

  it('プロジェクト概要の編集・Undo では ID が変わらない', () => {
    useDiagramStore.getState().hydrate({ ...PAYLOAD, projectId: ID });
    useDiagramStore.getState().updateProjectMeta('lifecycle', 'production');
    useDiagramStore.getState().undo();
    expect(useDiagramStore.getState().projectId).toBe(ID);
  });
});
