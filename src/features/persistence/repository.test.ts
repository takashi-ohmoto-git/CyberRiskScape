import { afterEach, describe, expect, it } from 'vitest';
import { EMPTY_PROJECT_META } from '../../core/model/types';
import { loadProject, saveProject } from './repository';
import { pickSerializableState, type SerializableState } from './serialize';
import { resetProjectStorage, setProjectStorage, type SaveTrigger } from './storage';

const emptyLayer = () => ({ nodes: [], edges: [], boundaries: [], annotations: [] });
const state = (): SerializableState => ({
  projectId: '00000000-0000-4000-8000-000000000001',
  layers: { L0: emptyLayer(), L1: emptyLayer(), L2: emptyLayer(), L3: emptyLayer(), PQC: emptyLayer() },
  activeLayer: 'L1',
  activeFramework: 'ALL',
  projectMeta: { ...EMPTY_PROJECT_META, name: 'サンプル' },
  vulnIntel: { 'CVE-2026-0001': { kev: { dateAdded: '2026-01-01' } } },
});

/** メモリに持つだけの保存先。 */
function memoryStorage(initial?: unknown) {
  const saves: { project: unknown; trigger: SaveTrigger }[] = [];
  let value = initial;
  setProjectStorage({
    load: async () => value,
    save: async (project, trigger) => {
      value = project;
      saves.push({ project, trigger });
    },
  });
  return saves;
}

describe('saveProject / loadProject', () => {
  afterEach(() => resetProjectStorage());

  it('差し替えた保存先に、保存形式に直した値と、保存のきっかけが渡る。読み込むと同じ内容が戻る', async () => {
    const saves = memoryStorage();
    await saveProject(state());
    await saveProject(state(), 'manual');
    expect(saves.map((s) => s.trigger)).toEqual(['auto', 'manual']);
    expect(saves[1].project).toMatchObject({ projectId: state().projectId, projectMeta: { name: 'サンプル' } });
    const loaded = await loadProject();
    expect(loaded?.projectId).toBe(state().projectId);
    expect(loaded?.projectMeta?.name).toBe('サンプル');
  });

  it('保存先に何も無ければ null。検証に通らない値も null（既定の状態で始める）', async () => {
    memoryStorage();
    expect(await loadProject()).toBeNull();
    memoryStorage({ schemaVersion: 'x' });
    expect(await loadProject()).toBeNull();
  });
});

describe('pickSerializableState', () => {
  it('保存する項目だけを取り出す。projectId と vulnIntel を落とさず、画面の一時的な状態は入れない', () => {
    const picked = pickSerializableState({ ...state(), isHydrated: true, selectedNodeId: 'n1' } as SerializableState);
    expect(picked.projectId).toBe(state().projectId);
    expect(picked.vulnIntel).toEqual(state().vulnIntel);
    expect(Object.keys(picked)).not.toContain('isHydrated');
    expect(Object.keys(picked)).not.toContain('selectedNodeId');
  });
});
