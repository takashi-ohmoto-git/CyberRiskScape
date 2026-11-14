import { describe, expect, it } from 'vitest';
import { useDiagramStore } from './diagramStore';
import { EMPTY_LAYER, type VulnIntel } from '../model/types';

const LAYERS = { L0: EMPTY_LAYER, L1: EMPTY_LAYER, L2: EMPTY_LAYER, L3: EMPTY_LAYER, PQC: EMPTY_LAYER };
const INTEL: VulnIntel = { 'CVE-2099-0001': { kev: { dateAdded: '2099-01-01' } } };

describe('diagramStore vulnIntel（CVE ごとの付加情報の持ち回り）', () => {
  it('hydrate: 読み込んだ値を保持する（保存時に書き戻すため）。省略時は undefined', () => {
    useDiagramStore.getState().hydrate({ layers: LAYERS, activeLayer: 'L1', activeFramework: 'ALL', vulnIntel: INTEL });
    expect(useDiagramStore.getState().vulnIntel).toEqual(INTEL);
    useDiagramStore.getState().hydrate({ layers: LAYERS, activeLayer: 'L1', activeFramework: 'ALL' });
    expect(useDiagramStore.getState().vulnIntel).toBeUndefined();
  });

  it('newProject: 前のプロジェクトの値を引き継がない', () => {
    useDiagramStore.getState().hydrate({ layers: LAYERS, activeLayer: 'L1', activeFramework: 'ALL', vulnIntel: INTEL });
    useDiagramStore.getState().newProject();
    expect(useDiagramStore.getState().vulnIntel).toBeUndefined();
  });
});
