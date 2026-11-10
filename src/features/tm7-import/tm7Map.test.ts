import { describe, expect, it } from 'vitest';
import { BUNDLED_COMPONENT_LIBRARY } from '../../component-library/loader/bundledComponentLibrary';
import { BUNDLED_TM7_MAP, loadTm7Map, resolveTm7Target } from './tm7Map';

describe('BUNDLED_TM7_MAP', () => {
  const ids = new Set(BUNDLED_COMPONENT_LIBRARY.components.map((c) => c.id));

  it('対応表の寄せ先のノード型はコンポーネントライブラリに実在する', () => {
    const targets = [...BUNDLED_TM7_MAP.types.values(), ...Object.values(BUNDLED_TM7_MAP.generic)];
    const missing = targets.flatMap((t) => (t.node && !ids.has(t.node) ? [t.node] : []));
    expect(missing).toEqual([]);
  });

  it('汎用型（GE.P / GE.EI / GE.DS / GE.DF / GE.TB.B / GE.TB.L）は全部ある', () => {
    for (const g of ['GE.P', 'GE.EI', 'GE.DS', 'GE.DF', 'GE.TB.B', 'GE.TB.L']) {
      expect(BUNDLED_TM7_MAP.generic[g]).toBeDefined();
    }
  });
});

describe('resolveTm7Target', () => {
  it('表に無い TypeId は親の汎用型に落とし、exact=false を返す', () => {
    expect(resolveTm7Target(BUNDLED_TM7_MAP, 'SE.P.Other.X', 'GE.P')).toEqual({ target: { node: 'PROCESS' }, exact: false });
    expect(resolveTm7Target(BUNDLED_TM7_MAP, 'SE.DS.TMCore.SQL', 'GE.DS')?.exact).toBe(true);
  });
});

describe('loadTm7Map', () => {
  it('typeId の重複はエラーにする', () => {
    const text = 'schemaVersion: 1\ngeneric: {}\ntypes:\n  - { typeId: A, node: PROCESS }\n  - { typeId: A, node: PROCESS }\n';
    expect(() => loadTm7Map(text)).toThrow();
  });
});
