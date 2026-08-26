import { describe, expect, it } from 'vitest';
import { ELEMENTAL_ID_PREFIX, formatElementalId } from './elementalId';

describe('formatElementalId', () => {
  it('コンポーネント（node）は C 接頭辞', () => {
    expect(formatElementalId('node', 1)).toBe('C1');
    expect(formatElementalId('node', 42)).toBe('C42');
  });

  it('データフロー（edge）は DF 接頭辞', () => {
    expect(formatElementalId('edge', 1)).toBe('DF1');
  });

  it('境界（boundary）は Z 接頭辞', () => {
    expect(formatElementalId('boundary', 7)).toBe('Z7');
  });

  it('接頭辞マップは 3 種別を網羅する', () => {
    expect(Object.keys(ELEMENTAL_ID_PREFIX).sort()).toEqual(['boundary', 'edge', 'node']);
  });
});
