import { describe, expect, it } from 'vitest';
import { getComponentRegistry } from '../../component-library/defaultRegistry';
import { isDfdNotationCategory } from './dfdNotation';

describe('isDfdNotationCategory', () => {
  const registry = getComponentRegistry('ja');
  it.each([
    ['PROCESS', true],
    ['DATA_STORE', true],
    ['EXTERNAL_ENTITY', true],
    ['MEMORY_STORE', false],
    ['CONNECTOR', false],
  ])('%s -> %s', (type, expected) => {
    expect(isDfdNotationCategory(registry.get(type)?.category)).toBe(expected);
  });
  it('未登録(undefined)は false', () => {
    expect(isDfdNotationCategory(undefined)).toBe(false);
  });
});
