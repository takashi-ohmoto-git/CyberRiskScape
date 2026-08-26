import { describe, expect, it } from 'vitest';
import { CustomRuleLibrarySchema, createEmptyLibrary } from './schema';

const validRule = {
  id: 'custom-001',
  framework: 'STRIDE',
  category: 'X',
  severity: 'High',
  description: 'y',
  appliesTo: { kind: 'node', nodeType: 'LLM', connection: { required: false } },
};

const VALID_LIBRARY = {
  id: 'lib1',
  name: 'My Rules',
  schemaVersion: 1,
  enabled: true,
  rules: [validRule],
  updatedAt: 1_700_000_000_000,
};

describe('CustomRuleLibrarySchema', () => {
  it('正常なライブラリを受理する', () => {
    expect(CustomRuleLibrarySchema.safeParse(VALID_LIBRARY).success).toBe(true);
  });

  it('rules 空配列を受理する（作成直後の空ライブラリ）', () => {
    expect(CustomRuleLibrarySchema.safeParse({ ...VALID_LIBRARY, rules: [] }).success).toBe(true);
  });

  it('schemaVersion 不一致を拒否する', () => {
    expect(CustomRuleLibrarySchema.safeParse({ ...VALID_LIBRARY, schemaVersion: 2 }).success).toBe(
      false,
    );
  });

  it('name 空文字を拒否する', () => {
    expect(CustomRuleLibrarySchema.safeParse({ ...VALID_LIBRARY, name: '' }).success).toBe(false);
  });

  it('ライブラリ内のルール id 重複を拒否する', () => {
    const dup = {
      ...VALID_LIBRARY,
      rules: [validRule, { ...validRule, description: 'dup' }],
    };
    expect(CustomRuleLibrarySchema.safeParse(dup).success).toBe(false);
  });

  it('不正な ThreatRule（不正 severity）を含むと拒否する', () => {
    const bad = { ...VALID_LIBRARY, rules: [{ ...validRule, severity: 'Catastrophic' }] };
    expect(CustomRuleLibrarySchema.safeParse(bad).success).toBe(false);
  });

  it('createEmptyLibrary はスキーマを満たす有効な空ライブラリを返す', () => {
    const lib = createEmptyLibrary('テスト');
    const parsed = CustomRuleLibrarySchema.safeParse(lib);
    expect(parsed.success).toBe(true);
    expect(lib.name).toBe('テスト');
    expect(lib.enabled).toBe(true);
    expect(lib.rules).toEqual([]);
  });
});
