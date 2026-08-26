import { describe, expect, it } from 'vitest';
import { parseLibraryFromJson, serializeLibraryToJson } from './io';
import type { CustomRuleLibrary } from './schema';

const RULE = {
  id: 'custom-001',
  framework: 'STRIDE' as const,
  category: 'X',
  severity: 'High' as const,
  description: 'y',
  appliesTo: { kind: 'node' as const, nodeType: 'LLM', connection: { required: false } },
};

const LIB: CustomRuleLibrary = {
  id: 'lib-local-123',
  name: 'My Rules',
  schemaVersion: 1,
  enabled: false,
  rules: [RULE],
  updatedAt: 42,
};

describe('serializeLibraryToJson', () => {
  it('可搬形式（kind/schemaVersion/name/rules）で出力し、インスタンス固有値は含めない', () => {
    const json = JSON.parse(serializeLibraryToJson(LIB));
    expect(json).toEqual({
      schemaVersion: 1,
      kind: 'cyberriskscape-rule-library',
      name: 'My Rules',
      rules: [RULE],
    });
    expect(json.id).toBeUndefined();
    expect(json.enabled).toBeUndefined();
    expect(json.updatedAt).toBeUndefined();
  });
});

describe('parseLibraryFromJson', () => {
  it('round-trip：export した JSON を取り込めて name/rules が一致する', () => {
    const result = parseLibraryFromJson(serializeLibraryToJson(LIB));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.library.name).toBe('My Rules');
    expect(result.library.rules).toEqual([RULE]);
    // 取り込み時は新しい id・enabled:true・updatedAt が採番される
    expect(result.library.id).not.toBe(LIB.id);
    expect(result.library.enabled).toBe(true);
  });

  it('kind 無しの手書き JSON も受理する', () => {
    const text = JSON.stringify({ schemaVersion: 1, name: 'Hand', rules: [RULE] });
    const result = parseLibraryFromJson(text);
    expect(result.ok).toBe(true);
  });

  it('JSON 構文エラーはメッセージ付きで失敗を返す（throw しない）', () => {
    const result = parseLibraryFromJson('{ not json');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('JSON 構文エラー');
  });

  it('スキーマ違反（不正 severity）は検証エラーを返す', () => {
    const text = JSON.stringify({
      schemaVersion: 1,
      name: 'Bad',
      rules: [{ ...RULE, severity: 'Catastrophic' }],
    });
    const result = parseLibraryFromJson(text);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('検証エラー');
  });

  it('ルール id 重複は拒否する', () => {
    const text = JSON.stringify({
      schemaVersion: 1,
      name: 'Dup',
      rules: [RULE, { ...RULE, description: 'dup' }],
    });
    expect(parseLibraryFromJson(text).ok).toBe(false);
  });

  it('name 欠落は拒否する', () => {
    const text = JSON.stringify({ schemaVersion: 1, rules: [RULE] });
    expect(parseLibraryFromJson(text).ok).toBe(false);
  });
});
