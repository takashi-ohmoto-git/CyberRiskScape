import { describe, expect, it } from 'vitest';
import { triggersToJson, triggersToJsonObject, triggersToMarkdown } from './triggers';
import type { ChangeTrigger } from '../change-triggers/schema/trigger';
import { setLocale } from '../i18n';

const AUTO: ChangeTrigger = {
  id: 'T1',
  title: '新しい信頼境界',
  checkpoint: 'チェックポイント1',
  detect: [{ kind: 'boundary-added' }],
};

const MANUAL: ChangeTrigger = {
  id: 'T4',
  title: '新しい技術またはランタイム',
  checkpoint: 'チェックポイント4',
  detect: [],
};

describe('triggersToMarkdown', () => {
  it('見出し・イントロ・チェックリスト項目を含む', () => {
    setLocale('ja');
    const md = triggersToMarkdown([AUTO, MANUAL]);
    expect(md).toContain('# 脅威モデリングの実行トリガー チェックリスト');
    expect(md).toContain('- [ ] **T1 新しい信頼境界** — チェックポイント1');
    expect(md).toContain('- [ ] **T4 新しい技術またはランタイム** — チェックポイント4');
  });

  it('自動判定できる項目とできない項目を節で分ける', () => {
    setLocale('ja');
    const md = triggersToMarkdown([AUTO, MANUAL]);
    const autoSectionIdx = md.indexOf('## モデル差分で自動判定できる項目');
    const manualSectionIdx = md.indexOf('人（または AI レビュアー）');
    const t1Idx = md.indexOf('T1 新しい信頼境界');
    const t4Idx = md.indexOf('T4 新しい技術またはランタイム');
    expect(autoSectionIdx).toBeGreaterThan(-1);
    expect(manualSectionIdx).toBeGreaterThan(-1);
    expect(t1Idx).toBeGreaterThan(autoSectionIdx);
    expect(t1Idx).toBeLessThan(manualSectionIdx);
    expect(t4Idx).toBeGreaterThan(manualSectionIdx);
  });

  it('英語ロケールでも出力できる', () => {
    setLocale('en');
    const md = triggersToMarkdown([AUTO, MANUAL]);
    expect(md).toContain('# Threat modeling trigger checklist');
    setLocale('ja');
  });

  it('自動判定できる項目が無ければ節ごと省略する', () => {
    setLocale('ja');
    const md = triggersToMarkdown([MANUAL]);
    expect(md).not.toContain('## モデル差分で自動判定できる項目');
    expect(md).toContain('人（または AI レビュアー）');
  });
});

describe('triggersToJson / triggersToJsonObject', () => {
  it('autoDetected を detect の有無から判定する', () => {
    const obj = triggersToJsonObject([AUTO, MANUAL]);
    expect(obj.kind).toBe('cyberriskscape-change-triggers');
    expect(obj.triggers).toEqual([
      { id: 'T1', title: '新しい信頼境界', checkpoint: 'チェックポイント1', autoDetected: true },
      { id: 'T4', title: '新しい技術またはランタイム', checkpoint: 'チェックポイント4', autoDetected: false },
    ]);
  });

  it('triggersToJson は整形済み JSON 文字列を返す', () => {
    const json = JSON.parse(triggersToJson([AUTO])) as Record<string, unknown>;
    expect(json.schemaVersion).toBe(1);
    expect(Array.isArray(json.triggers)).toBe(true);
  });
});
