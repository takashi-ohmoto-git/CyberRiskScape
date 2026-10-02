import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ChangeTriggerLoadError,
  loadChangeTriggers,
  parseChangeTriggerFile,
  type RawYamlFile,
} from './loadChangeTriggers';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const DATA_DIR = resolve(__dirname, '../../../data/change-triggers');

function loadAllYamlFiles(): RawYamlFile[] {
  const files = readdirSync(DATA_DIR).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
  return files.map((name) => ({ source: name, text: readFileSync(join(DATA_DIR, name), 'utf-8') }));
}

describe('loadChangeTriggers - 同梱データ', () => {
  it('data/change-triggers 配下の YAML をロードできる（T1〜T8）', () => {
    const result = loadChangeTriggers(loadAllYamlFiles());
    expect(result.triggers.map((t) => t.id).sort()).toEqual([
      'T1',
      'T2',
      'T3',
      'T4',
      'T5',
      'T6',
      'T7',
      'T8',
    ]);
  });

  it('全トリガーの id がライブラリ全体で一意である', () => {
    const result = loadChangeTriggers(loadAllYamlFiles());
    const ids = result.triggers.map((t) => t.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('T4 は detect: [] （モデル差分から自動判定できない）', () => {
    const result = loadChangeTriggers(loadAllYamlFiles());
    const t4 = result.triggers.find((t) => t.id === 'T4');
    expect(t4?.detect).toEqual([]);
  });
});

describe('parseChangeTriggerFile - バリデーション', () => {
  it('正常な最小 YAML をパースできる', () => {
    const yaml = `
schemaVersion: 1
triggers:
  - id: T1
    title: タイトル
    checkpoint: 確認ポイント
    detect: []
`;
    const triggers = parseChangeTriggerFile(yaml, 'inline');
    expect(triggers).toHaveLength(1);
    expect(triggers[0].id).toBe('T1');
  });

  it('id が T<数字> 形式でない場合は拒否する', () => {
    const yaml = `
schemaVersion: 1
triggers:
  - id: trigger-1
    title: タイトル
    checkpoint: 確認ポイント
    detect: []
`;
    expect(() => parseChangeTriggerFile(yaml, 'inline')).toThrow(ChangeTriggerLoadError);
  });

  it('未知の detector kind を拒否する', () => {
    const yaml = `
schemaVersion: 1
triggers:
  - id: T1
    title: タイトル
    checkpoint: 確認ポイント
    detect:
      - kind: node-removed
`;
    expect(() => parseChangeTriggerFile(yaml, 'inline')).toThrow(ChangeTriggerLoadError);
  });

  it('*-changed 系の detector は fields が無いと拒否する', () => {
    const yaml = `
schemaVersion: 1
triggers:
  - id: T1
    title: タイトル
    checkpoint: 確認ポイント
    detect:
      - kind: node-changed
`;
    expect(() => parseChangeTriggerFile(yaml, 'inline')).toThrow(ChangeTriggerLoadError);
  });

  it('node-added はフィルタ無しでも受理する', () => {
    const yaml = `
schemaVersion: 1
triggers:
  - id: T1
    title: タイトル
    checkpoint: 確認ポイント
    detect:
      - kind: node-added
`;
    const triggers = parseChangeTriggerFile(yaml, 'inline');
    expect(triggers[0].detect).toEqual([{ kind: 'node-added' }]);
  });

  it('schemaVersion 不一致を拒否する', () => {
    const yaml = `
schemaVersion: 2
triggers: []
`;
    expect(() => parseChangeTriggerFile(yaml, 'inline')).toThrow(ChangeTriggerLoadError);
  });

  it('YAML パースエラーは ChangeTriggerLoadError として throw される', () => {
    const broken = 'schemaVersion: 1\ntriggers:\n  - id: T1\n   bad: indent';
    expect(() => parseChangeTriggerFile(broken, 'broken.yaml')).toThrow(ChangeTriggerLoadError);
  });
});

describe('loadChangeTriggers - 重複検知', () => {
  const single = `
schemaVersion: 1
triggers:
  - id: T1
    title: タイトル
    checkpoint: 確認ポイント
    detect: []
`;

  it('同一 id が複数ファイルにまたがる場合は拒否する', () => {
    expect(() =>
      loadChangeTriggers([
        { source: 'a.yaml', text: single },
        { source: 'b.yaml', text: single },
      ]),
    ).toThrow(/Duplicate trigger id/);
  });
});
