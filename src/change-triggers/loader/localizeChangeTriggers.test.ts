import { describe, expect, it } from 'vitest';
import {
  findOrphanOverlayIds,
  findUntranslatedTriggerIds,
  loadChangeTriggerOverlay,
  localizeTriggers,
  parseChangeTriggerOverlayFile,
} from './localizeChangeTriggers';
import { ChangeTriggerLoadError } from './loadChangeTriggers';
import type { ChangeTrigger } from '../schema/trigger';

const triggerT1: ChangeTrigger = {
  id: 'T1',
  title: '新しい信頼境界',
  checkpoint: 'データが新しいネットワークセグメントを越える',
  detect: [{ kind: 'boundary-added' }],
};

const triggerT2: ChangeTrigger = {
  id: 'T2',
  title: '新しい外部インターフェース',
  checkpoint: 'インターネット向け API',
  detect: [{ kind: 'edge-added', peerTrust: ['Internet'] }],
};

const overlayYaml = `
schemaVersion: 1
locale: en
triggers:
  T1:
    title: New trust boundary
    checkpoint: Data crosses a new network segment
`;

describe('parseChangeTriggerOverlayFile', () => {
  it('トリガー id をキーに訳文を返す', () => {
    const overlay = parseChangeTriggerOverlayFile(overlayYaml, 'en/sample.yaml');
    expect(Object.keys(overlay)).toEqual(['T1']);
    expect(overlay.T1?.title).toBe('New trust boundary');
  });

  it('未知のフィールドはスキーマ違反として落とす', () => {
    const bad = `
schemaVersion: 1
locale: en
triggers:
  T1:
    detect: []
`;
    expect(() => parseChangeTriggerOverlayFile(bad, 'en/bad.yaml')).toThrow(ChangeTriggerLoadError);
  });

  it('YAML 構文エラーはソース名付きで落とす', () => {
    expect(() => parseChangeTriggerOverlayFile('triggers: [unclosed', 'en/broken.yaml')).toThrow(
      /broken\.yaml/,
    );
  });
});

describe('loadChangeTriggerOverlay', () => {
  it('複数ファイルを 1 つのマップへ統合する', () => {
    const other = `
schemaVersion: 1
locale: en
triggers:
  T2:
    title: New external interface
`;
    const merged = loadChangeTriggerOverlay([
      { source: 'en/a.yaml', text: overlayYaml },
      { source: 'en/b.yaml', text: other },
    ]);
    expect(Object.keys(merged).sort()).toEqual(['T1', 'T2']);
  });

  it('同じトリガー id が複数ファイルにあれば落とす', () => {
    expect(() =>
      loadChangeTriggerOverlay([
        { source: 'en/a.yaml', text: overlayYaml },
        { source: 'en/b.yaml', text: overlayYaml },
      ]),
    ).toThrow(/Duplicate overlay entry/);
  });
});

describe('localizeTriggers', () => {
  const overlay = parseChangeTriggerOverlayFile(overlayYaml, 'en/sample.yaml');

  it('指定されたフィールドだけを差し替える', () => {
    const [localized] = localizeTriggers([triggerT1], overlay);
    expect(localized?.title).toBe('New trust boundary');
    expect(localized?.checkpoint).toBe('Data crosses a new network segment');
    // detect は翻訳対象外＝原文のまま
    expect(localized?.detect).toEqual(triggerT1.detect);
  });

  it('原文を破壊しない（新しいオブジェクトを返す）', () => {
    localizeTriggers([triggerT1], overlay);
    expect(triggerT1.title).toBe('新しい信頼境界');
  });

  it('訳の無いトリガーはそのまま返す', () => {
    const [localized] = localizeTriggers([triggerT2], overlay);
    expect(localized).toBe(triggerT2);
  });
});

describe('診断', () => {
  const overlay = parseChangeTriggerOverlayFile(overlayYaml, 'en/sample.yaml');

  it('原本に無いトリガー id を検出する', () => {
    expect(findOrphanOverlayIds([triggerT2], overlay)).toEqual(['T1']);
    expect(findOrphanOverlayIds([triggerT1], overlay)).toEqual([]);
  });

  it('未翻訳のトリガー id を検出する', () => {
    expect(findUntranslatedTriggerIds([triggerT1, triggerT2], overlay)).toEqual(['T2']);
  });
});
