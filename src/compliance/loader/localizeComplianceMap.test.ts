import { describe, expect, it } from 'vitest';
import {
  findOrphanOverlayRefs,
  loadComplianceOverlay,
  localizeComplianceMap,
  parseComplianceOverlayFile,
} from './localizeComplianceMap';
import {
  ComplianceMapLoadError,
  makeComplianceKey,
  type LoadedComplianceMap,
} from './loadComplianceMap';
import { BUNDLED_COMPLIANCE_MAP, getComplianceMap } from './bundledComplianceMap';
import type { ComplianceItem, StandardId } from '../schema/complianceItem';

const item = (ref: string): ComplianceItem => ({
  ref,
  title: 'タイトル',
  summary: '要約。',
});

const map: LoadedComplianceMap = {
  standards: new Map([
    [
      'jp-ai-business-guideline' as StandardId,
      {
        id: 'jp-ai-business-guideline' as StandardId,
        title: 'AI 事業者ガイドライン',
        url: 'https://example.test/',
      },
    ],
  ]),
  itemsByStandard: new Map([['jp-ai-business-guideline' as StandardId, [item('共通の指針-4')]]]),
  index: new Map([[makeComplianceKey('jp-ai-business-guideline', '共通の指針-4'), item('共通の指針-4')]]),
  sources: ['jp-ai-business-guideline.yaml'],
};

const overlayYaml = `
schemaVersion: 1
locale: en
standard: jp-ai-business-guideline
title: "AI 事業者ガイドライン (METI/MIC AI Guidelines for Business, in Japanese)"
refLabels:
  "共通の指針-4": "共通の指針-4 (Common Guiding Principle 4)"
`;

describe('parseComplianceOverlayFile', () => {
  it('規格 ID と訳を返す', () => {
    const parsed = parseComplianceOverlayFile(overlayYaml, 'en/jp.yaml');
    expect(parsed.standard).toBe('jp-ai-business-guideline');
    expect(parsed.refLabels?.['共通の指針-4']).toContain('Common Guiding Principle 4');
  });

  it('未知の規格 ID を拒否する', () => {
    expect(() =>
      parseComplianceOverlayFile(
        `
schemaVersion: 1
locale: en
standard: not-a-standard
`,
        'en/bad.yaml',
      ),
    ).toThrow(ComplianceMapLoadError);
  });

  it('未知フィールドを拒否する（strict）', () => {
    expect(() =>
      parseComplianceOverlayFile(
        `
schemaVersion: 1
locale: en
standard: jp-ai-business-guideline
items: {}
`,
        'en/bad.yaml',
      ),
    ).toThrow(ComplianceMapLoadError);
  });
});

describe('loadComplianceOverlay', () => {
  it('同じ規格が 2 ファイルにあれば落とす', () => {
    expect(() =>
      loadComplianceOverlay([
        { source: 'en/a.yaml', text: overlayYaml },
        { source: 'en/b.yaml', text: overlayYaml },
      ]),
    ).toThrow(ComplianceMapLoadError);
  });
});

describe('localizeComplianceMap', () => {
  const overlay = loadComplianceOverlay([{ source: 'en/jp.yaml', text: overlayYaml }]);

  it('規格名を訳文へ差し替える', () => {
    const localized = localizeComplianceMap(map, overlay);
    expect(localized.standards.get('jp-ai-business-guideline' as StandardId)?.title).toBe(
      'AI 事業者ガイドライン (METI/MIC AI Guidelines for Business, in Japanese)',
    );
  });

  it('ref の表示ラベルを引ける', () => {
    const localized = localizeComplianceMap(map, overlay);
    expect(
      localized.refLabels?.get(makeComplianceKey('jp-ai-business-guideline', '共通の指針-4')),
    ).toContain('Common Guiding Principle 4');
  });

  it('逆引きキーである ref 自体は変えない', () => {
    const localized = localizeComplianceMap(map, overlay);
    expect(localized.index.has(makeComplianceKey('jp-ai-business-guideline', '共通の指針-4'))).toBe(
      true,
    );
    expect(localized.itemsByStandard.get('jp-ai-business-guideline' as StandardId)?.[0]?.ref).toBe(
      '共通の指針-4',
    );
  });

  it('原本を書き換えない', () => {
    localizeComplianceMap(map, overlay);
    expect(map.standards.get('jp-ai-business-guideline' as StandardId)?.title).toBe(
      'AI 事業者ガイドライン',
    );
  });
});

describe('findOrphanOverlayRefs', () => {
  it('原本に無い ref を検出する', () => {
    const overlay = loadComplianceOverlay([
      {
        source: 'en/jp.yaml',
        text: `
schemaVersion: 1
locale: en
standard: jp-ai-business-guideline
refLabels:
  "存在しない-1": "gone"
`,
      },
    ]);
    expect(findOrphanOverlayRefs(map, overlay)).toEqual([
      'jp-ai-business-guideline / 存在しない-1',
    ]);
  });
});

describe('同梱のコンプライアンス翻訳オーバーレイ', () => {
  it('原本に無い規格・ref を訳していない', () => {
    const en = getComplianceMap('en');
    expect(en).not.toBe(BUNDLED_COMPLIANCE_MAP);
    // getComplianceMap の内部で診断済み。ここでは適用結果の健全性を確認する。
    for (const key of en.refLabels?.keys() ?? []) {
      expect(BUNDLED_COMPLIANCE_MAP.index.has(key)).toBe(true);
    }
  });

  it('ja は原本をそのまま返す', () => {
    expect(getComplianceMap('ja')).toBe(BUNDLED_COMPLIANCE_MAP);
  });

  it('脅威ルールが参照する日本語 ref はすべて表示ラベルを持つ', () => {
    const en = getComplianceMap('en');
    const japanese = /[぀-ゟ゠-ヿ一-鿿]/;
    const missing: string[] = [];
    for (const [key, item] of BUNDLED_COMPLIANCE_MAP.index) {
      if (!japanese.test(item.ref)) continue;
      if (!en.refLabels?.has(key)) missing.push(key);
    }
    expect(missing).toEqual([]);
  });

  it('EN の規格名に素の日本語だけが残っていない（英語併記がある）', () => {
    const en = getComplianceMap('en');
    const japanese = /[぀-ゟ゠-ヿ一-鿿]/;
    const broken: string[] = [];
    for (const [id, meta] of en.standards) {
      if (japanese.test(meta.title) && !/[A-Za-z]{3,}/.test(meta.title)) broken.push(id);
    }
    expect(broken).toEqual([]);
  });
});
