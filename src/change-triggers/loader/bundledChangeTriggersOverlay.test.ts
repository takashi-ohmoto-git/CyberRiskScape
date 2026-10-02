import { describe, expect, it } from 'vitest';
import { BUNDLED_CHANGE_TRIGGERS } from './bundledChangeTriggers';
import { findOrphanOverlayIds, loadChangeTriggerOverlay, localizeTriggers } from './localizeChangeTriggers';
import type { RawYamlFile } from './loadChangeTriggers';

/**
 * 実際に同梱される翻訳オーバーレイ（`data/change-triggers/i18n/<locale>/*.yaml`）の
 * 不変条件を検証する（`threat-library/loader/bundledOverlay.test.ts` と同じ設計）。
 */

const overlayModules = import.meta.glob<string>('../../../data/change-triggers/i18n/*/*.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

const filesByLocale: Record<string, RawYamlFile[]> = {};
for (const [path, text] of Object.entries(overlayModules)) {
  const segments = path.split('/');
  const fileName = segments[segments.length - 1] ?? path;
  const locale = segments[segments.length - 2] ?? '';
  (filesByLocale[locale] ??= []).push({ source: `${locale}/${fileName}`, text });
}

const locales = Object.keys(filesByLocale);

describe('同梱の翻訳オーバーレイ', () => {
  it('少なくとも 1 ロケール分が同梱されている', () => {
    expect(locales.length).toBeGreaterThan(0);
  });

  describe.each(locales)('locale: %s', (locale) => {
    const overlay = loadChangeTriggerOverlay(filesByLocale[locale] ?? []);
    const translatedIds = Object.keys(overlay);

    it('全トリガーが翻訳されている（T1〜T8 すべて）', () => {
      expect(translatedIds.sort()).toEqual(BUNDLED_CHANGE_TRIGGERS.triggers.map((t) => t.id).sort());
    });

    it('原本に存在しないトリガー id を含まない', () => {
      expect(findOrphanOverlayIds(BUNDLED_CHANGE_TRIGGERS.triggers, overlay)).toEqual([]);
    });

    it('訳文に日本語が残っていない', () => {
      const japanese = /[぀-ゟ゠-ヿ一-鿿]/;
      const broken: string[] = [];
      for (const id of translatedIds) {
        const t = overlay[id];
        if (t?.title && japanese.test(t.title)) broken.push(`${id}.title`);
        if (t?.checkpoint && japanese.test(t.checkpoint)) broken.push(`${id}.checkpoint`);
      }
      expect(broken).toEqual([]);
    });

    it('適用しても原本のトリガー数と id 集合が変わらない', () => {
      const localized = localizeTriggers(BUNDLED_CHANGE_TRIGGERS.triggers, overlay);
      expect(localized.map((t) => t.id)).toEqual(BUNDLED_CHANGE_TRIGGERS.triggers.map((t) => t.id));
    });
  });
});
