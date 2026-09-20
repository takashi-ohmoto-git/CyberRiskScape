import { describe, expect, it } from 'vitest';
import { BUNDLED_COMPONENT_LIBRARY } from './bundledComponentLibrary';
import { BUNDLED_COMPONENT_OVERLAYS } from './bundledComponentOverlay';
import { findOrphanOverlayIds, localizeComponents } from './localizeComponentLibrary';

/**
 * 実際に同梱されるコンポーネント型の翻訳オーバーレイ
 * （`data/component-library/i18n/<locale>/*.yaml`）の不変条件を検証する。
 *
 * 訳の「質」は測れないが、**壊れ方**（スキーマ違反・存在しない型 id・訳し漏れ・
 * 日本語の残り・ラベル重複）はここで機械的に止められる。
 * 脅威ライブラリ側の `threat-library/loader/bundledOverlay.test.ts` と対称。
 */

const locales = Object.keys(BUNDLED_COMPONENT_OVERLAYS);
const components = BUNDLED_COMPONENT_LIBRARY.components;

describe('同梱のコンポーネント翻訳オーバーレイ', () => {
  it('少なくとも 1 ロケール分が同梱されている', () => {
    expect(locales.length).toBeGreaterThan(0);
  });

  describe.each(locales)('locale: %s', (locale) => {
    const overlay = BUNDLED_COMPONENT_OVERLAYS[locale] ?? {};

    it('原本に存在しない型 id を含まない', () => {
      expect(findOrphanOverlayIds(components, overlay)).toEqual([]);
    });

    it('全ての型が訳されている（パレットに原文が混ざらない）', () => {
      const untranslated = components.filter((c) => overlay[c.id] === undefined).map((c) => c.id);
      expect(untranslated).toEqual([]);
    });

    it('訳文に日本語が残っていない', () => {
      const japanese = /[぀-ゟ゠-ヿ一-鿿]/;
      const broken: string[] = [];
      for (const [id, t] of Object.entries(overlay)) {
        if (t.label !== undefined && japanese.test(t.label)) broken.push(`${id}.label`);
        if (t.description !== undefined && japanese.test(t.description))
          broken.push(`${id}.description`);
      }
      expect(broken).toEqual([]);
    });

    it('適用しても型の数と id 集合が変わらない', () => {
      const localized = localizeComponents(BUNDLED_COMPONENT_LIBRARY, overlay);
      expect(localized.components.map((c) => c.id)).toEqual(components.map((c) => c.id));
    });

    it('適用後のラベルに日本語が残っていない', () => {
      const japanese = /[぀-ゟ゠-ヿ一-鿿]/;
      const localized = localizeComponents(BUNDLED_COMPONENT_LIBRARY, overlay);
      const broken = localized.components
        .filter((c) => japanese.test(c.label) || japanese.test(c.description ?? ''))
        .map((c) => c.id);
      expect(broken).toEqual([]);
    });

    it('適用後のラベルが一意（パレットで同名が並ばない）', () => {
      const localized = localizeComponents(BUNDLED_COMPONENT_LIBRARY, overlay);
      const seen = new Map<string, string>();
      const duplicates: string[] = [];
      for (const c of localized.components) {
        const previous = seen.get(c.label);
        if (previous !== undefined) duplicates.push(`${c.label}: ${previous} / ${c.id}`);
        else seen.set(c.label, c.id);
      }
      expect(duplicates).toEqual([]);
    });
  });
});
