import { describe, expect, it } from 'vitest';
import { BUNDLED_THREAT_LIBRARY } from './bundledLibrary';
import {
  findOrphanOverlayIds,
  loadThreatLibraryOverlay,
  localizeRules,
} from './localizeThreatLibrary';
import type { RawYamlFile } from './loadThreatLibrary';

/**
 * 実際に同梱される翻訳オーバーレイ（`data/threat-library/i18n/<locale>/*.yaml`）の
 * 不変条件を検証する。訳文を書く作業の安全網。
 *
 * 訳の「質」は測れないが、**壊れ方**（スキーマ違反・存在しないルール id・
 * テンプレートトークンの脱落・tier markup の消失）はここで機械的に止められる。
 */

const overlayModules = import.meta.glob<string>('../../../data/threat-library/i18n/*/*.yaml', {
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

const TOKEN_RE = /\{\{[a-zA-Z0-9_]+\}\}/g;
const TIER_RE = /\[(Foundation|Enterprise|Advanced)\]/gi;

function tokensOf(text: string): string[] {
  return [...text.matchAll(TOKEN_RE)].map((m) => m[0]).sort();
}

function tiersOf(text: string): string[] {
  return [...text.matchAll(TIER_RE)].map((m) => m[1]?.toLowerCase() ?? '').sort();
}

const locales = Object.keys(filesByLocale);

describe('同梱の翻訳オーバーレイ', () => {
  it('少なくとも 1 ロケール分が同梱されている', () => {
    expect(locales.length).toBeGreaterThan(0);
  });

  describe.each(locales)('locale: %s', (locale) => {
    const overlay = loadThreatLibraryOverlay(filesByLocale[locale] ?? []);
    const rulesById = new Map(BUNDLED_THREAT_LIBRARY.rules.map((r) => [r.id, r]));
    const translatedIds = Object.keys(overlay);

    it('スキーマ検証を通る（パース時に例外が出ない）', () => {
      expect(translatedIds.length).toBeGreaterThan(0);
    });

    it('原本に存在しないルール id を含まない', () => {
      expect(findOrphanOverlayIds(BUNDLED_THREAT_LIBRARY.rules, overlay)).toEqual([]);
    });

    it('description の {{token}} を原文どおり保持している', () => {
      const broken: string[] = [];
      for (const id of translatedIds) {
        const translated = overlay[id]?.description;
        const original = rulesById.get(id)?.description;
        if (translated === undefined || original === undefined) continue;
        if (tokensOf(original).join(',') !== tokensOf(translated).join(',')) {
          broken.push(`${id}: expected ${tokensOf(original).join(',') || '(none)'}`);
        }
      }
      expect(broken).toEqual([]);
    });

    it('mitigation の tier markup を原文どおり保持している', () => {
      const broken: string[] = [];
      for (const id of translatedIds) {
        const translated = overlay[id]?.mitigation;
        const original = rulesById.get(id)?.mitigation;
        if (translated === undefined || original === undefined) continue;
        if (tiersOf(original).join(',') !== tiersOf(translated).join(',')) {
          broken.push(`${id}: expected ${tiersOf(original).join(',') || '(none)'}`);
        }
      }
      expect(broken).toEqual([]);
    });

    it('訳文に日本語が残っていない', () => {
      const japanese = /[぀-ゟ゠-ヿ一-鿿]/;
      const broken: string[] = [];
      for (const id of translatedIds) {
        const t = overlay[id];
        for (const [field, value] of Object.entries({
          name: t?.name,
          category: t?.category,
          description: t?.description,
          mitigation: t?.mitigation,
        })) {
          if (typeof value === 'string' && japanese.test(value)) broken.push(`${id}.${field}`);
        }
      }
      expect(broken).toEqual([]);
    });

    it('適用しても原本のルール数と id 集合が変わらない', () => {
      const localized = localizeRules(BUNDLED_THREAT_LIBRARY.rules, overlay);
      expect(localized.map((r) => r.id)).toEqual(BUNDLED_THREAT_LIBRARY.rules.map((r) => r.id));
    });

    it('tier markup を持つ訳文からは mitigationTiers が再計算されている', () => {
      const localized = localizeRules(BUNDLED_THREAT_LIBRARY.rules, overlay);
      const broken: string[] = [];
      for (const rule of localized) {
        const t = overlay[rule.id];
        if (!t?.mitigation) continue;
        if (tiersOf(t.mitigation).length > 0 && rule.mitigationTiers === undefined) {
          broken.push(rule.id);
        }
      }
      expect(broken).toEqual([]);
    });
  });
});
