import { describe, expect, it } from 'vitest';
import { BUNDLED_COMPLIANCE_MAP, getComplianceMap } from './bundledComplianceMap';
import type { StandardId } from '../schema/complianceItem';

/**
 * 実際に同梱されるコンプライアンス翻訳オーバーレイの不変条件を検証する。
 * 訳の「質」は測れないが、**壊れ方**（訳し漏れ・日本語残り・原文の破壊）は止められる。
 */

const JAPANESE = /[぀-ゟ゠-ヿ一-鿿]/;

describe('同梱のコンプライアンス翻訳（en）', () => {
  const en = getComplianceMap('en');

  it('ja は原本をそのまま返す', () => {
    expect(getComplianceMap('ja')).toBe(BUNDLED_COMPLIANCE_MAP);
  });

  it('原本の項目数・ref 集合が変わらない', () => {
    for (const [id, items] of BUNDLED_COMPLIANCE_MAP.itemsByStandard) {
      expect(en.itemsByStandard.get(id)?.map((i) => i.ref)).toEqual(items.map((i) => i.ref));
    }
    expect(en.index.size).toBe(BUNDLED_COMPLIANCE_MAP.index.size);
  });

  it('原本（ja）を書き換えていない', () => {
    const jaItem = BUNDLED_COMPLIANCE_MAP.itemsByStandard
      .get('nist-csf-2.0-examples' as StandardId)
      ?.at(0);
    expect(jaItem?.summary).toBeDefined();
    expect(JAPANESE.test(jaItem?.summary ?? '')).toBe(true);
  });

  it('text を持つ規格は訳を書かずとも英語 summary になっている', () => {
    const items = en.itemsByStandard.get('nist-csf-2.0-examples' as StandardId) ?? [];
    expect(items.length).toBeGreaterThan(0);
    const stillJapanese = items.filter((i) => JAPANESE.test(i.summary)).map((i) => i.ref);
    expect(stillJapanese).toEqual([]);
  });

  it('EN の項目に日本語が残っていない', () => {
    const broken: string[] = [];
    for (const [id, items] of en.itemsByStandard) {
      for (const item of items) {
        if (JAPANESE.test(item.title)) broken.push(`${id}/${item.ref}.title`);
        if (JAPANESE.test(item.summary)) broken.push(`${id}/${item.ref}.summary`);
      }
    }
    expect(broken).toEqual([]);
  });
});

describe('規格メタ（en）', () => {
  const en = getComplianceMap('en');

  it('規格名・ライセンス・注記に素の日本語が残っていない', () => {
    const broken: string[] = [];
    for (const [id, meta] of en.standards) {
      for (const [field, value] of Object.entries({
        title: meta.title,
        license: meta.license,
        disclaimer: meta.disclaimer,
      })) {
        // 日本の公文書名は原題を残し英語を併記する運用なので、英単語があれば良しとする。
        if (typeof value === 'string' && JAPANESE.test(value) && !/[A-Za-z]{3,}/.test(value)) {
          broken.push(`${id}.${field}`);
        }
      }
    }
    expect(broken).toEqual([]);
  });

  it('ja 側の規格メタは日本語のまま', () => {
    const ja = BUNDLED_COMPLIANCE_MAP.standards.get('nist-csf-2.0' as StandardId);
    expect(JAPANESE.test(ja?.disclaimer ?? '')).toBe(true);
  });
});
