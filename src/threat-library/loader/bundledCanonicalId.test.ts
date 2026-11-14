import { describe, expect, it } from 'vitest';
import { BUNDLED_THREAT_LIBRARY } from './bundledLibrary';

/**
 * 同梱ルールは `canonicalId` を必ず持つ。
 * 検出脅威の id（人の判断のキー・SARIF・差分・MCP が使う）は `canonicalId::kind:要素 id` なので、
 * 付け忘れると、そのルールだけ id が `ルール id-要素 id` の形になり、後から付けたときに id が変わる。
 * スキーマ上は任意（利用者のカスタムルールは付けなくてよい）なので、同梱分はここで確かめる。
 */
describe('同梱の脅威ライブラリ：canonicalId', () => {
  it('すべての同梱ルールが canonicalId を持つ', () => {
    const missing = BUNDLED_THREAT_LIBRARY.rules.filter((r) => !r.canonicalId).map((r) => r.id);
    expect(missing).toEqual([]);
  });
});
