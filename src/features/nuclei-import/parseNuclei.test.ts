import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseNuclei } from './parseNuclei';

const fx = (n: string) => readFileSync(new URL(`./__fixtures__/${n}`, import.meta.url), 'utf-8');

describe('parseNuclei', () => {
  it('JSONL：読める行を取り、JSON でない行は invalid に数える', () => {
    const r = parseNuclei(fx('nuclei.jsonl'));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.results).toHaveLength(6);
      expect(r.invalid).toBe(1);
    }
  });

  it('JSON 配列（-je）も読める', () => {
    const r = parseNuclei(fx('nuclei.json'));
    expect(r.ok && r.results.map((x) => x['template-id'])).toEqual(['sqli-error-based', 'tech-detect']);
  });

  it('template-id が無い要素は invalid', () => {
    const r = parseNuclei('[{"host":"a"},{"template-id":"x"}]');
    expect(r.ok && r.invalid).toBe(1);
  });

  it('読まない項目（request など）は結果に残らない', () => {
    const r = parseNuclei(fx('nuclei.jsonl'));
    const keys = new Set((r.ok ? r.results : []).flatMap((x) => Object.keys(x)));
    for (const k of ['request', 'response', 'curl-command', 'extracted-results', 'interaction', 'meta', 'ip']) expect(keys.has(k)).toBe(false);
  });

  it.each([[''], ['   \n'], ['not json\nalso not'], ['[1,2]'], ['[broken']])('読めるものが無い入力 %j → エラー', (text) => {
    expect(parseNuclei(text).ok).toBe(false);
  });
});
