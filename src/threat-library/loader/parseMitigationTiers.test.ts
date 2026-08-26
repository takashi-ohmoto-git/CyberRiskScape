import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { parseMitigationTiers } from './parseMitigationTiers';

describe('parseMitigationTiers', () => {
  beforeEach(() => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('undefined / 空文字は undefined を返す', () => {
    expect(parseMitigationTiers(undefined)).toBeUndefined();
    expect(parseMitigationTiers('')).toBeUndefined();
  });

  it('markup を含まない文字列は undefined を返す', () => {
    expect(parseMitigationTiers('単に対策を書いただけの文章。')).toBeUndefined();
  });

  it('3 段全部を含む文字列を分解する', () => {
    const r = parseMitigationTiers(
      '[Foundation] 短命トークン発行。 [Enterprise] mTLS と証明書ピン留め。 [Advanced] HSM 連携で attest 済み。',
    );
    expect(r).toEqual({
      foundation: '短命トークン発行。',
      enterprise: 'mTLS と証明書ピン留め。',
      advanced: 'HSM 連携で attest 済み。',
    });
  });

  it('部分的な段階（Foundation のみ）を分解する', () => {
    const r = parseMitigationTiers('[Foundation] 最低限の対策のみ。');
    expect(r).toEqual({ foundation: '最低限の対策のみ。' });
  });

  it('部分的な段階（Enterprise + Advanced）を分解する', () => {
    const r = parseMitigationTiers('[Enterprise] mTLS。 [Advanced] HSM。');
    expect(r).toEqual({ enterprise: 'mTLS。', advanced: 'HSM。' });
  });

  it('順序が逆（Advanced → Foundation）でも識別する', () => {
    const r = parseMitigationTiers('[Advanced] HSM。 [Foundation] 短命トークン。');
    expect(r).toEqual({ advanced: 'HSM。', foundation: '短命トークン。' });
  });

  it('タグ名は大文字小文字無視', () => {
    const r = parseMitigationTiers('[foundation] a。 [ENTERPRISE] b。 [Advanced] c。');
    expect(r).toEqual({ foundation: 'a。', enterprise: 'b。', advanced: 'c。' });
  });

  it('markup 前のプレフィックステキストは無視する', () => {
    const r = parseMitigationTiers('前置きテキスト。 [Foundation] 短命トークン。');
    expect(r).toEqual({ foundation: '短命トークン。' });
  });

  it('各値の前後空白を trim する', () => {
    const r = parseMitigationTiers('[Foundation]    値の前後に空白    [Enterprise]  別の値  ');
    expect(r).toEqual({ foundation: '値の前後に空白', enterprise: '別の値' });
  });

  it('同一タグ重複は後勝ち + warn', () => {
    const spy = vi.spyOn(console, 'warn');
    const r = parseMitigationTiers('[Foundation] 古い値。 [Enterprise] x。 [Foundation] 新しい値。');
    expect(r).toEqual({ foundation: '新しい値。', enterprise: 'x。' });
    expect(spy).toHaveBeenCalledOnce();
  });

  it('全タグが空本文なら undefined（無効な markup として扱う）', () => {
    expect(parseMitigationTiers('[Foundation][Enterprise][Advanced]')).toBeUndefined();
  });

  it('一部のタグが空本文なら、本文があるタグだけを返す', () => {
    const r = parseMitigationTiers('[Foundation] [Enterprise] mTLS。 [Advanced]');
    expect(r).toEqual({ enterprise: 'mTLS。' });
  });

  it('警告メッセージにルール ID を含める（指定時）', () => {
    const spy = vi.spyOn(console, 'warn');
    parseMitigationTiers('[Foundation] a。 [Foundation] b。', 'my-rule-001');
    expect(spy).toHaveBeenCalledWith(expect.stringContaining('my-rule-001'));
  });
});
