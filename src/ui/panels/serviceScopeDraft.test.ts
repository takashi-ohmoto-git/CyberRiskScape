import { describe, expect, it } from 'vitest';
import { findInvalidScopeRows, toSavedServiceScope } from './serviceScopeDraft';

describe('findInvalidScopeRows', () => {
  it('解釈できない値の行だけ検出する（空の行は対象外）', () => {
    const rows = [
      { kind: 'domain' as const, value: 'order.example.com' },
      { kind: 'cidr' as const, value: 'not an ip' },
      { kind: 'host' as const, value: '   ' },
      { kind: 'url-prefix' as const, value: 'ftp://x' },
    ];
    expect(findInvalidScopeRows(rows)).toEqual([1, 3]);
  });
});

describe('toSavedServiceScope', () => {
  it('空の行を捨て、前後の空白を除き、値は正規化しない', () => {
    const out = toSavedServiceScope([
      { kind: 'domain', value: '  Order.Example.com ', note: ' メモ ' },
      { kind: 'host', value: '' },
      { kind: 'cidr', value: '203.0.113.5/28', note: '  ' },
    ]);
    expect(out).toEqual([
      { kind: 'domain', value: 'Order.Example.com', note: 'メモ' },
      { kind: 'cidr', value: '203.0.113.5/28' },
    ]);
  });

  it('0 件・未指定なら undefined', () => {
    expect(toSavedServiceScope([{ kind: 'host', value: ' ' }])).toBeUndefined();
    expect(toSavedServiceScope(undefined)).toBeUndefined();
  });
});
